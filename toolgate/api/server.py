"""ToolGate v2 API: a typed, owner-controlled agent capability boundary."""

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from toolgate.api.builtin_capabilities import (
    ensure_builtin_research_capabilities,
    ensure_builtin_system_capabilities,
)
from toolgate.api.definitions import (
    require_valid_automation_definition,
    require_valid_tool_definition,
    workflow_tool_ids,
)
from toolgate.api.deps import deny, require_admin, require_agent, require_owner
from toolgate.api.invocation import (
    enforce_dispatch_usage_limits,
    enforce_usage_limits,
    invoke_tool,
    require_current_dispatch_authority,
)
from toolgate.api.models import (
    AgentKeyCreate,
    AgentKeyScopes,
    OwnerDecision,
    PortFinalizationRequest,
    PortReviewRequest,
    SecretCreate,
    SecretUpdate,
    V2Automation,
    V2Invoke,
    V2Publish,
    V2Request,
    V2RequestDecision,
    V2Service,
    V2Settings,
    V2Tool,
    VerificationCallback,
    VerificationMethodCreate,
)
from toolgate.api.routes.spending import router as _spending_router
from toolgate.core import (
    control_plane,
    editor_catalogue,
    editor_drafts,
    editor_execution,
    editor_graph,
    editor_publication,
    editor_runs,
    legacy_archive,
    owner_channel,
    port_finalization,
    port_reviews,
    publications,
    recovery_journal,
    vault,
)
from toolgate.core import execution_journal as journal
from toolgate.core.public_https import (
    public_client,
    public_url,
)
from toolgate.executors import (
    container_control,
    filesystem_inventory,
    port_control,
    port_recovery,
    process_control,
)
from toolgate.executors.port_plan import PlanError

SERVICE_VERSION = "0.4.0"

app = FastAPI(title="ToolGate", version=SERVICE_VERSION)


@app.exception_handler(publications.PublicationInvalid)
async def publication_invalid(_request: Request, exc: publications.PublicationInvalid):
    return JSONResponse(
        status_code=409,
        content={
            "detail": {
                "code": "PUBLICATION_UNAVAILABLE",
                "message": str(exc),
            }
        },
    )


@app.exception_handler(control_plane.DefinitionConflict)
async def definition_conflict(_request: Request, exc: control_plane.DefinitionConflict):
    return JSONResponse(
        status_code=409,
        content={
            "detail": {
                "code": "DEFINITION_CONFLICT",
                "message": str(exc),
                "current_version": exc.current_version,
            }
        },
    )


@app.exception_handler(owner_channel.OwnerError)
async def owner_error(_request: Request, error: owner_channel.OwnerError):
    return JSONResponse(
        {"detail": {"code": error.code, "message": str(error)}}, status_code=error.status
    )


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, error: RequestValidationError):
    if request.url.path.startswith("/v2/owner/"):
        return JSONResponse(
            {
                "detail": {
                    "code": "invalid_request",
                    "message": "Send a supported owner request with bounded fields.",
                }
            },
            status_code=422,
        )
    return await request_validation_exception_handler(request, error)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.environ.get(
            "TOOLGATE_DASHBOARD_ORIGINS", "http://localhost:8011,http://127.0.0.1:8011"
        ).split(",")
        if origin.strip()
    ],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "X-ToolGate-Key",
        "X-ToolGate-Execution-Key",
        "X-ToolGate-Timestamp",
        "X-ToolGate-Signature",
    ],
)


@app.on_event("startup")
def startup():
    with control_plane._conn() as conn:
        recovery_journal.assert_not_held(conn)
    control_plane.purge_legacy_state()
    try:
        legacy_archive.migrate()
    except (sqlite3.Error, ValueError) as exc:
        raise RuntimeError(
            "AI archive migration failed; keep ToolGate stopped, preserve toolgate.db, "
            "and inspect the migration error before retrying"
        ) from exc
    control_plane.invalidate_legacy_verifications()
    journal.recover_interrupted()
    generated = vault.ensure_control_keys()
    for name in generated:
        print(f"[toolgate] generated and persisted {name}; value intentionally not logged")
    # A vault that cannot encrypt must not quietly keep provider keys in the clear.
    try:
        moved = vault.encrypt_values_at_rest()
    except vault.VaultError as exc:
        raise RuntimeError(f"ToolGate refuses to start without a usable vault key. {exc}") from exc
    if moved:
        print(
            f"[toolgate] encrypted {moved} vault value(s) at rest; values intentionally not logged"
        )
    bootstrap_key = os.environ.get("TOOLGATE_BOOTSTRAP_EXECUTION_KEY", "").strip()
    if bootstrap_key:
        scopes = [
            scope.strip()
            for scope in os.environ.get("TOOLGATE_BOOTSTRAP_SCOPES", "").split(",")
            if scope.strip()
        ]
        control_plane.ensure_bootstrap_agent_key(bootstrap_key, scopes)
    ensure_builtin_research_capabilities()
    ensure_builtin_system_capabilities()


HEALTH_CACHE_SECONDS = 15
HEALTH_PROBE_TIMEOUT_SECONDS = 2.0
_HEALTHY_STATUSES = {"ok", "not_configured"}
_health_snapshot: dict | None = None


def _probe_control_plane() -> dict:
    """Open the control-plane database for real rather than assuming it is there."""
    try:
        control_plane.settings()
    except (sqlite3.Error, OSError, ValueError) as exc:
        return {"status": "unavailable", "reason": type(exc).__name__}
    return {"status": "ok"}


def _probe_http(url: str, path: str, expected_service: str | None = None) -> dict:
    """Coarse reachability of one upstream. Never returns the host or the body."""
    try:
        response = httpx.get(f"{url.rstrip('/')}{path}", timeout=HEALTH_PROBE_TIMEOUT_SECONDS)
    except httpx.HTTPError as exc:
        # "unavailable" is the contract's word for configured-but-not-working;
        # the exception class carries why. Status vocabulary is fixed so one
        # dashboard can render every module - nuance belongs in reason.
        return {"status": "unavailable", "reason": type(exc).__name__}
    if response.status_code >= 500:
        return {"status": "degraded", "reason": "upstream_5xx"}
    if not 200 <= response.status_code < 300:
        return {"status": "unavailable", "reason": "upstream_http_error"}
    if expected_service is not None:
        try:
            body = response.json()
        except ValueError:
            return {"status": "unavailable", "reason": "invalid_health_response"}
        if (
            not isinstance(body, dict)
            or body.get("service") != expected_service
            or body.get("status") not in {"ok", "degraded", "unavailable"}
        ):
            return {"status": "unavailable", "reason": "invalid_health_response"}
        if body["status"] != "ok":
            return {"status": body["status"], "reason": "upstream_reports_" + body["status"]}
    return {"status": "ok"}


def _memorygate_configured() -> bool:
    try:
        return bool(vault.get_key("MEMORYGATE_READ_KEY"))
    except KeyError:
        return False


def _run_dependency_checks() -> dict:
    checks = {"control_plane_db": _probe_control_plane(), "vault": vault.vault_status()}
    try:
        settings = control_plane.settings()
        generation_configured = bool(settings.get("generation_url")) or any(
            tool.get("status") == "active"
            and tool.get("execution", {}).get("type") == "ollama_generate"
            for tool in control_plane.list_objects("tool")
        )
    except (sqlite3.Error, OSError, ValueError):
        settings = {}
        generation_configured = False

    probes = {
        "searxng": (
            settings.get("research_searxng_url", "http://toolgate-searxng:8080"),
            "/healthz",
        )
    }
    if _memorygate_configured():
        probes["memorygate"] = (
            os.environ.get("MEMORYGATE_URL", "http://memorygate-api:8020"),
            "/health",
        )
    else:
        checks["memorygate"] = {"status": "not_configured"}

    if generation_configured:
        probes["generation"] = (
            settings.get("generation_url", "http://memorygate-ollama:11434"),
            "/api/tags",
        )
    else:
        checks["generation"] = {"status": "not_configured"}

    with ThreadPoolExecutor(max_workers=len(probes)) as pool:
        results = {
            name: pool.submit(
                _probe_http, url, path, "memorygate" if name == "memorygate" else None
            )
            for name, (url, path) in probes.items()
        }
    checks.update({name: future.result() for name, future in results.items()})

    failing = sorted(
        name for name, check in checks.items() if check["status"] not in _HEALTHY_STATUSES
    )
    return {
        "status": "degraded" if failing else "ok",
        "degraded": failing,
        "checks": checks,
        "checked_at": datetime.now(UTC).isoformat(),
    }


@app.get("/health")
def health():
    """Unauthenticated liveness plus real dependency probes.

    Probe detail stays coarse -- a status word and an exception class, never a
    host, a credential or an upstream body -- because anyone can call this.
    Results are cached briefly so an anonymous caller cannot turn the endpoint
    into an outbound request amplifier; the age of the cached answer is
    reported rather than hidden.
    """
    global _health_snapshot
    now = time.monotonic()
    snapshot = _health_snapshot
    if snapshot is None or now - snapshot["probed_at"] >= HEALTH_CACHE_SECONDS:
        snapshot = {**_run_dependency_checks(), "probed_at": now}
        _health_snapshot = snapshot
    # Field names and order are fixed by the Conker module contract - see
    # docs/module-contract.md. "version" is this module's own version, not the
    # API revision: they mean different things, and a dashboard reading one
    # field for both is wrong about every module it does not special-case.
    return {
        "service": "toolgate",
        "version": SERVICE_VERSION,
        "status": snapshot["status"],
        "degraded": snapshot["degraded"],
        "checks": snapshot["checks"],
        "checked_at": snapshot["checked_at"],
        "age_seconds": round(now - snapshot["probed_at"], 1),
    }


@app.get("/auth/check")
def auth_check(_tier: str = Depends(require_admin)):
    return {"tier": "admin"}


@app.get("/vault/secrets")
def list_secrets(_tier: str = Depends(require_admin)):
    return vault.list_placeholders()


@app.post("/vault/secrets")
def create_secret(payload: SecretCreate, _tier: str = Depends(require_admin)):
    try:
        vault.set_secret(payload.name, payload.value, allow_existing=False)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    control_plane.event("secret_created", "info", "secret", payload.name, "admin")
    return {"name": payload.name}


@app.put("/vault/secrets/{name}")
def update_secret(name: str, payload: SecretUpdate, _tier: str = Depends(require_admin)):
    try:
        vault.set_secret(name, payload.value, allow_existing=True)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    control_plane.event("secret_updated", "warning", "secret", name, "admin")
    return {"name": name}


@app.delete("/vault/secrets/{name}")
def delete_secret(name: str, _tier: str = Depends(require_admin)):
    try:
        vault.delete_secret(name)
    except KeyError:
        raise HTTPException(404, "secret not found") from None
    control_plane.event("secret_deleted", "warning", "secret", name, "admin")
    return {"name": name}


@app.post("/settings/keys/admin/rotate")
def rotate_control_key(_tier: str = Depends(require_admin)):
    return {"which": "admin", "key": vault.rotate_control_key("TOOLGATE_ADMIN_KEY")}


def _lookup_path(value, path: str):
    for part in path.split(".") if path else []:
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return None
    return value


def _workflow_value(value, state: dict):
    if isinstance(value, str) and value.startswith("$args."):
        return _lookup_path(state["args"], value[6:])
    if isinstance(value, str) and value.startswith("$vars."):
        return _lookup_path(state["vars"], value[6:])
    if isinstance(value, str) and value.startswith("$last"):
        return _lookup_path(state.get("last"), value[6:] if value.startswith("$last.") else "")
    if isinstance(value, list):
        return [_workflow_value(item, state) for item in value]
    if isinstance(value, dict):
        return {key: _workflow_value(item, state) for key, item in value.items()}
    return value


def _workflow_compare(actual, operator: str, expected) -> bool:
    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected
    if operator == "contains":
        return expected in actual
    if operator == "in":
        return actual in expected
    if operator in {"gte", "lte", "gt", "lt"}:
        left, right = float(actual), float(expected)
        return {"gte": left >= right, "lte": left <= right, "gt": left > right, "lt": left < right}[
            operator
        ]
    raise ValueError(f"unsupported operator {operator}")


def _charge_workflow(state):
    for frame in (state, *state.get("ancestors", ())):
        frame["count"] += 1
        if frame["count"] > frame["max_steps"]:
            deny("POLICY_DENIED", "Automation exceeded its shared ancestor step ceiling")
        if time.monotonic() - frame["started_at"] > frame["runtime_ceiling"]:
            deny("POLICY_DENIED", "Automation exceeded its shared ancestor runtime ceiling")


def _run_editor_graph(step, state, actor, approval_granted):
    if not state.get("publication"):
        deny("PUBLICATION_REQUIRED", "Editor graphs require an immutable published version", 422)
    document = editor_publication.document_from_block(step)
    budget = state.setdefault("graph_budget", editor_execution.Budget())

    def dispatch(node, args, _budget):
        if node.type == "workflow_call":
            result = _invoke_nested_automation(
                {
                    "automation_id": node.config["toolId"],
                    "published_version": node.config["version"],
                },
                state,
                actor,
                approval_granted,
                resolved_args=args,
            )
        else:
            tool = state["tool_snapshot"].get(node.config["tool"])
            if not tool:
                deny(
                    "PUBLICATION_REQUIRED", "Graph capability is not pinned in its publication", 422
                )
            child_id = (
                "child_"
                + hashlib.sha256(f"{state['action_id']}:{state['count']}".encode()).hexdigest()
            )
            result = invoke_tool(
                tool,
                args,
                actor,
                approval_granted=approval_granted,
                actor_id=state["actor_id"],
                action_id=child_id,
                job_id=state.get("job_id"),
                parent_action_id=state["action_id"],
                authority_scope=state["authority_scope"],
                publication=state.get("root_publication", state["publication"]),
            )
        if result.get("code") in {"OUTCOME_UNKNOWN", "IN_PROGRESS"}:
            deny(
                "OUTCOME_UNKNOWN", "A graph child dispatch is uncertain; reconcile its receipt", 409
            )
        if result.get("code") != "OK":
            raise editor_execution.GraphValueError(
                "A graph capability did not complete successfully; inspect its receipt."
            )
        # Expose the executor output, not credentials or the journal envelope.
        payload = result.get("result", {})
        return payload.get("result") if isinstance(payload, dict) else payload

    try:
        result = editor_execution.execute(
            document,
            state["args"],
            dispatch=dispatch,
            budget=budget,
            on_step=lambda: _charge_workflow(state),
        )
    except editor_execution.GraphExecutionError as exc:
        state["results"] = exc.receipts
        return {"code": "WORKFLOW_FAILED", "message": str(exc), "node_id": exc.node_id}
    state["results"] = result["steps"]
    return {"code": "OK", "result": result["output"]}


def _run_workflow_steps(steps: list, state: dict, actor: str, approval_granted: bool):
    if len(steps) == 1 and steps[0].get("type") == "editor_graph":
        return _run_editor_graph(steps[0], state, actor, approval_granted)
    for step in steps:
        _charge_workflow(state)
        if state.get("graph_budget"):
            state["graph_budget"].charge()
        kind = step["type"]
        result = None
        if kind == "tool_call":
            tool = (
                state["tool_snapshot"].get(step["tool_id"])
                if "tool_snapshot" in state
                else control_plane.get("tool", step["tool_id"])
            )
            if not tool or tool.get("status") != "active":
                deny(
                    "TOOL_UNAVAILABLE", f"Workflow references unavailable tool '{step['tool_id']}'"
                )
            if tool.get("authorization") != "auto" and not approval_granted:
                deny(
                    "POLICY_DENIED",
                    f"Automation must require confirmation before calling '{tool['id']}'",
                )
            call_args = {
                field["name"]: state["args"][field["name"]]
                for field in tool.get("inputs", [])
                if field.get("name") in state["args"]
            }
            call_args.update(_workflow_value(step.get("args", {}), state))
            parent_id = state.get("action_id")
            child_id = (
                ("child_" + hashlib.sha256(f"{parent_id}:{state['count']}".encode()).hexdigest())
                if parent_id
                else None
            )
            result = invoke_tool(
                tool,
                call_args,
                actor,
                approval_granted=approval_granted,
                actor_id=state.get("actor_id"),
                action_id=child_id,
                job_id=state.get("job_id"),
                parent_action_id=parent_id,
                publication=state.get("root_publication", state.get("publication")),
                authority_scope=state.get("authority_scope"),
            )
            if result.get("code") in {"OUTCOME_UNKNOWN", "IN_PROGRESS"}:
                deny("OUTCOME_UNKNOWN", "A child dispatch is uncertain; this workflow is held", 409)
        elif kind == "automation_call":
            result = _invoke_nested_automation(step, state, actor, approval_granted)
        elif kind == "set":
            state["vars"][step.get("name", "value")] = _workflow_value(step.get("value"), state)
            result = {"code": "VALUE_SET", "name": step.get("name", "value")}
        elif kind == "calculation":
            values = [_workflow_value(value, state) for value in step.get("values", [])]
            operation = step.get("operation", "add")
            if not values or any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or (isinstance(value, float) and not math.isfinite(value))
                for value in values
            ):
                deny("VALIDATION_ERROR", "Calculation values must resolve to numbers", 422)
            calculated = {
                "add": lambda: sum(values),
                "subtract": lambda: values[0] - sum(values[1:]),
                "multiply": lambda: __import__("math").prod(values),
                "divide": lambda: values[0] / __import__("math").prod(values[1:]),
                "min": lambda: min(values),
                "max": lambda: max(values),
            }.get(operation)
            if not calculated:
                deny("VALIDATION_ERROR", f"Unsupported calculation '{operation}'", 422)
            try:
                value = calculated()
            except ZeroDivisionError:
                deny("VALIDATION_ERROR", "Calculation divided by zero", 422)
            except OverflowError:
                deny("VALIDATION_ERROR", "Calculation exceeded the numeric range", 422)
            if isinstance(value, float) and not math.isfinite(value):
                deny("VALIDATION_ERROR", "Calculation result must be finite", 422)
            state["vars"][step.get("save_as", "calculation")] = value
            result = {"code": "CALCULATED", "result": value}
        elif kind == "condition":
            actual = _workflow_value(step.get("left", f"$args.{step.get('field', '')}"), state)
            expected = _workflow_value(step.get("right", step.get("value")), state)
            try:
                matches = _workflow_compare(actual, step.get("operator", "equals"), expected)
            except (TypeError, ValueError):
                deny("VALIDATION_ERROR", "Condition could not compare its configured values", 422)
            branch = step.get("then", []) if matches else step.get("else", [])
            result = {"code": "CONDITION_MET" if matches else "CONDITION_NOT_MET"}
            final = _run_workflow_steps(branch, state, actor, approval_granted)
            if final is not None:
                return final
            if not matches and not branch and step.get("on_false", "stop") == "stop":
                deny("POLICY_DENIED", "Automation condition was not met")
        elif kind == "switch":
            selected = str(_workflow_value(step.get("value"), state))
            branch = step.get("cases", {}).get(selected, step.get("default", []))
            result = {"code": "SWITCH_SELECTED", "case": selected}
            final = _run_workflow_steps(branch, state, actor, approval_granted)
            if final is not None:
                return final
        elif kind == "loop":
            items = _workflow_value(step.get("items"), state)
            if not isinstance(items, list):
                deny("VALIDATION_ERROR", "Loop items must resolve to an array", 422)
            if len(items) > step["max_iterations"]:
                deny("POLICY_DENIED", "Loop input exceeds its deterministic iteration ceiling")
            item_name = step.get("item_name", "item")
            had_previous = item_name in state["vars"]
            previous = state["vars"].get(item_name)
            try:
                for item in items:
                    state["vars"][item_name] = item
                    final = _run_workflow_steps(
                        step.get("steps", []), state, actor, approval_granted
                    )
                    if final is not None:
                        return final
            finally:
                if had_previous:
                    state["vars"][item_name] = previous
                else:
                    state["vars"].pop(item_name, None)
            result = {"code": "LOOP_COMPLETE", "iterations": len(items)}
        elif kind == "retry":
            last_error = None
            for attempt in range(step["max_attempts"]):
                try:
                    final = _run_workflow_steps([step["step"]], state, actor, approval_granted)
                    if final is not None:
                        return final
                    last_error = None
                    break
                except HTTPException as exc:
                    last_error = exc
                    if (
                        exc.status_code not in {429, 502, 503}
                        or attempt + 1 >= step["max_attempts"]
                    ):
                        raise
                    time.sleep(min(float(step.get("delay_seconds", 0)), 5))
            result = {
                "code": "RETRY_COMPLETE",
                "attempts": step["max_attempts"] if last_error else attempt + 1,
            }
        elif kind == "delay":
            time.sleep(float(step.get("seconds", 0)))
            result = {"code": "DELAY_COMPLETE", "seconds": step.get("seconds", 0)}
        elif kind == "notification":
            notification = control_plane.create_request(
                "update",
                step.get("title", "Automation update"),
                str(_workflow_value(step.get("message", "Automation notification"), state)),
                actor,
                {"automation_id": state["automation_id"]},
                "info",
            )
            result = {"code": "NOTIFICATION_CREATED", "request_id": notification["id"]}
        elif kind == "return":
            return {"code": "OK", "result": _workflow_value(step.get("value"), state)}
        state["last"] = result
        state["results"].append({"type": kind, "result": result})
    return None


def _automation_input_errors(definition, args):
    workflow = definition.get("workflow", [])
    if len(workflow) == 1 and workflow[0].get("type") == "editor_graph":
        try:
            document = editor_publication.document_from_block(workflow[0])
            editor_execution.inputs(document.inputs, args)
            return []
        except ValueError as exc:
            return [str(exc)]
    return control_plane.validate_inputs(definition.get("inputs", []), args)


def _invoke_nested_automation(
    step: dict, state: dict, actor: str, approval_granted: bool, *, resolved_args=None
) -> dict:
    publication = (
        (state.get("publication") or {}).get("automations", {}).get(publications.nested_key(step))
    )
    if not publication:
        deny("PUBLICATION_REQUIRED", "Nested calls require a pinned publication", 422)
    definition = publication["definition"]
    if definition.get("authorization", "auto") != "auto" and not approval_granted:
        deny("POLICY_DENIED", "Nested automation requires root owner confirmation", 403)
    args = (
        resolved_args if resolved_args is not None else _workflow_value(step.get("args", {}), state)
    )
    errors = _automation_input_errors(definition, args)
    if errors:
        deny("VALIDATION_ERROR", "; ".join(errors), 422)
    action_id = (
        "child_" + hashlib.sha256(f"{state['action_id']}:{state['count']}".encode()).hexdigest()
    )
    root_publication = state.get("root_publication", state["publication"])

    def authorize(conn):
        require_current_dispatch_authority(conn, state["actor_id"], state["authority_scope"])
        publications.for_execution(
            conn, root_publication["kind"], root_publication["id"], root_publication["version"]
        )
        enforce_dispatch_usage_limits(conn, "automation", definition, "automation_executed")

    record, dispatch = journal.begin(
        action_id,
        "automation",
        definition["id"],
        args,
        state["actor_id"],
        definition["version"],
        job_id=state.get("job_id"),
        parent_action_id=state["action_id"],
        authorize=authorize,
        publication_digest=publication["digest"],
    )
    if not dispatch:
        result = journal.response(record)
        if result.get("code") in {"OUTCOME_UNKNOWN", "IN_PROGRESS"}:
            deny("OUTCOME_UNKNOWN", "Nested dispatch is uncertain; this workflow is held", 409)
        return result
    limits = definition.get("policy", {}).get("usage_limits", {})
    nested = {
        "automation_id": definition["id"],
        "tool_snapshot": publication["tools"],
        "publication": publication,
        "root_publication": root_publication,
        "authority_scope": state["authority_scope"],
        "action_id": action_id,
        "job_id": state.get("job_id"),
        "actor_id": state["actor_id"],
        "args": args,
        "vars": {},
        "last": None,
        "results": [],
        "count": 0,
        "ancestors": (state, *state.get("ancestors", ())),
        "max_steps": int(limits.get("max_steps", 100)),
        "started_at": time.monotonic(),
        "runtime_ceiling": min(int(limits.get("max_runtime_seconds", 30) or 30), 120),
    }
    if state.get("graph_budget"):
        nested["graph_budget"] = state["graph_budget"]
    try:
        final = _run_workflow_steps(definition.get("workflow", []), nested, actor, approval_granted)
    except Exception:  # hold any incomplete nested dispatch; never retry it.
        journal.unknown(action_id)
        deny("OUTCOME_UNKNOWN", "Nested workflow is incomplete; reconcile its receipt", 409)
    failed = isinstance(final, dict) and final.get("code") == "WORKFLOW_FAILED"
    envelope = {
        "code": "WORKFLOW_FAILED" if failed else "OK",
        "message": "Nested workflow failed" if failed else "Nested automation completed",
        "result": final,
        "steps": nested["results"],
        "variables": nested["vars"],
        "publication": {
            "kind": "automation",
            "id": definition["id"],
            "version": publication["version"],
            "digest": publication["digest"],
        },
    }
    record = journal.finish(action_id, envelope)
    control_plane.event(
        "automation_executed",
        "info",
        "automation",
        definition["id"],
        actor,
        {"steps": nested["count"], "version": definition["version"], "action_id": action_id},
    )
    return journal.response(record)


@app.get("/v2/status")
def status(_tier: str = Depends(require_admin)):
    requests = control_plane.list_objects("request")
    return {
        "lockdown": control_plane.settings().get("lockdown", False),
        "tools": len(control_plane.list_objects("tool")),
        "automations": len(control_plane.list_objects("automation")),
        "services": len(control_plane.list_objects("service")),
        "pending_requests": sum(r.get("status") == "pending" for r in requests),
    }


@app.post("/v2/settings/lockdown")
def set_lockdown(enabled: bool, reason: str = "", _tier: str = Depends(require_admin)):
    return control_plane.set_lockdown(enabled, "admin", reason)


@app.get("/v2/settings")
def get_settings(_tier: str = Depends(require_admin)):
    return {
        "generation_model": "qwen3:4b",
        "event_retention_days": 90,
        "default_confirmation_expiry_seconds": 60,
        "producthunt_commercial_use_approved": False,
        **control_plane.settings(),
    }


@app.put("/v2/settings")
def update_settings(payload: V2Settings, _tier: str = Depends(require_admin)):
    return control_plane.update_settings(payload.model_dump(), "admin")


@app.get("/v2/verification-methods")
def list_verification_methods(_tier: str = Depends(require_admin)):
    return control_plane.list_objects("verification_method")


@app.post("/v2/verification-methods")
def create_verification_method(
    payload: VerificationMethodCreate, _tier: str = Depends(require_admin)
):
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", payload.secret_ref):
        raise HTTPException(422, "secret_ref must be a vault reference name")
    try:
        vault.get_key(payload.secret_ref)
    except KeyError:
        raise HTTPException(422, "secret_ref is not configured in ToolGate") from None
    method = control_plane.create_verification_method(payload.model_dump())
    control_plane.event(
        "verification_method_created", "info", "verification_method", method["id"], "admin"
    )
    return method


@app.delete("/v2/verification-methods/{method_id}")
def delete_verification_method(method_id: str, _tier: str = Depends(require_admin)):
    if not control_plane.remove("verification_method", method_id):
        raise HTTPException(404, "verification method not found")
    control_plane.event(
        "verification_method_deleted", "warning", "verification_method", method_id, "admin"
    )
    return {"deleted": True, "id": method_id}


@app.post("/v2/verification/callback")
def verification_callback(
    payload: VerificationCallback,
    x_toolgate_timestamp: str | None = Header(None, alias="X-ToolGate-Timestamp"),
    x_toolgate_signature: str | None = Header(None, alias="X-ToolGate-Signature"),
):
    if control_plane.settings().get("lockdown"):
        deny("LOCKED_DOWN", "ToolGate is in lockdown mode", 423)
    method = control_plane.get("verification_method", payload.method_id)
    if (
        not method
        or method.get("status") != "active"
        or method.get("method_type") != "signed_callback"
    ):
        deny("VERIFICATION_METHOD_INVALID", "Verification method is unavailable", 401)
    try:
        timestamp = int(x_toolgate_timestamp or "")
    except ValueError:
        timestamp = 0
    canonical = json.dumps(
        payload.model_dump(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    try:
        secret = vault.get_key(method["secret_ref"])
    except KeyError:
        deny("VERIFICATION_METHOD_INVALID", "Verification method secret is unavailable", 503)
    expected = hmac.new(
        secret.encode(), f"{timestamp}.{canonical}".encode(), hashlib.sha256
    ).hexdigest()
    valid = (
        abs(int(time.time()) - timestamp) <= 60
        and bool(x_toolgate_signature)
        and hmac.compare_digest(x_toolgate_signature.removeprefix("sha256="), expected)
    )
    if not valid:
        control_plane.event(
            "verification_callback_rejected",
            "critical",
            "verification_method",
            method["id"],
            "callback",
            {"reason": "invalid signature or timestamp"},
        )
        failures = control_plane.event_count_since(
            "verification_callback_rejected", "verification_method", method["id"], 300
        )
        if failures >= 5:
            control_plane.set_lockdown(True, "system", "repeated invalid verification callbacks")
        deny("CALLBACK_SIGNATURE_INVALID", "Callback signature or timestamp is invalid", 401)
    request = control_plane.get("request", payload.request_id)
    binding = request.get("payload", {}).get("binding", {}) if request else {}
    if not request or request.get("kind") != "verification" or request.get("status") != "pending":
        deny("REQUEST_NOT_PENDING", "Verification request is not pending", 409)
    if not hmac.compare_digest(str(binding.get("nonce", "")), payload.nonce):
        deny("CALLBACK_NONCE_INVALID", "Callback nonce does not match this request", 409)
    if payload.decision not in {"approved", "rejected"}:
        raise HTTPException(422, "decision must be approved or rejected")
    try:
        record = control_plane.decide_request(
            payload.request_id, payload.decision, f"callback:{method['name']}"
        )
    except ValueError as exc:
        deny(
            "REQUEST_NOT_PENDING",
            str(exc),
            409,
            "Refresh the request; do not retry a decided or expired approval",
        )
    if not record:
        deny(
            "REQUEST_NOT_PENDING",
            "Verification request no longer exists",
            409,
            "Request fresh confirmation",
        )
    control_plane.update_verification_method(
        method["id"], {"last_seen_at": datetime.now(UTC).isoformat()}
    )
    control_plane.event(
        "verification_callback_accepted",
        "info",
        "verification_method",
        method["id"],
        "callback",
        {"request_id": payload.request_id, "decision": payload.decision},
    )
    return {"status": record["status"], "request_id": record["id"]}


@app.get("/v2/archives/ai")
def export_ai_archive(_tier: str = Depends(require_admin)):
    return legacy_archive.export()


@app.get("/v2/agent-keys")
def list_agent_keys(_tier: str = Depends(require_admin)):
    return control_plane.list_agent_keys()


@app.post("/v2/agent-keys")
def create_agent_key(payload: AgentKeyCreate, _tier: str = Depends(require_admin)):
    record, raw = control_plane.issue_agent_key(payload.name, payload.scopes)
    return {"key": raw, "record": record}


@app.patch("/v2/agent-keys/{key_id}/scopes")
def update_agent_key_scopes(
    key_id: str, payload: AgentKeyScopes, _tier: str = Depends(require_admin)
):
    record = control_plane.update_agent_key_scopes(key_id, payload.scopes)
    if not record:
        raise HTTPException(404, "agent key not found")
    return record


@app.delete("/v2/agent-keys/{key_id}")
def revoke_agent_key(key_id: str, _tier: str = Depends(require_admin)):
    if not control_plane.revoke_agent_key(key_id):
        raise HTTPException(404, "agent key not found")
    return {"ok": True}


@app.get("/v2/services")
def list_services(_tier: str = Depends(require_admin)):
    tools = control_plane.list_objects("tool")
    automations = control_plane.list_objects("automation")
    return [
        {
            **service,
            "linked_tools": [
                tool["id"] for tool in tools if tool.get("service_id") == service["id"]
            ],
            "linked_automations": [
                item["id"]
                for item in automations
                if any(
                    step.get("tool_id")
                    in {tool["id"] for tool in tools if tool.get("service_id") == service["id"]}
                    for step in item.get("workflow", [])
                    if isinstance(step, dict)
                )
            ],
        }
        for service in control_plane.list_objects("service")
    ]


@app.post("/v2/services")
def create_service(payload: V2Service, _tier: str = Depends(require_admin)):
    service = control_plane.create_service(payload.model_dump())
    control_plane.event("service_saved", "info", "service", service["id"], "admin")
    return service


@app.post("/v2/services/{service_id}/check")
def check_service(service_id: str, _tier: str = Depends(require_admin)):
    service = control_plane.get("service", service_id)
    if not service:
        raise HTTPException(404, "service not found")
    health_url = service.get("destination_policy", {}).get("health_url")
    if not isinstance(health_url, str):
        raise HTTPException(422, "service has no health_url")
    parsed = urlsplit(health_url)
    allowed_internal = (
        parsed.hostname in {"memorygate-api", "memorygate-ollama"} and parsed.scheme == "http"
    )
    allowed_public = public_url(health_url)
    if not (allowed_internal or allowed_public):
        deny("DESTINATION_DENIED", "Service health destination is not allowed")
    try:
        if allowed_public:
            with public_client(timeout=10) as client:
                response = client.get(health_url)
        else:
            response = httpx.get(health_url, timeout=10, follow_redirects=False)
        healthy = 200 <= response.status_code < 300
    except httpx.HTTPError:
        healthy = False
    updated = control_plane.update_service(
        service_id,
        {
            "health": "healthy" if healthy else "unhealthy",
            "last_health_check_at": datetime.now(UTC).isoformat(),
        },
    )
    control_plane.event(
        "service_health_checked",
        "info" if healthy else "warning",
        "service",
        service_id,
        "admin",
        {"healthy": healthy},
    )
    return updated


@app.get("/v2/tools")
def list_tools(_tier: str = Depends(require_admin)):
    return control_plane.list_objects("tool")


@app.get("/v2/tools/{tool_id}")
def get_tool(tool_id: str, _tier: str = Depends(require_admin)):
    tool = control_plane.get("tool", tool_id)
    if not tool:
        raise HTTPException(404, "tool not found")
    return tool


@app.get("/v2/agent/tools")
def agent_tools(agent: dict = Depends(require_agent)):
    return [
        tool
        for tool in control_plane.list_objects("tool")
        if tool.get("status") == "active" and control_plane.is_scoped(agent, tool["id"])
    ]


@app.get("/v2/agent/status")
def agent_status(agent: dict = Depends(require_agent)):
    return {
        "code": "OK",
        "message": "ToolGate is online",
        "id": agent["id"],
        "agent": agent["name"],
        "scopes": agent.get("scopes", []),
        "lockdown": control_plane.settings().get("lockdown", False),
    }


@app.get("/v2/agent/policy-summary")
def agent_policy_summary(agent: dict = Depends(require_agent)):
    """Stable, secret-free policy evidence for the caller's effective capability set."""
    items = []
    for tool in control_plane.list_objects("tool"):
        if tool.get("status") != "active" or not control_plane.is_scoped(agent, tool["id"]):
            continue
        policy = tool.get("policy", {})
        limits = policy.get("usage_limits", {})
        definition = {
            "id": tool["id"],
            "status": tool.get("status"),
            "authorization": tool.get("authorization", "auto"),
            "execution": tool.get("execution", {}),
            "policy": policy,
        }
        definition_canonical = json.dumps(
            definition, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        items.append(
            {
                "id": tool["id"],
                "name": tool.get("name", tool["id"]),
                "authorization": tool.get("authorization", "auto"),
                "executionType": tool.get("execution", {}).get("type", "unknown"),
                "usageLimits": {
                    key: limits[key]
                    for key in (
                        "max_per_minute",
                        "max_per_hour",
                        "cooldown_seconds",
                        "max_runtime_seconds",
                        "max_steps",
                    )
                    if key in limits
                },
                "definitionDigest": hashlib.sha256(definition_canonical.encode()).hexdigest(),
            }
        )
    evidence = {
        "lockdown": bool(control_plane.settings().get("lockdown", False)),
        "scopePatterns": sorted(agent.get("scopes", [])),
        "tools": sorted(items, key=lambda item: item["id"]),
    }
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {**evidence, "digest": hashlib.sha256(canonical.encode()).hexdigest()}


@app.get("/v2/agent/tools/{tool_id}")
def agent_tool_info(tool_id: str, agent: dict = Depends(require_agent)):
    tool = control_plane.get("tool", tool_id)
    if not tool or tool.get("status") != "active" or not control_plane.is_scoped(agent, tool_id):
        raise HTTPException(404, "tool not found or not permitted")
    return tool


def _port_review_authority(agent):
    tool = control_plane.get("tool", "system.port-control")
    if (
        not control_plane.is_scoped(agent, "system.port-control")
        or not tool
        or tool.get("status") != "active"
        or tool.get("authorization") != "owner_confirmation"
        or tool.get("execution") != {"type": "port_control"}
    ):
        deny("POLICY_DENIED", "Active port replacement scope is required", 403)
    with control_plane._conn() as conn:
        require_current_dispatch_authority(conn, agent["id"], "system.port-control")
    return tool


@app.post("/v2/agent/system/port-reviews")
def create_port_review(payload: PortReviewRequest, agent: dict = Depends(require_agent)):
    tool = _port_review_authority(agent)
    enforce_usage_limits("tool", tool, "port_review_created")
    try:
        replacement = port_control.inspect_review(
            payload.container_id,
            payload.operation,
            mapping=payload.mapping.model_dump() if payload.mapping else None,
            original=payload.original.model_dump() if payload.original else None,
        )
        _port_review_authority(agent)
        result = port_reviews.create(agent["id"], replacement)
    except (container_control.ControlError, PlanError, port_reviews.ReviewError) as exc:
        deny("REVIEW_UNAVAILABLE", str(exc), 422)
    control_plane.event("port_review_created", "info", "tool", "system.port-control", agent["name"])
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.get("/v2/agent/system/port-reviews/{review_id}")
def get_port_review(review_id: str, agent: dict = Depends(require_agent)):
    _port_review_authority(agent)
    try:
        result = port_reviews.get(review_id, agent["id"])
    except port_reviews.ReviewError:
        deny("REVIEW_UNAVAILABLE", "Port review is unavailable", 404)
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.get("/v2/agent/system/port-recovery/{action_id:path}")
def inspect_port_recovery(action_id: str, agent: dict = Depends(require_agent)):
    _port_review_authority(agent)
    try:
        result = port_recovery.inspect(action_id, agent["id"])
        _port_review_authority(agent)
    except (port_recovery.RecoveryError, ValueError):
        deny("RECOVERY_UNAVAILABLE", "Replacement recovery evidence is unavailable", 409)
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.post("/v2/agent/system/port-finalizations")
def finalize_port_recovery(
    payload: PortFinalizationRequest, agent: Annotated[dict, Depends(require_agent)]
):
    tool = _port_review_authority(agent)
    parent = journal.get(payload.action_id)
    if (
        not parent
        or parent["actor_id"] != agent["id"]
        or parent["subject_type"] != "tool"
        or parent["subject_id"] != "system.port-control"
    ):
        deny("RECOVERY_UNAVAILABLE", "Replacement recovery is unavailable", 409)
    # Lost recovery acknowledgements read the immutable receipt without another effect.
    if parent["status"] == "completed":
        return JSONResponse(journal.response(parent), headers={"Cache-Control": "no-store"})
    args = {
        "operation": "recover_verified_receipt",
        "action_id": payload.action_id,
        "fingerprint": parent["fingerprint"],
    }
    try:
        receipt = port_finalization.preview(payload.action_id, agent["id"])
        if not payload.approval_request_id:
            enforce_usage_limits("tool", tool, "port_finalization_requested")
            request = control_plane.create_verification_request(
                "Recover verified port replacement receipt",
                "Restore the recorded successful result and release its reservation. "
                "No container changes will run. Recovery may recheck Docker inspection. "
                + json.dumps(receipt),
                agent["name"],
                "tool",
                "system.port-control",
                args,
                tool.get("version"),
                60,
                agent["id"],
            )
            control_plane.event(
                "port_finalization_requested", "info", "tool", "system.port-control", agent["name"]
            )
            return JSONResponse(
                {
                    "code": "CONFIRMATION_REQUIRED",
                    "request_id": request["id"],
                    "expires_at": request["payload"]["binding"]["expires_at"],
                },
                headers={"Cache-Control": "no-store"},
            )

        def authorize(conn):
            require_current_dispatch_authority(conn, agent["id"], "system.port-control")
            row = conn.execute(
                "SELECT * FROM v2_objects WHERE kind='tool' AND id='system.port-control'"
            ).fetchone()
            current = control_plane._row(row) if row else {}
            if (
                current.get("version") != tool.get("version")
                or current.get("status") != "active"
                or current.get("authorization") != "owner_confirmation"
                or current.get("execution") != {"type": "port_control"}
            ):
                deny("POLICY_DENIED", "Port replacement policy changed", 403)
            approved, reason = control_plane.consume_verification_in_transaction(
                conn,
                payload.approval_request_id,
                "tool",
                "system.port-control",
                args,
                tool.get("version"),
                agent["name"],
                agent["id"],
            )
            if not approved:
                deny("APPROVAL_INVALID", reason, 409)

        record = port_finalization.finalize(payload.action_id, agent["id"], authorize=authorize)
    except (ValueError, container_control.ControlError):
        deny("RECOVERY_UNAVAILABLE", "Replacement recovery is unavailable", 409)
    return JSONResponse(journal.response(record), headers={"Cache-Control": "no-store"})


@app.get("/v2/agent/system/targets")
def agent_system_targets(agent: dict = Depends(require_agent)):
    tool_id = "system.container-control"
    if not control_plane.is_scoped(agent, tool_id):
        deny("POLICY_DENIED", "Managed container scope is required", 403)
    result = {
        "kind": "configured-targets",
        "status": "configured",
        "containers": [],
        "actions": [],
        "requiresApproval": True,
        "observed": False,
        "source": "toolgate/container-control",
    }
    tool = control_plane.get("tool", tool_id)
    if control_plane.settings().get("lockdown"):
        result["status"] = "locked_down"
    elif (
        not tool
        or tool.get("status") != "active"
        or tool.get("authorization") != "owner_confirmation"
        or tool.get("execution") != {"type": "container_control"}
    ):
        result["status"] = "disabled"
    else:
        try:
            result["containers"] = container_control.targets()
            result["actions"] = ["start", "stop", "restart"]
        except container_control.ControlError as exc:
            result["status"] = exc.code
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.get("/v2/agent/system/services")
def agent_system_services(agent: dict = Depends(require_agent)):
    tool_id = "system.process-control"
    if not control_plane.is_scoped(agent, tool_id):
        deny("POLICY_DENIED", "Managed service scope is required", 403)
    result = {
        "kind": "configured-targets",
        "status": "configured",
        "services": [],
        "actions": [],
        "requiresApproval": True,
        "observed": False,
        "source": "toolgate/process-control",
    }
    tool = control_plane.get("tool", tool_id)
    if control_plane.settings().get("lockdown"):
        result["status"] = "locked_down"
    elif (
        not tool
        or tool.get("status") != "active"
        or tool.get("authorization") != "owner_confirmation"
        or tool.get("execution") != {"type": "process_control"}
    ):
        result["status"] = "disabled"
    else:
        try:
            result["services"] = process_control.targets()
            result["actions"] = ["start", "stop", "restart"]
        except process_control.ControlError as exc:
            result["status"] = exc.code
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.get("/v2/agent/system/file-roots")
def agent_file_roots(agent: dict = Depends(require_agent)):
    tool_id = "system.files-list"
    if not control_plane.is_scoped(agent, tool_id):
        deny("POLICY_DENIED", "Directory listing scope is required", 403)
    tool = control_plane.get("tool", tool_id)
    if (
        control_plane.settings().get("lockdown")
        or not tool
        or tool.get("status") != "active"
        or tool.get("authorization") == "blocked"
        or tool.get("execution") != {"type": "filesystem_inventory"}
    ):
        return JSONResponse(
            {"mode": "unavailable", "code": "disabled", "roots": []},
            headers={"Cache-Control": "no-store"},
        )
    try:
        result = filesystem_inventory.roots()
    except filesystem_inventory.FileError as exc:
        result = {"mode": "unavailable", "code": exc.code, "roots": []}
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.post("/v2/tools")
def create_tool(payload: V2Tool, _tier: str = Depends(require_admin)):
    body = payload.model_dump()
    require_valid_tool_definition(body)
    tool = control_plane.create_tool(body)
    control_plane.event("tool_saved", "info", "tool", tool["id"], "admin")
    return tool


@app.put("/v2/tools/{tool_id}")
def update_tool(tool_id: str, payload: V2Tool, _tier: str = Depends(require_admin)):
    body = payload.model_dump()
    require_valid_tool_definition(body)
    tool = control_plane.update_tool(tool_id, body)
    if not tool:
        raise HTTPException(404, "tool not found")
    control_plane.event(
        "tool_updated", "info", "tool", tool_id, "admin", {"version": tool["version"]}
    )
    return tool


@app.delete("/v2/tools/{tool_id}")
def delete_tool(tool_id: str, _tier: str = Depends(require_admin)):
    if not control_plane.remove("tool", tool_id):
        raise HTTPException(404, "tool not found")
    control_plane.event("tool_deleted", "warning", "tool", tool_id, "admin")
    return {"deleted": True, "id": tool_id}


@app.post("/v2/tools/{tool_id}/invoke")
def run_tool(tool_id: str, payload: V2Invoke, agent: dict = Depends(require_agent)):
    publication = _requested_publication("tool", tool_id, payload)
    tool = publication["definition"] if publication else control_plane.get("tool", tool_id)
    if not tool:
        deny("TOOL_UNAVAILABLE", f"Tool '{tool_id}' was not found", 404, "Run `toolgate tool list`")
    if tool.get("status") != "active" or not control_plane.is_scoped(agent, tool_id):
        deny(
            "POLICY_DENIED",
            "Your agent key is not allowed to use this tool",
            403,
            "Ask the owner for scope",
        )
    return invoke_tool(
        tool,
        payload.args,
        agent["name"],
        approval_request_id=payload.approval_request_id,
        actor_id=agent["id"],
        action_id=payload.action_id,
        job_id=payload.job_id,
        publication=publication,
        authority_scope=tool_id,
    )


def _requested_publication(kind: str, obj_id: str, payload: V2Invoke) -> dict | None:
    if payload.published_version is None:
        if payload.expected_publication_digest is not None:
            deny("PUBLICATION_REQUIRED", "A publication digest requires published_version", 422)
        return None
    if not payload.action_id:
        deny("ACTION_ID_REQUIRED", "Published runs require a stable action_id", 422)
    with control_plane._conn() as conn:
        publication = publications.for_execution(conn, kind, obj_id, payload.published_version)
        if payload.expected_publication_digest is not None and not secrets.compare_digest(
            payload.expected_publication_digest, publication["digest"]
        ):
            deny(
                "PUBLICATION_MISMATCH",
                "The selected publication does not match the expected digest",
                409,
            )
        return publication


def _publish_definition(kind: str, obj_id: str, payload: V2Publish):
    validator = (
        require_valid_tool_definition if kind == "tool" else require_valid_automation_definition
    )
    try:
        result = publications.publish(
            kind,
            obj_id,
            payload.expected_version,
            validate=validator,
            validate_tool=require_valid_tool_definition,
        )
    except publications.PublicationInvalid as exc:
        raise HTTPException(422, {"code": "INVALID_PUBLICATION", "message": str(exc)}) from exc
    if result is None:
        raise HTTPException(404, "definition not found")
    return result


@app.post("/v2/tools/{tool_id}/publish", dependencies=[Depends(require_admin)])
def publish_tool(tool_id: str, payload: V2Publish):
    return _publish_definition("tool", tool_id, payload)


@app.post("/v2/automations/{automation_id}/publish", dependencies=[Depends(require_admin)])
def publish_automation(automation_id: str, payload: V2Publish):
    return _publish_definition("automation", automation_id, payload)


@app.get("/v2/tools/{tool_id}/versions", dependencies=[Depends(require_admin)])
def tool_versions(tool_id: str):
    return publications.history("tool", tool_id)


@app.get("/v2/automations/{automation_id}/versions", dependencies=[Depends(require_admin)])
def automation_versions(automation_id: str):
    return publications.history("automation", automation_id)


def _definition_version(kind: str, obj_id: str, version: int, published: bool):
    result = publications.get(kind, obj_id, version, published=published)
    if result is None:
        raise HTTPException(404, "definition version not found")
    return result


@app.get("/v2/tools/{tool_id}/versions/{version}", dependencies=[Depends(require_admin)])
def tool_version(tool_id: str, version: int, published: bool = False):
    return _definition_version("tool", tool_id, version, published)


@app.get(
    "/v2/automations/{automation_id}/versions/{version}", dependencies=[Depends(require_admin)]
)
def automation_version(automation_id: str, version: int, published: bool = False):
    return _definition_version("automation", automation_id, version, published)


@app.get("/v2/automations")
def list_automations(_tier: str = Depends(require_admin)):
    return control_plane.list_objects("automation")


@app.get("/v2/actions")
def list_actions(_tier: str = Depends(require_admin)):
    return {"results": journal.list_actions()}


@app.get("/v2/agent/actions/{action_id:path}")
def agent_action(action_id: str, agent: dict = Depends(require_agent)):
    record = journal.get(action_id)
    if not record or record["actor_id"] != agent["id"]:
        raise HTTPException(404, "action not found")
    return journal.response(record)


@app.get("/v2/automations/{automation_id}")
def get_automation(automation_id: str, _tier: str = Depends(require_admin)):
    automation = control_plane.get("automation", automation_id)
    if not automation:
        raise HTTPException(404, "automation not found")
    return automation


@app.get("/v2/agent/automations")
def agent_automations(agent: dict = Depends(require_agent)):
    return [
        item
        for item in control_plane.list_objects("automation")
        if item.get("status") == "active"
        and control_plane.is_scoped(agent, f"automation:{item['id']}")
    ]


@app.get("/v2/agent/published-workflows")
def agent_published_workflows(agent: dict = Depends(require_agent)):
    return editor_catalogue.agent_workflows(agent)


@app.get("/v2/agent/automations/{automation_id}")
def agent_automation_info(automation_id: str, agent: dict = Depends(require_agent)):
    item = control_plane.get("automation", automation_id)
    if (
        not item
        or item.get("status") != "active"
        or not control_plane.is_scoped(agent, f"automation:{automation_id}")
    ):
        raise HTTPException(404, "automation not found or not permitted")
    return item


@app.post("/v2/automations")
def create_automation(payload: V2Automation, _tier: str = Depends(require_admin)):
    body = payload.model_dump()
    require_valid_automation_definition(body)
    automation = control_plane.create_automation(body)
    control_plane.event("automation_saved", "info", "automation", automation["id"], "admin")
    return automation


@app.put("/v2/automations/{automation_id}")
def update_automation(
    automation_id: str, payload: V2Automation, _tier: str = Depends(require_admin)
):
    body = payload.model_dump()
    require_valid_automation_definition(body)
    automation = control_plane.update_automation(automation_id, body)
    if not automation:
        raise HTTPException(404, "automation not found")
    control_plane.event(
        "automation_updated",
        "info",
        "automation",
        automation_id,
        "admin",
        {"version": automation["version"]},
    )
    return automation


@app.delete("/v2/automations/{automation_id}")
def delete_automation(automation_id: str, _tier: str = Depends(require_admin)):
    if not control_plane.remove("automation", automation_id):
        raise HTTPException(404, "automation not found")
    control_plane.event("automation_deleted", "warning", "automation", automation_id, "admin")
    return {"deleted": True, "id": automation_id}


@app.post("/v2/automations/{automation_id}/run")
def run_automation(automation_id: str, payload: V2Invoke, agent: dict = Depends(require_agent)):
    publication = _requested_publication("automation", automation_id, payload)
    publication_digest = publication["digest"] if publication else None
    automation = (
        publication["definition"] if publication else control_plane.get("automation", automation_id)
    )
    if not automation or automation.get("status") != "active":
        deny("TOOL_UNAVAILABLE", "Automation is not active", 404)
    if not control_plane.is_scoped(agent, f"automation:{automation_id}"):
        deny("POLICY_DENIED", "Your agent key is not allowed to run this automation")
    if not publication and any(
        step.get("type") == "editor_graph" for step in automation.get("workflow", [])
    ):
        deny("PUBLICATION_REQUIRED", "Editor graphs require an immutable published version", 422)
    if not publication and workflow_tool_ids(automation.get("workflow", []), "automation_call"):
        deny(
            "PUBLICATION_REQUIRED",
            "Nested automation calls require an explicit published root version",
            422,
        )
    authority_scope = (
        tuple(
            dict.fromkeys(
                f"automation:{member['id']}" for member in publications.members(publication)
            )
        )
        if publication
        else (f"automation:{automation_id}",)
    )
    if not all(control_plane.is_scoped(agent, scope) for scope in authority_scope):
        deny("POLICY_DENIED", "The agent needs every pinned nested automation scope", 403)
    if not payload.action_id:
        deny("ACTION_ID_REQUIRED", "Supply a stable action_id for this workflow run", 422)
    try:
        previous = journal.existing(
            payload.action_id,
            "automation",
            automation_id,
            payload.args,
            agent["id"],
            payload.job_id,
            publication_digest=publication_digest,
        )
    except (journal.ExecutionConflict, ValueError) as exc:
        deny("ACTION_CONFLICT", str(exc), 409)
    if previous:
        return journal.response(previous)
    if control_plane.settings().get("lockdown"):
        deny("LOCKED_DOWN", "ToolGate is in lockdown mode", 423)
    errors = _automation_input_errors(automation, payload.args)
    if errors:
        deny("VALIDATION_ERROR", "; ".join(errors), 422)
    authorization = automation.get("authorization", "auto")
    if authorization == "blocked":
        control_plane.event(
            "execution_blocked",
            "warning",
            "automation",
            automation_id,
            agent["name"],
            {"code": "POLICY_DENIED"},
        )
        deny("POLICY_DENIED", "This automation is permanently blocked by its owner policy")
    approval_granted = False
    tool_snapshot = {}
    if authorization != "auto" and not payload.approval_request_id:
        expiry = int(control_plane.settings().get("default_confirmation_expiry_seconds", 60))
        request = control_plane.create_verification_request(
            f"Run {automation['name']}",
            "Owner confirmation is required for this exact immutable automation run.",
            agent["name"],
            "automation",
            automation_id,
            payload.args,
            automation.get("version"),
            expiry,
            agent["id"],
            publication_digest=publication_digest,
        )
        return {
            "code": "CONFIRMATION_REQUIRED",
            "message": "Automation queued for owner review",
            "request_id": request["id"],
            "expires_at": request["payload"]["binding"]["expires_at"],
            "next_action": f"After approval, retry with --approval-request-id {request['id']}",
        }
    limits = automation.get("policy", {}).get("usage_limits", {})

    def authorize(conn):
        nonlocal approval_granted, tool_snapshot
        require_current_dispatch_authority(conn, agent["id"], authority_scope)
        if publication:
            tool_snapshot = publications.for_execution(
                conn, "automation", automation_id, publication["version"]
            )["tools"]
        else:
            tool_snapshot = control_plane.automation_tool_snapshot(
                conn, automation_id, automation.get("version")
            )
        enforce_dispatch_usage_limits(conn, "automation", automation, "automation_executed")
        if authorization != "auto":
            approval_granted, reason = control_plane.consume_verification_in_transaction(
                conn,
                payload.approval_request_id,
                "automation",
                automation_id,
                payload.args,
                automation.get("version"),
                agent["name"],
                agent["id"],
                publication_digest=publication_digest,
            )
            if not approval_granted:
                deny("APPROVAL_INVALID", reason, 409)

    try:
        record, dispatch = journal.begin(
            payload.action_id,
            "automation",
            automation_id,
            payload.args,
            agent["id"],
            automation.get("version"),
            job_id=payload.job_id,
            authorize=authorize,
            publication_digest=publication_digest,
        )
    except (journal.ExecutionConflict, ValueError) as exc:
        deny("ACTION_CONFLICT", str(exc), 409)
    if not dispatch:
        return journal.response(record)
    state = {
        "automation_id": automation_id,
        "tool_snapshot": tool_snapshot,
        "action_id": payload.action_id,
        "publication": publication,
        "authority_scope": authority_scope,
        "job_id": payload.job_id,
        "actor_id": agent["id"],
        "args": payload.args,
        "vars": {},
        "last": None,
        "results": [],
        "count": 0,
        "max_steps": int(limits.get("max_steps", 100)),
        "started_at": time.monotonic(),
        "runtime_ceiling": min(int(limits.get("max_runtime_seconds", 30) or 30), 120),
    }
    try:
        final = _run_workflow_steps(
            automation.get("workflow", []), state, agent["name"], approval_granted
        )
    except Exception:
        journal.unknown(payload.action_id)
        return journal.response(journal.get(payload.action_id))
    failed = isinstance(final, dict) and final.get("code") == "WORKFLOW_FAILED"
    envelope = {
        "code": "WORKFLOW_FAILED" if failed else "OK",
        "message": "Workflow failed" if failed else "Automation completed",
        "result": final,
        "steps": state["results"],
        "variables": state["vars"],
    }
    if publication:
        envelope["publication"] = {
            "kind": "automation",
            "id": automation_id,
            "version": publication["version"],
            "digest": publication_digest,
        }
    record = journal.finish(payload.action_id, envelope)
    control_plane.event(
        "automation_executed",
        "info",
        "automation",
        automation_id,
        agent["name"],
        {
            "steps": state["count"],
            "version": automation.get("version"),
            "action_id": payload.action_id,
        },
    )
    return journal.response(record)


@app.get("/v2/requests")
def list_requests(_tier: str = Depends(require_admin)):
    return control_plane.list_objects("request")


@app.get("/v2/owner/requests", dependencies=[Depends(require_owner)])
def owner_requests(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(
        default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$"
    ),
):
    return owner_channel.list_requests(limit, cursor)


@app.get("/v2/owner/editor-capabilities", dependencies=[Depends(require_owner)])
def owner_editor_capabilities(
    kind: Literal["tool", "workflow"] = "tool",
    q: str = Query(default="", max_length=100),
    after: str | None = Query(default=None, max_length=80, pattern=r"^[a-z0-9][a-z0-9.-]{1,79}$"),
    limit: int = Query(default=50, ge=1, le=100),
):
    return editor_catalogue.list_capabilities(kind, q, after, limit)


@app.get("/v2/owner/editor-drafts", dependencies=[Depends(require_owner)])
def owner_editor_drafts(
    limit: int = Query(default=50, ge=1, le=100),
    after: str | None = Query(default=None, max_length=64),
):
    return editor_drafts.list_drafts(limit, after)


@app.get("/v2/owner/editor-drafts/{draft_id}", dependencies=[Depends(require_owner)])
def owner_editor_draft(draft_id: str):
    return editor_drafts.get(draft_id)


@app.get("/v2/owner/editor-drafts/{draft_id}/validation", dependencies=[Depends(require_owner)])
def validate_owner_editor_draft(draft_id: str):
    record = editor_drafts.get(draft_id)
    document = editor_drafts.EditorDocument.model_validate(record["document"])
    issues = editor_graph.validate_graph(document)
    return {
        "id": draft_id,
        "revision": record["revision"],
        "graph_valid": not issues,
        "issues": issues,
        "execution_ready": False,
    }


@app.post("/v2/owner/editor-drafts/{draft_id}", dependencies=[Depends(require_owner)])
def save_owner_editor_draft(draft_id: str, payload: editor_drafts.SaveDraft):
    return editor_drafts.save(draft_id, payload)


@app.get("/v2/owner/editor-drafts/{draft_id}/publications", dependencies=[Depends(require_owner)])
def owner_editor_publications(draft_id: str):
    return {"items": editor_publication.history(draft_id)}


@app.get("/v2/owner/editor-drafts/{draft_id}/access", dependencies=[Depends(require_owner)])
def editor_access(
    draft_id: str,
    version: int = Query(ge=1),
    digest: str = Query(pattern=r"^[a-f0-9]{64}$"),
    agent: dict = Depends(require_agent),
):
    return editor_runs.access(draft_id, editor_runs.Target(version=version, digest=digest), agent)


@app.post("/v2/owner/editor-drafts/{draft_id}/access", dependencies=[Depends(require_owner)])
def change_editor_access(
    draft_id: str, payload: editor_runs.Access, agent: dict = Depends(require_agent)
):
    return editor_runs.access(draft_id, payload, agent, enabled=payload.enabled)


@app.get("/v2/owner/editor-drafts/{draft_id}/runs", dependencies=[Depends(require_owner)])
def owner_editor_runs(draft_id: str, agent: dict = Depends(require_agent)):
    return editor_runs.history(draft_id, agent)


@app.post("/v2/owner/editor-drafts/{draft_id}/runs", dependencies=[Depends(require_owner)])
def run_owner_editor_draft(
    draft_id: str, payload: editor_runs.Run, agent: dict = Depends(require_agent)
):
    publication, previous, dispatch = editor_runs.begin(draft_id, payload, agent)
    if not dispatch:
        return editor_runs._response(previous)
    try:
        result = run_automation(
            publication["id"],
            V2Invoke(
                args=payload.args,
                action_id=payload.action_id,
                approval_request_id=payload.approval_request_id,
                published_version=payload.version,
                expected_publication_digest=payload.digest,
            ),
            agent,
        )
    except HTTPException as exc:
        # A policy rejection is a known response. Any uncertain child dispatch is
        # already held by run_automation's journal; never try an alternate path.
        result = {
            "code": exc.detail.get("code", "REQUEST_REJECTED")
            if isinstance(exc.detail, dict)
            else "REQUEST_REJECTED",
            "message": "Run was rejected. Check publication availability, access and approval before creating another run.",
        }
        request = (
            control_plane.get("request", payload.approval_request_id)
            if payload.approval_request_id
            else None
        )
        if result["code"] == "APPROVAL_INVALID" and request and request.get("status") == "pending":
            result = {
                "code": "CONFIRMATION_REQUIRED",
                "request_id": payload.approval_request_id,
                "message": "Approval is still pending in Inbox. Resume this same run after approval.",
            }
    result = {**result, "action_id": payload.action_id}
    return editor_runs.finish(payload.action_id, result)


@app.post("/v2/owner/editor-drafts/{draft_id}/publish", dependencies=[Depends(require_owner)])
def publish_owner_editor_draft(draft_id: str, payload: editor_publication.PublishDraft):
    publication = editor_publication.publish_draft(
        draft_id,
        payload,
        validate=require_valid_automation_definition,
        validate_tool=require_valid_tool_definition,
    )
    return {
        "draft_id": draft_id,
        "revision": payload.expected_revision,
        "automation_id": publication["id"],
        "version": publication["version"],
        "digest": publication["digest"],
        "published_at": publication["published_at"],
    }


@app.get("/v2/owner/requests/{request_id}", dependencies=[Depends(require_owner)])
def owner_request(request_id: str):
    return owner_channel.get(request_id)


@app.post("/v2/owner/requests/{request_id}/decision", dependencies=[Depends(require_owner)])
def owner_decision(request_id: str, payload: OwnerDecision):
    return owner_channel.decide(request_id, payload.status, payload.note)


@app.post("/v2/requests")
def create_agent_request(payload: V2Request, agent: dict = Depends(require_agent)):
    if control_plane.settings().get("lockdown"):
        deny("LOCKED_DOWN", "ToolGate is in lockdown mode", 423)
    if payload.kind == "ai_draft":
        deny(
            "AI_DRAFT_RETIRED",
            "AI drafts belong in Pi",
            410,
            "Use the owner tools API to register a reviewed capability",
        )
    try:
        return control_plane.create_request(
            payload.kind,
            payload.title,
            payload.details,
            agent["name"],
            {**payload.payload, "created_by_agent_key": agent["id"]},
            payload.severity,
        )
    except ValueError as exc:
        deny(
            "REQUEST_KIND_INVALID",
            str(exc),
            422,
            "Invoke the exact tool or automation to request confirmation",
        )


@app.get("/v2/agent/requests/{request_id}")
def agent_request_status(request_id: str, agent: dict = Depends(require_agent)):
    request = control_plane.get("request", request_id)
    if not request or request.get("payload", {}).get("created_by_agent_key") != agent["id"]:
        raise HTTPException(404, "request not found")
    return {
        "id": request["id"],
        "kind": request["kind"],
        "status": request["status"],
        "title": request["title"],
        "created_at": request["created_at"],
        "decision": request.get("decision"),
    }


@app.post("/v2/admin/requests")
def create_admin_request(payload: V2Request, _tier: str = Depends(require_admin)):
    if payload.kind == "ai_draft":
        deny(
            "AI_DRAFT_RETIRED",
            "AI drafts belong in Pi",
            410,
            "Use the owner tools API to register a reviewed capability",
        )
    try:
        return control_plane.create_request(
            payload.kind, payload.title, payload.details, "admin", payload.payload, payload.severity
        )
    except ValueError as exc:
        deny(
            "REQUEST_KIND_INVALID",
            str(exc),
            422,
            "Invoke the exact tool or automation to request confirmation",
        )


@app.post("/v2/requests/{request_id}/decision")
def decide_request(
    request_id: str, payload: V2RequestDecision, _tier: str = Depends(require_admin)
):
    if payload.status not in {"approved", "rejected", "dismissed"}:
        raise HTTPException(400, "status must be approved, rejected, or dismissed")
    existing = control_plane.get("request", request_id)
    if existing and existing.get("kind") == "ai_draft":
        deny(
            "AI_DRAFT_RETIRED",
            "Legacy AI drafts are read-only history",
            410,
            "Export /v2/archives/ai and recreate the capability through the owner tools API",
        )
    try:
        record = control_plane.decide_request(request_id, payload.status, "admin", payload.note)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    if not record:
        raise HTTPException(404, "request not found")
    return record


@app.get("/v2/events")
def list_events(limit: int = 100, _tier: str = Depends(require_admin)):
    return control_plane.events(limit)


@app.get("/v2/agent/events")
def agent_events(limit: int = 50, _agent: dict = Depends(require_agent)):
    return [
        {
            key: event[key]
            for key in ("id", "event_type", "severity", "subject_type", "subject_id", "created_at")
        }
        for event in control_plane.events(limit)
    ]


app.include_router(_spending_router)
