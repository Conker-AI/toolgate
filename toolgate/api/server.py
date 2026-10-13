"""ToolGate v2 API: a typed, owner-controlled agent capability boundary."""

import hashlib
import json
import os
import secrets
import sqlite3
import time
from datetime import UTC, datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
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
    OwnerDecision,
    PortFinalizationRequest,
    PortReviewRequest,
    V2Automation,
    V2Invoke,
    V2Publish,
    V2Request,
    V2RequestDecision,
    V2Service,
    V2Tool,
)
from toolgate.api.routes.agent_keys import router as _agent_keys_router
from toolgate.api.routes.health import router as _health_router
from toolgate.api.routes.settings import router as _settings_router
from toolgate.api.routes.spending import router as _spending_router
from toolgate.api.routes.vault import router as _vault_router
from toolgate.api.version import SERVICE_VERSION
from toolgate.api.workflows import _automation_input_errors, _run_workflow_steps
from toolgate.core import (
    control_plane,
    editor_catalogue,
    editor_drafts,
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


app.include_router(_health_router)


app.include_router(_vault_router)


app.include_router(_settings_router)


app.include_router(_agent_keys_router)


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
