"""ToolGate v2 API: a typed, owner-controlled agent capability boundary."""

import hashlib
import json
import os
import sqlite3

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from toolgate.api.builtin_capabilities import (
    ensure_builtin_research_capabilities,
    ensure_builtin_system_capabilities,
)
from toolgate.api.deps import deny, require_admin, require_agent, require_owner
from toolgate.api.models import (
    OwnerDecision,
    V2Request,
    V2RequestDecision,
)
from toolgate.api.routes.agent_keys import router as _agent_keys_router
from toolgate.api.routes.automations import router as _automations_router
from toolgate.api.routes.editor import router as _editor_router
from toolgate.api.routes.health import router as _health_router
from toolgate.api.routes.publications import router as _publications_router
from toolgate.api.routes.services import router as _services_router
from toolgate.api.routes.settings import router as _settings_router
from toolgate.api.routes.spending import router as _spending_router
from toolgate.api.routes.system import router as _system_router
from toolgate.api.routes.tools import router as _tools_router
from toolgate.api.routes.vault import router as _vault_router
from toolgate.api.version import SERVICE_VERSION
from toolgate.core import (
    control_plane,
    editor_catalogue,
    legacy_archive,
    owner_channel,
    publications,
    recovery_journal,
    vault,
)
from toolgate.core import execution_journal as journal

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


app.include_router(_services_router)


app.include_router(_tools_router)


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


app.include_router(_system_router)


app.include_router(_publications_router)


app.include_router(_automations_router)


@app.get("/v2/actions")
def list_actions(_tier: str = Depends(require_admin)):
    return {"results": journal.list_actions()}


@app.get("/v2/agent/actions/{action_id:path}")
def agent_action(action_id: str, agent: dict = Depends(require_agent)):
    record = journal.get(action_id)
    if not record or record["actor_id"] != agent["id"]:
        raise HTTPException(404, "action not found")
    return journal.response(record)


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


app.include_router(_editor_router)


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
