"""ToolGate v2 API: a typed, owner-controlled agent capability boundary."""

import os
import sqlite3

from fastapi import Depends, FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from toolgate.api.builtin_capabilities import (
    ensure_builtin_research_capabilities,
    ensure_builtin_system_capabilities,
)
from toolgate.api.deps import require_admin
from toolgate.api.routes.agent import router as _agent_router
from toolgate.api.routes.agent_keys import router as _agent_keys_router
from toolgate.api.routes.automations import router as _automations_router
from toolgate.api.routes.editor import router as _editor_router
from toolgate.api.routes.health import router as _health_router
from toolgate.api.routes.publications import router as _publications_router
from toolgate.api.routes.requests import router as _requests_router
from toolgate.api.routes.services import router as _services_router
from toolgate.api.routes.settings import router as _settings_router
from toolgate.api.routes.spending import router as _spending_router
from toolgate.api.routes.system import router as _system_router
from toolgate.api.routes.tools import router as _tools_router
from toolgate.api.routes.vault import router as _vault_router
from toolgate.api.version import SERVICE_VERSION
from toolgate.core import (
    control_plane,
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


app.include_router(_agent_router)


app.include_router(_system_router)


app.include_router(_publications_router)


app.include_router(_automations_router)


@app.get("/v2/actions")
def list_actions(_tier: str = Depends(require_admin)):
    return {"results": journal.list_actions()}


app.include_router(_requests_router)


app.include_router(_editor_router)


@app.get("/v2/events")
def list_events(limit: int = 100, _tier: str = Depends(require_admin)):
    return control_plane.events(limit)


app.include_router(_spending_router)
