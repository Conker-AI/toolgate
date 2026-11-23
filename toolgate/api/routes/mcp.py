"""Owner routes for external MCP servers: discover, import, enable, classify and scope their tools."""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from toolgate.api.definitions import require_valid_tool_definition
from toolgate.api.deps import require_agent, require_owner
from toolgate.core import mcp_imports, mcp_observe
from toolgate.executors import mcp_http

router = APIRouter()


@router.post("/v2/owner/mcp/discover", dependencies=[Depends(require_owner)])
def owner_mcp_discover(payload: mcp_imports.Discover):
    discovered = mcp_http.discover(payload.url, payload.secret_ref)
    # A tool he marked Observe that this server now advertises differently asks him again.
    mcp_observe.notice(payload.url, payload.secret_ref, discovered)
    return JSONResponse(discovered, headers={"Cache-Control": "no-store"})


@router.post("/v2/owner/mcp/import", dependencies=[Depends(require_owner)])
def owner_mcp_import(payload: mcp_imports.Import):
    return JSONResponse(
        mcp_imports.import_tool(payload, require_valid_tool_definition),
        headers={"Cache-Control": "no-store"},
    )


@router.get("/v2/owner/mcp/tools", dependencies=[Depends(require_owner)])
def owner_mcp_tools():
    return JSONResponse(mcp_imports.list_tools(), headers={"Cache-Control": "no-store"})


@router.post("/v2/owner/mcp/tools/{tool_id}/state", dependencies=[Depends(require_owner)])
def owner_mcp_state(tool_id: str, payload: mcp_imports.State):
    return JSONResponse(
        mcp_imports.set_state(tool_id, payload, require_valid_tool_definition),
        headers={"Cache-Control": "no-store"},
    )


@router.post("/v2/owner/mcp/tools/{tool_id}/class", dependencies=[Depends(require_owner)])
def owner_mcp_class(tool_id: str, payload: mcp_imports.ReadClass):
    """Observe (runs without asking; scope, limits, spending and the audit log still apply) or
    Act outward (asks for every exact call, the default). Observe rediscovers the endpoint and is
    refused unless the names have the shape of a read (a read verb and one part, or longer when
    the server's annotations say read-only; nothing that acts; 422 `act_outward_name`), the
    server's annotations, if any, say read-only (422 `act_outward_hint`) and it still advertises
    the tool as imported (409 `schema_changed`); it binds the description and annotations seen.
    A stale `expected_version` is refused (409). Pi's gateway asks the owner's password for Observe, as
    for every access grant."""
    return JSONResponse(
        mcp_imports.set_class(tool_id, payload), headers={"Cache-Control": "no-store"}
    )


@router.get("/v2/owner/mcp/tools/{tool_id}/access", dependencies=[Depends(require_owner)])
def owner_mcp_access(tool_id: str, agent: dict = Depends(require_agent)):
    return JSONResponse(mcp_imports.access(tool_id, agent), headers={"Cache-Control": "no-store"})


@router.post("/v2/owner/mcp/tools/{tool_id}/access", dependencies=[Depends(require_owner)])
def owner_mcp_set_access(
    tool_id: str, payload: mcp_imports.State, agent: dict = Depends(require_agent)
):
    return JSONResponse(
        mcp_imports.access(tool_id, agent, payload), headers={"Cache-Control": "no-store"}
    )
