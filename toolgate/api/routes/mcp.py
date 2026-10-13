"""Owner routes for external MCP servers: discover, import, enable and scope their tools."""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from toolgate.api.definitions import require_valid_tool_definition
from toolgate.api.deps import require_agent, require_owner
from toolgate.core import mcp_imports
from toolgate.executors import mcp_http

router = APIRouter()


@router.post("/v2/owner/mcp/discover", dependencies=[Depends(require_owner)])
def owner_mcp_discover(payload: mcp_imports.Discover):
    return JSONResponse(mcp_http.discover(payload.url, payload.secret_ref), headers={"Cache-Control": "no-store"})


@router.post("/v2/owner/mcp/import", dependencies=[Depends(require_owner)])
def owner_mcp_import(payload: mcp_imports.Import):
    return JSONResponse(mcp_imports.import_tool(payload, require_valid_tool_definition), headers={"Cache-Control": "no-store"})


@router.get("/v2/owner/mcp/tools", dependencies=[Depends(require_owner)])
def owner_mcp_tools():
    return JSONResponse(mcp_imports.list_tools(), headers={"Cache-Control": "no-store"})


@router.post("/v2/owner/mcp/tools/{tool_id}/state", dependencies=[Depends(require_owner)])
def owner_mcp_state(tool_id: str, payload: mcp_imports.State):
    return JSONResponse(mcp_imports.set_state(tool_id, payload, require_valid_tool_definition), headers={"Cache-Control": "no-store"})


@router.get("/v2/owner/mcp/tools/{tool_id}/access", dependencies=[Depends(require_owner)])
def owner_mcp_access(tool_id: str, agent: dict = Depends(require_agent)):
    return JSONResponse(mcp_imports.access(tool_id, agent), headers={"Cache-Control": "no-store"})


@router.post("/v2/owner/mcp/tools/{tool_id}/access", dependencies=[Depends(require_owner)])
def owner_mcp_set_access(tool_id: str, payload: mcp_imports.State, agent: dict = Depends(require_agent)):
    return JSONResponse(mcp_imports.access(tool_id, agent, payload), headers={"Cache-Control": "no-store"})
