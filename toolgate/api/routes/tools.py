"""Owner tool catalogue (create, update, delete) and the agent's tool invocation route."""

from fastapi import APIRouter, Depends, HTTPException

from toolgate.api.definitions import require_valid_tool_definition
from toolgate.api.deps import deny, require_admin, require_agent
from toolgate.api.invocation import invoke_tool
from toolgate.api.models import V2Invoke, V2Tool
from toolgate.api.routes.publications import _requested_publication
from toolgate.core import control_plane

router = APIRouter()


@router.get("/v2/tools")
def list_tools(_tier: str = Depends(require_admin)):
    return control_plane.list_objects("tool")


@router.get("/v2/tools/{tool_id}")
def get_tool(tool_id: str, _tier: str = Depends(require_admin)):
    tool = control_plane.get("tool", tool_id)
    if not tool:
        raise HTTPException(404, "tool not found")
    return tool


@router.post("/v2/tools")
def create_tool(payload: V2Tool, _tier: str = Depends(require_admin)):
    body = payload.model_dump()
    require_valid_tool_definition(body)
    # Creating needs no version; replacing an existing tool needs the one the caller saw.
    tool = control_plane.create_tool(body, require_absent=body.get("expected_version") is None)
    control_plane.event("tool_saved", "info", "tool", tool["id"], "admin")
    return tool


@router.put("/v2/tools/{tool_id}")
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


@router.delete("/v2/tools/{tool_id}")
def delete_tool(tool_id: str, _tier: str = Depends(require_admin)):
    if not control_plane.remove("tool", tool_id):
        raise HTTPException(404, "tool not found")
    control_plane.event("tool_deleted", "warning", "tool", tool_id, "admin")
    return {"deleted": True, "id": tool_id}


@router.post("/v2/tools/{tool_id}/invoke")
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
