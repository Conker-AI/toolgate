"""Owner routes for access: let Pi decide by his policy, mark tools that always ask him, and
choose which tools the chat's key may use at all."""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from toolgate.api.deps import deny, require_agent, require_owner
from toolgate.core import access_policy, control_plane, tool_access

router = APIRouter()


@router.get("/v2/owner/access", dependencies=[Depends(require_owner)])
def owner_access(agent: dict = Depends(require_agent)):
    """Whether the presented key decides by his policy, and the tools on his floor."""
    return JSONResponse(
        {
            "delegate": access_policy.is_delegate(agent),
            "sensitive": sorted(access_policy.sensitive_ids()),
            "floorExecutions": sorted(access_policy.FLOOR_EXECUTIONS),
        },
        headers={"Cache-Control": "no-store"},
    )


@router.post("/v2/owner/access/delegate", dependencies=[Depends(require_owner)])
def owner_set_delegate(payload: access_policy.Delegation, agent: dict = Depends(require_agent)):
    """Lets the presented key's "run" decisions skip his confirmation (never on the floor)."""
    return {"delegate": access_policy.set_delegate(agent, payload.enabled)}


@router.post("/v2/owner/tools/{tool_id}/sensitive", dependencies=[Depends(require_owner)])
def owner_set_sensitive(tool_id: str, payload: access_policy.Sensitivity):
    """A sensitive tool always asks him, whatever the chat, agent or AI decides."""
    if control_plane.get("tool", tool_id) is None:
        deny("TOOL_UNAVAILABLE", "No such tool", 404)
    return {"id": tool_id, "sensitive": access_policy.set_sensitive(tool_id, payload.sensitive)}


@router.get("/v2/owner/tools/{tool_id}/access", dependencies=[Depends(require_owner)])
def owner_tool_access(tool_id: str, agent: dict = Depends(require_agent)):
    """Whether the presented key may use this tool."""
    return JSONResponse(tool_access.access(tool_id, agent), headers={"Cache-Control": "no-store"})


@router.post("/v2/owner/tools/{tool_id}/access", dependencies=[Depends(require_owner)])
def owner_set_tool_access(
    tool_id: str, payload: tool_access.State, agent: dict = Depends(require_agent)
):
    """Grant or revoke the presented key's use of this tool (never an agent's or a bound key's)."""
    return JSONResponse(
        tool_access.access(tool_id, agent, payload), headers={"Cache-Control": "no-store"}
    )
