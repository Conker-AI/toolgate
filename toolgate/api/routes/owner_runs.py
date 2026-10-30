"""Owner routes to run one tool by hand and read its recent runs from the journal."""

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from toolgate.api.deps import deny, require_agent, require_owner
from toolgate.api.invocation import invoke_tool
from toolgate.core import control_plane, owner_runs

router = APIRouter()


@router.post("/v2/owner/tools/{tool_id}/runs", dependencies=[Depends(require_owner)])
def owner_run_tool(tool_id: str, payload: owner_runs.ToolRun, agent: dict = Depends(require_agent)):
    """Run any active tool as the owner, under the chat's own key. A tool that asks still makes an
    approval request; resume with the same action_id and its approval_request_id."""
    owner_runs.own_key(agent)
    tool = control_plane.get("tool", tool_id)
    if not tool or tool.get("status") != "active":
        deny("TOOL_UNAVAILABLE", "No such tool", 404)
    return invoke_tool(
        tool,
        payload.args,
        owner_runs.ACTOR,
        approval_request_id=payload.approval_request_id,
        actor_id=agent["id"],
        action_id=payload.action_id,
        # His authority stands in for the key's scope; the key must still be active when it runs.
        authority_scope=(),
        decision=owner_runs.decision(tool),
    )


@router.get("/v2/owner/tools/{tool_id}/runs", dependencies=[Depends(require_owner)])
def owner_tool_runs(tool_id: str, limit: int = Query(default=20, ge=1, le=owner_runs.MAX_RUNS)):
    """The newest runs of this tool, by any key, as the journal stores them."""
    return JSONResponse(owner_runs.history(tool_id, limit), headers={"Cache-Control": "no-store"})
