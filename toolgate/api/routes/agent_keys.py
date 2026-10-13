"""Owner management of agent keys and their scopes."""

from fastapi import APIRouter, Depends, HTTPException

from toolgate.api.deps import require_admin
from toolgate.api.models import AgentKeyCreate, AgentKeyScopes
from toolgate.core import control_plane

router = APIRouter()


@router.get("/v2/agent-keys")
def list_agent_keys(_tier: str = Depends(require_admin)):
    return control_plane.list_agent_keys()


@router.post("/v2/agent-keys")
def create_agent_key(payload: AgentKeyCreate, _tier: str = Depends(require_admin)):
    record, raw = control_plane.issue_agent_key(payload.name, payload.scopes)
    return {"key": raw, "record": record}


@router.patch("/v2/agent-keys/{key_id}/scopes")
def update_agent_key_scopes(
    key_id: str, payload: AgentKeyScopes, _tier: str = Depends(require_admin)
):
    record = control_plane.update_agent_key_scopes(key_id, payload.scopes)
    if not record:
        raise HTTPException(404, "agent key not found")
    return record


@router.delete("/v2/agent-keys/{key_id}")
def revoke_agent_key(key_id: str, _tier: str = Depends(require_admin)):
    if not control_plane.revoke_agent_key(key_id):
        raise HTTPException(404, "agent key not found")
    return {"ok": True}
