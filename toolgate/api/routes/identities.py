"""Agent identities: a key defines its agents' toolkits; the owner mints keys bound to one agent."""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from toolgate.api.deps import deny, require_agent, require_owner
from toolgate.core import identities

router = APIRouter()


class Toolkit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scopes: list[str] = Field(max_length=identities.MAX_SCOPES)


@router.put("/v2/agent/identities/{agent_id}")
def define_identity(agent_id: str, payload: Toolkit, agent: dict = Depends(require_agent)):
    """Set one agent's toolkit under this key. It only narrows: the key stays the ceiling."""
    try:
        return identities.define(agent, agent_id, payload.scopes)
    except identities.IdentityError as exc:
        deny("INVALID_IDENTITY", str(exc), 422)


@router.get("/v2/agent/identities")
def list_identities(agent: dict = Depends(require_agent)):
    if agent.get("identity"):
        deny("INVALID_IDENTITY", "Only the key itself lists its agents.", 403)
    return {"identities": identities.listing(agent)}


@router.post("/v2/owner/agents/{agent_id}/keys", dependencies=[Depends(require_owner)])
def mint_agent_key(agent_id: str, agent: dict = Depends(require_agent)):
    """A key bound to one agent of the chat's key, for that agent's CLI or MCP. Shown once."""
    try:
        record, raw = identities.mint(agent, agent_id)
    except identities.IdentityError as exc:
        deny("INVALID_IDENTITY", str(exc), 422)
    return JSONResponse({"key": raw, "record": record}, headers={"Cache-Control": "no-store"})


@router.get("/v2/owner/agents/{agent_id}/keys", dependencies=[Depends(require_owner)])
def agent_keys(agent_id: str, agent: dict = Depends(require_agent)):
    return JSONResponse(
        {"keys": identities.bound_keys(agent, agent_id)}, headers={"Cache-Control": "no-store"}
    )


@router.post("/v2/owner/agent-keys/{key_id}/revoke", dependencies=[Depends(require_owner)])
def revoke_agent_key(key_id: str, agent: dict = Depends(require_agent)):
    if not identities.revoke_bound(agent, key_id):
        deny("KEY_UNAVAILABLE", "No such key for this chat.", 404)
    return {"revoked": True, "id": key_id}
