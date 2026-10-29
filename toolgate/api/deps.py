"""Caller authentication dependencies and the structured denial shared by every route module."""

import secrets

from fastapi import Header, HTTPException

from toolgate.core import control_plane, identities, owner_channel, vault


def require_admin(x_toolgate_key: str | None = Header(None, alias="X-ToolGate-Key")) -> str:
    key = vault.get_control_key("TOOLGATE_ADMIN_KEY")
    if not key or not x_toolgate_key or not secrets.compare_digest(key, x_toolgate_key):
        raise HTTPException(401, "requires TOOLGATE_ADMIN_KEY")
    return "admin"


def require_agent(
    x_toolgate_execution_key: str | None = Header(None, alias="X-ToolGate-Execution-Key"),
    x_toolgate_agent: str | None = Header(None, alias="X-ToolGate-Agent"),
) -> dict:
    agent = control_plane.authenticate_agent(x_toolgate_execution_key)
    if not agent:
        raise HTTPException(401, "missing or invalid X-ToolGate-Execution-Key")
    # The agent this key acts as, capped by the key; a bound key is always its own agent.
    effective = identities.resolve(agent, x_toolgate_agent)
    if effective is None:
        raise HTTPException(403, "This key cannot act as that agent")
    return effective


def require_owner(x_toolgate_owner_key: str | None = Header(None, alias="X-ToolGate-Owner-Key")):
    owner_channel.authenticate(x_toolgate_owner_key)


def require_owner_or_agent(
    x_toolgate_owner_key: str | None = Header(None, alias="X-ToolGate-Owner-Key"),
    x_toolgate_execution_key: str | None = Header(None, alias="X-ToolGate-Execution-Key"),
    x_toolgate_agent: str | None = Header(None, alias="X-ToolGate-Agent"),
) -> None:
    """For read-only calls: the owner key when it is sent, otherwise an execution key."""
    if x_toolgate_owner_key is not None:
        owner_channel.authenticate(x_toolgate_owner_key)
    else:
        require_agent(x_toolgate_execution_key, x_toolgate_agent)


def deny(code: str, message: str, status: int = 403, next_action: str = ""):
    raise HTTPException(status, {"code": code, "message": message, "next_action": next_action})
