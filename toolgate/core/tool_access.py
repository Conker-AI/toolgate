"""Whether the chat's own key may use one tool: the owner's switch for any tool.

A grant adds `tool:<id>` to the presenting key's scopes; a revoke removes it. Grants belong to the
chat's own key, never to one agent or a key bound to an agent: agents only narrow what the key may
do. Changes are checked against the tool's exact digest so a stale screen cannot change a tool
that was edited in the meantime.
"""

from __future__ import annotations

import json
import re

from pydantic import BaseModel, ConfigDict, Field

from . import control_plane as cp
from . import publications
from .owner_channel import OwnerError

TOOL_ID = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"


class State(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    enabled: bool
    expected_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


def _not_found():
    return OwnerError("tool_not_found", "Tool not found.", 404)


def access(identity, agent, payload: State | None = None, *, accept=None, not_found=_not_found,
           event_prefix="tool_access"):
    """The key's access to one tool; with a payload, grant or revoke it first.

    `accept(tool)` narrows which tools this route serves (the MCP route keeps its own)."""
    if not re.fullmatch(TOOL_ID, identity):
        raise not_found()
    with cp._conn() as conn:
        conn.execute("BEGIN IMMEDIATE" if payload else "BEGIN")
        row = conn.execute(
            "SELECT * FROM v2_objects WHERE kind='tool' AND id=?", (identity,)
        ).fetchone()
        tool = cp._row(row) if row else None
        if not tool or (accept is not None and not accept(tool)):
            raise not_found()
        digest = publications.digest(tool)
        if agent.get("identity"):
            # Grants belong to the chat's own key, never to one agent or a bound key.
            raise OwnerError("execution_unavailable", "Grant access on the chat's own key.", 403)
        caller = conn.execute("SELECT * FROM v2_agent_keys WHERE id=?", (agent["id"],)).fetchone()
        if not caller or caller["status"] != "active":
            raise OwnerError(
                "execution_unavailable", "The execution credential is no longer active.", 403
            )
        caller = cp.public_agent_key(caller)
        scope = "tool:" + identity
        if payload:
            if payload.expected_digest != digest:
                raise OwnerError(
                    "definition_conflict", "The tool changed; reload before changing access.", 409
                )
            if payload.enabled and tool["status"] != "active":
                raise OwnerError("tool_disabled", "Enable the tool before granting access.", 409)
            updated = (
                list(dict.fromkeys([*caller["scopes"], scope]))
                if payload.enabled
                else [item for item in caller["scopes"] if item != scope]
            )
            if not payload.enabled and cp.is_scoped({**caller, "scopes": updated}, identity):
                raise OwnerError(
                    "broad_execution_grant", "A broader host-managed grant still covers this tool.",
                    409,
                )
            conn.execute(
                "UPDATE v2_agent_keys SET scopes=? WHERE id=?", (json.dumps(updated), caller["id"])
            )
            caller["scopes"] = updated
    if payload:
        cp.event(
            f"{event_prefix}_granted" if payload.enabled else f"{event_prefix}_revoked",
            "warning",
            "tool",
            identity,
            "owner",
            {"actor_id": caller["id"]},
        )
    return {
        "schemaVersion": 1,
        "toolId": identity,
        "actorId": caller["id"],
        "actorName": caller["name"],
        "enabled": cp.is_scoped(caller, identity),
        "requiredScope": scope,
        "digest": digest,
    }
