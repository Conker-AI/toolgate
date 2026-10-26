"""Who may decide access for the owner, and the floor no decision crosses.

Pi resolves each action's level from the owner's own settings (chat, agent, tool default) and may
tell ToolGate "run" or "ask". ToolGate accepts "run" only from an execution key the owner marked
as a policy delegate, and never for a tool on the floor: one he marked sensitive, or the system
controls that already carry their own exact review. "Ask" (tightening) is accepted from any key.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from toolgate.core import control_plane

# Fixed executors with their own exact owner review; never decided by a delegate.
FLOOR_EXECUTIONS = frozenset({"port_control", "container_control", "process_control"})
DECIDERS = ("tool_default", "agent", "chat", "ai_reviewer", "owner_request")


class Decision(BaseModel):
    """A delegate's resolution of the owner's policy for one exact action."""

    model_config = ConfigDict(extra="forbid")
    outcome: Literal["run", "ask"]
    decided_by: Literal["tool_default", "agent", "chat", "ai_reviewer", "owner_request"]
    reason: str = Field(default="", max_length=500)


class Sensitivity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sensitive: bool


class Delegation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


def _tables(conn) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS v2_access_floor ("
        "tool_id TEXT PRIMARY KEY, updated_at TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS v2_policy_delegates ("
        "key_id TEXT PRIMARY KEY, enabled_at TEXT NOT NULL)"
    )


def sensitive_ids() -> set[str]:
    with control_plane._conn() as conn:
        _tables(conn)
        return {row["tool_id"] for row in conn.execute("SELECT tool_id FROM v2_access_floor")}


def on_floor(tool: dict, sensitive: set[str] | None = None) -> bool:
    marked = sensitive_ids() if sensitive is None else sensitive
    return tool.get("id") in marked or tool.get("execution", {}).get("type") in FLOOR_EXECUTIONS


def set_sensitive(tool_id: str, sensitive: bool, actor: str = "owner") -> bool:
    with control_plane._conn() as conn:
        _tables(conn)
        if sensitive:
            conn.execute(
                "INSERT OR IGNORE INTO v2_access_floor VALUES (?, ?)",
                (tool_id, control_plane._now()),
            )
        else:
            conn.execute("DELETE FROM v2_access_floor WHERE tool_id=?", (tool_id,))
    control_plane.event(
        "tool_sensitivity_changed", "warning", "tool", tool_id, actor, {"sensitive": sensitive}
    )
    return sensitive


def _key(agent: dict) -> str:
    # Delegation belongs to the key, whichever agent identity it acts as.
    return agent.get("key_id") or agent["id"].partition("#")[0]


def is_delegate(agent: dict) -> bool:
    with control_plane._conn() as conn:
        _tables(conn)
        row = conn.execute(
            "SELECT 1 FROM v2_policy_delegates WHERE key_id=?", (_key(agent),)
        ).fetchone()
    return row is not None


def set_delegate(agent: dict, enabled: bool, actor: str = "owner") -> bool:
    with control_plane._conn() as conn:
        _tables(conn)
        if enabled:
            conn.execute(
                "INSERT OR IGNORE INTO v2_policy_delegates VALUES (?, ?)",
                (_key(agent), control_plane._now()),
            )
        else:
            conn.execute("DELETE FROM v2_policy_delegates WHERE key_id=?", (_key(agent),))
    control_plane.event(
        "policy_delegate_changed", "warning", "agent_key", _key(agent), actor, {"enabled": enabled}
    )
    return enabled


def resolve(tool: dict, authorization: str, decision: Decision | None, agent: dict) -> str:
    """The authorization this exact invocation runs under. Blocked stays blocked; a floor tool
    keeps its own; a delegate's "run" makes it auto; anyone's "ask" makes it owner confirmation."""
    if decision is None or authorization == "blocked":
        return authorization
    if decision.outcome == "ask":
        return "owner_confirmation"
    if on_floor(tool) or not is_delegate(agent):
        return authorization
    return "auto"
