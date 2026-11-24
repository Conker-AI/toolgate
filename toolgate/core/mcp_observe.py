"""Observe or Act outward: the owner's read class for one imported MCP tool (ADR-0006).

Act outward is what every imported tool is until he says otherwise: each call asks him, bound to
its exact arguments (approval level 2 or more). Observe runs without asking; scope, lockdown,
usage limits, spending, the action journal and the audit log apply exactly as before, only the
approval card is skipped. Observe is a class per tool, never a blanket switch:
- only the owner channel sets it, for the exact tool version he saw (`mcp_imports.set_class`);
  Pi's gateway asks his password for it, as for every other access grant (ADR-0010);
- only a tool whose names have the shape of a read (says_act_outward: a read verb and one part,
  or longer when the server's annotations say read-only) can be Observe, and only if those
  annotations, when it gives any, say read-only (hints_act);
- it binds the endpoint, credential reference, MCP tool name, schema hash, description and
  annotations he saw: when the server advertises anything else (at a call or at his discovery)
  the tool is back to Act outward until he confirms it again;
- built-in tools never have it, and anyone's "ask" or his sensitive mark still asks him.
The class is read from the stored tool at each call and again inside the dispatch transaction,
never from a pinned publication or the caller's copy.
"""

from __future__ import annotations

import re

from . import control_plane as cp
from .access_policy import Decision

# Re-exported: these names were defined here before the split (tests and callers use them).
from .mcp_observe_names import (  # noqa: F401
    ACT_OUTWARD_WORDS,
    ACTS,
    ACTS_AT_EDGES,
    CONNECTORS,
    HINTED_READ_VERBS,
    LEADS,
    READ_VERBS,
    names_act,
    says_act_outward,
)

OBSERVE, ACT_OUTWARD = "observe", "act_outward"
MCP_ID = re.compile(r"mcp[.][a-z0-9][a-z0-9.-]{1,74}")
# What the owner's Observe is bound to: the exact tool on the exact endpoint, as discovered, and
# `advert_hash` (mcp_http.advert_hash) over the description and annotations the server gave it.
BOUND = ("url", "secret_ref", "tool_name", "schema_hash")
ADVERT = re.compile(r"[a-f0-9]{64}")
# A call that found the server advertising another tool, schema, description or annotations.
CHANGED_ADVERT = frozenset({"schema_changed", "unsupported_schema", "advert_changed"})


def hints_act(annotations: object) -> bool:
    """Whether the server's own annotations keep a tool asking. Without annotations the name
    alone decides (by its short shape). With them, Observe needs readOnlyHint true and
    destructiveHint absent or false; anything else (none, a title only, a hint that is not a
    boolean) asks."""
    if annotations is None:
        return False
    if not isinstance(annotations, dict):
        return True
    return (
        annotations.get("readOnlyHint") is not True
        or annotations.get("destructiveHint", False) is not False
    )


def bound(execution: object) -> dict | None:
    """The part of an MCP execution the owner's Observe is bound to; None for anything else."""
    if not isinstance(execution, dict) or execution.get("type") != "mcp_http":
        return None
    return {key: execution.get(key) for key in BOUND}


def stated(tool: object) -> str:
    """The class a stored imported tool states: Observe only while the stored class still binds
    its own execution and the advert he confirmed, and all its names read (by the shape the
    server's read-only hint he confirmed allows, `read_only_hint`); otherwise Act outward."""
    if not isinstance(tool, dict) or not MCP_ID.fullmatch(str(tool.get("id"))):
        return ACT_OUTWARD
    execution, stored = bound(tool.get("execution")), tool.get("read_class")
    if (
        execution is None
        or not isinstance(stored, dict)
        or stored.get("class") != OBSERVE
        or {key: stored.get(key) for key in BOUND} != execution
        or not ADVERT.fullmatch(str(stored.get("advert_hash")))
        or names_act(
            (tool.get("id"), tool.get("name"), execution["tool_name"]),
            stored.get("read_only_hint") is True,
        )
    ):
        return ACT_OUTWARD
    return OBSERVE


def _marked_sensitive(conn, tool_id: str) -> bool:
    # The owner's sensitive mark (core/access_policy.py) keeps a tool asking whatever its class.
    if not conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='v2_access_floor'"
    ).fetchone():
        return False
    return bool(
        conn.execute("SELECT 1 FROM v2_access_floor WHERE tool_id=?", (tool_id,)).fetchone()
    )


def observes(conn, tool: dict) -> bool:
    """The guard: whether this definition of a tool runs as Observe now. The stored tool must be
    active, ask the owner by its own authorization and state Observe; the definition being run
    (perhaps a pinned publication) must have the same bound execution and names; and he must not
    have marked it sensitive."""
    identity = tool.get("id")
    if not isinstance(identity, str):
        return False
    seen = bound(tool.get("execution"))
    row = conn.execute(
        "SELECT * FROM v2_objects WHERE kind='tool' AND id=?", (identity,)
    ).fetchone()
    current = cp._row(row) if row else None
    if (
        seen is None
        or current is None
        or current.get("status") != "active"
        or current.get("authorization") != "owner_confirmation"
        or stated(current) != OBSERVE
        or bound(current.get("execution")) != seen
        or says_act_outward(tool.get("name"), current["read_class"].get("read_only_hint") is True)
    ):
        return False
    return not _marked_sensitive(conn, identity)


def runs_unasked(conn, tool: dict, authorization: str, decision: Decision | None) -> bool:
    """Whether this exact call skips the owner's card: an Observe tool that would otherwise ask
    him, unless the caller said "ask" (an "ask" always tightens)."""
    if authorization != "owner_confirmation":
        return False
    if decision is not None and decision.outcome == "ask":
        return False
    return observes(conn, tool)


def advert(conn, tool_id: str) -> str | None:
    """The description and annotations hash he confirmed with Observe, for the call to check
    against what the server advertises right before it is sent; None when it is not Observe."""
    row = conn.execute("SELECT * FROM v2_objects WHERE kind='tool' AND id=?", (tool_id,)).fetchone()
    tool = cp._row(row) if row else None
    if tool is None or stated(tool) != OBSERVE:
        return None
    return tool["read_class"]["advert_hash"]


def save(conn, tool: dict, read_class: dict) -> dict:
    """Write the tool's next version with this class, inside the caller's write transaction."""
    body = {key: value for key, value in tool.items() if key not in {"created_at", "updated_at"}}
    body["read_class"] = read_class
    return cp._put("tool", tool["id"], body, expected_version=tool["version"], connection=conn)


def revert(tool_id: str, reason: str) -> bool:
    """Back to Act outward, because the server now advertises another tool, schema, description or
    annotations than the ones the owner confirmed. Only tightens; a tool that is not Observe is left as it is."""
    with cp._conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM v2_objects WHERE kind='tool' AND id=?", (tool_id,)
        ).fetchone()
        tool = cp._row(row) if row else None
        stored = tool.get("read_class") if tool else None
        if not tool or not isinstance(stored, dict) or stored.get("class") != OBSERVE:
            return False
        saved = save(conn, tool, {"class": ACT_OUTWARD})
        cp.event(
            "mcp_class_reverted",
            "warning",
            "tool",
            tool_id,
            "system",
            {"reason": reason, "version": saved["version"]},
            connection=conn,
        )
    return True


def notice(url: str, secret_ref: str | None, discovered: dict) -> list[str]:
    """After a discovery of an endpoint: every Observe tool on it whose tool is gone, renamed,
    unsupported, or has another schema, description or annotations now goes back to Act outward."""
    advertised = {
        tool.get("name"): (tool.get("schemaHash"), tool.get("advertHash"))
        for tool in discovered.get("tools", [])
        if isinstance(tool, dict)
    }
    unsupported = {
        tool.get("name")
        for tool in discovered.get("unsupportedTools", [])
        if isinstance(tool, dict)
    }
    with cp._conn() as conn:
        rows = conn.execute(
            "SELECT * FROM v2_objects WHERE kind='tool' AND id LIKE 'mcp.%' LIMIT 201"
        ).fetchall()
        tools = [cp._row(row) for row in rows]
    reverted = []
    for tool in tools:
        stored, execution = tool.get("read_class"), bound(tool.get("execution"))
        if (
            not isinstance(stored, dict)
            or stored.get("class") != OBSERVE
            or execution is None
            or execution["url"] != url
            or execution["secret_ref"] != secret_ref
        ):
            continue
        name = execution["tool_name"]
        schema, advert_seen = advertised.get(name, (None, None))
        if name in unsupported or schema != execution["schema_hash"]:
            reason = "schema_changed"
        elif advert_seen != stored.get("advert_hash"):
            reason = "advert_changed"
        else:
            continue
        if revert(tool["id"], reason):
            reverted.append(tool["id"])
    return reverted
