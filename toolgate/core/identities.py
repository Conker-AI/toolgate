"""Agent identities: each Conker agent's own view of ToolGate, scoped to its toolkit.

A key may present an agent (`X-ToolGate-Agent`). The agent's identity has its own scopes, always
capped by the presenting key's scopes, so defining identities only partitions what the key may
already do: it can never grant anything. The actor becomes `key_id#agent`, which the journal,
approvals and dispatch-time checks carry, so an identity holds until the action runs.

The owner can also mint a key bound to one agent (for its CLI or MCP use). A bound key always acts
as that agent, under the parent key's ceiling; it cannot present another agent or define
identities. An agent with no identity sees nothing, except the companion, which by default keeps
the full view of its key.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import uuid

from toolgate.core import control_plane

AGENT = re.compile(r"[a-z][a-z0-9_]{0,63}")
COMPANION = "companion"
MAX_SCOPES = 1000


class IdentityError(ValueError):
    pass


def _tables(conn) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS v2_agent_identities (key_id TEXT NOT NULL, agent_id TEXT NOT NULL,"
        " scopes TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (key_id, agent_id))"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS v2_key_bindings (key_id TEXT PRIMARY KEY,"
        " parent_key_id TEXT NOT NULL, agent_id TEXT NOT NULL, created_at TEXT NOT NULL)"
    )


def _scopes(conn, key_id: str, agent_id: str) -> list[str]:
    row = conn.execute(
        "SELECT scopes FROM v2_agent_identities WHERE key_id=? AND agent_id=?", (key_id, agent_id)
    ).fetchone()
    if row is not None:
        return json.loads(row["scopes"])
    return ["*"] if agent_id == COMPANION else []


def _active(conn, key_id: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM v2_agent_keys WHERE id=? AND status='active'", (key_id,)
    ).fetchone()
    return control_plane.public_agent_key(row) if row else None


def _effective(conn, key: dict, requested: str | None) -> dict | None:
    _tables(conn)
    binding = conn.execute(
        "SELECT parent_key_id, agent_id FROM v2_key_bindings WHERE key_id=?", (key["id"],)
    ).fetchone()
    if binding is not None:
        parent = _active(conn, binding["parent_key_id"])
        if parent is None or (requested is not None and requested != binding["agent_id"]):
            return None
        return {
            **key,
            "key_id": key["id"],
            "identity": binding["agent_id"],
            "scopes": _scopes(conn, parent["id"], binding["agent_id"]),
            "ceiling": parent["scopes"],
            "bound": True,
        }
    if requested is None:
        return {**key, "key_id": key["id"], "identity": None}
    if not AGENT.fullmatch(requested):
        return None
    return {
        **key,
        "id": f"{key['id']}#{requested}",
        "key_id": key["id"],
        "identity": requested,
        "scopes": _scopes(conn, key["id"], requested),
        "ceiling": key["scopes"],
    }


def resolve(key: dict, requested: str | None) -> dict | None:
    """The caller as ToolGate sees it: the key itself, or the agent it presents. None: refuse."""
    with control_plane._conn() as conn:
        return _effective(conn, key, requested)


def for_actor(conn, actor_id: str | None) -> dict | None:
    """Recompute the actor from durable state at dispatch time; None when the key is gone."""
    if not actor_id:
        return None
    key_id, _, agent = actor_id.partition("#")
    key = _active(conn, key_id)
    return _effective(conn, key, agent or None) if key else None


def agent_for(actor_id: str | None) -> str | None:
    """The agent an action runs as, for per-agent resources such as its sandbox workspace: its
    identity, or the companion for a key acting as itself. None when the key is gone."""
    if not actor_id:
        return COMPANION
    with control_plane._conn() as conn:
        actor = for_actor(conn, actor_id)
    if actor is None:
        return None
    return actor.get("identity") or COMPANION


def define(key: dict, agent_id: str, scopes: list[str]) -> dict:
    """Set one agent's toolkit under the presenting key. Only narrows: the key stays the ceiling."""
    if key.get("bound") or key.get("identity"):
        raise IdentityError("Only the key itself defines its agents.")
    if not AGENT.fullmatch(agent_id):
        raise IdentityError("Agent ids are lowercase letters, digits and underscores.")
    cleaned = sorted({str(scope).strip() for scope in scopes if str(scope).strip()})
    if len(cleaned) > MAX_SCOPES or any(len(scope) > 200 for scope in cleaned):
        raise IdentityError("Too many or too long scopes.")
    with control_plane._conn() as conn:
        _tables(conn)
        conn.execute(
            "INSERT INTO v2_agent_identities VALUES (?,?,?,?) ON CONFLICT(key_id, agent_id) "
            "DO UPDATE SET scopes=excluded.scopes, updated_at=excluded.updated_at",
            (key["id"], agent_id, json.dumps(cleaned), control_plane._now()),
        )
    control_plane.event(
        "agent_identity_defined",
        "info",
        "agent_key",
        key["id"],
        key["name"],
        {"agent": agent_id, "scopes": cleaned},
    )
    return {"agent": agent_id, "scopes": cleaned}


def listing(key: dict) -> list[dict]:
    with control_plane._conn() as conn:
        _tables(conn)
        rows = conn.execute(
            "SELECT agent_id, scopes, updated_at FROM v2_agent_identities WHERE key_id=? "
            "ORDER BY agent_id",
            (key["id"],),
        ).fetchall()
    return [
        {
            "agent": row["agent_id"],
            "scopes": json.loads(row["scopes"]),
            "updatedAt": row["updated_at"],
        }
        for row in rows
    ]


def mint(parent: dict, agent_id: str, actor: str = "owner") -> tuple[dict, str]:
    """A key bound to one agent of the presenting key, for that agent's CLI or MCP use."""
    if parent.get("bound") or parent.get("identity"):
        raise IdentityError("Mint agent keys from the chat's own key.")
    if not AGENT.fullmatch(agent_id):
        raise IdentityError("Agent ids are lowercase letters, digits and underscores.")
    raw = "tgx_" + secrets.token_urlsafe(32)
    record = {
        "id": str(uuid.uuid4()),
        "name": f"{agent_id} (CLI/MCP)",
        "key_hash": hashlib.sha256(raw.encode()).hexdigest(),
        "scopes": [],
        "status": "active",
        "created_at": control_plane._now(),
    }
    with control_plane._conn() as conn:
        _tables(conn)
        conn.execute(
            "INSERT INTO v2_agent_keys(id,name,key_hash,scopes,status,created_at) VALUES(?,?,?,?,?,?)",
            (
                record["id"],
                record["name"],
                record["key_hash"],
                "[]",
                "active",
                record["created_at"],
            ),
        )
        conn.execute(
            "INSERT INTO v2_key_bindings VALUES (?,?,?,?)",
            (record["id"], parent["id"], agent_id, record["created_at"]),
        )
    control_plane.event(
        "agent_key_minted",
        "warning",
        "agent_key",
        record["id"],
        actor,
        {"agent": agent_id, "parent": parent["id"]},
    )
    return control_plane.public_agent_key(record), raw


def bound_keys(parent: dict, agent_id: str) -> list[dict]:
    with control_plane._conn() as conn:
        _tables(conn)
        rows = conn.execute(
            "SELECT k.* FROM v2_agent_keys k JOIN v2_key_bindings b ON b.key_id=k.id "
            "WHERE b.parent_key_id=? AND b.agent_id=? ORDER BY k.created_at DESC",
            (parent["id"], agent_id),
        ).fetchall()
    return [control_plane.public_agent_key(row) for row in rows]


def revoke_bound(parent: dict, key_id: str, actor: str = "owner") -> bool:
    with control_plane._conn() as conn:
        _tables(conn)
        owned = conn.execute(
            "SELECT 1 FROM v2_key_bindings WHERE key_id=? AND parent_key_id=?",
            (key_id, parent["id"]),
        ).fetchone()
    return bool(owned) and control_plane.revoke_agent_key(key_id, actor)
