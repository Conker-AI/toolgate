"""Typed v2 control-plane storage and enforcement helpers.

This module deliberately keeps ToolGate's owner data in SQLite and exposes a
small declarative model.  Generated executors may consume these definitions,
but agents never get write access to them directly.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import uuid
from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime
from typing import Literal, overload

from toolgate.core import schema_ledger

# Definitions and the event log live beside this module, and call back into it by module (cp.X),
# so a patch on control_plane still reaches them. Callers keep importing every name from here.
from toolgate.core.control_plane_definitions import (  # noqa: F401
    create_automation,
    create_service,
    create_tool,
    create_verification_method,
    update_automation,
    update_service,
    update_tool,
    update_verification_method,
)
from toolgate.core.control_plane_events import (  # noqa: F401
    event,
    event_count_since,
    events,
    latest_event_at,
)

# Stateless rules and the schema live beside this module; callers keep importing them from here.
from toolgate.core.control_plane_rules import (  # noqa: F401
    DEFAULT_USAGE_LIMITS,
    is_scoped,
    validate_inputs,
    with_default_limits,
)
from toolgate.core.control_plane_schema import SCHEMA  # noqa: F401
from toolgate.core.paths import DB_PATH


def _now() -> str:
    return datetime.now(UTC).isoformat()


@contextmanager
def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # The schema runs once per database (its ledger), not on every connection.
    schema_ledger.ensure(conn)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def purge_legacy_state() -> None:
    """Remove pre-v2 runtime tables from a reused local database.

    ToolGate v2 is intentionally a fresh control plane; old script approvals and
    audit data must not survive as hidden operational state.
    """
    with _conn() as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        for row in rows:
            name = row["name"]
            if name.startswith("v2_") or name.startswith("sqlite_"):
                continue
            conn.execute(f'DROP TABLE IF EXISTS "{name}"')


def _row(row: sqlite3.Row) -> dict:
    value = json.loads(row["body"])
    value.setdefault("id", row["id"])
    value.setdefault("created_at", row["created_at"])
    value.setdefault("updated_at", row["updated_at"])
    return value


class DefinitionConflict(ValueError):
    """An owner edited an older definition; no write has been applied."""

    def __init__(self, current_version: int | None):
        super().__init__("Definition changed. Reload it before saving.")
        self.current_version = current_version


@overload
def _put(
    kind: str,
    obj_id: str,
    body: dict,
    *,
    expected_version: int | None = None,
    require_existing: Literal[False] = False,
    require_absent: bool = False,
    connection=None,
) -> dict: ...
@overload
def _put(
    kind: str,
    obj_id: str,
    body: dict,
    *,
    expected_version: int | None = None,
    require_existing: bool,
    require_absent: bool = False,
    connection=None,
) -> dict | None: ...
def _put(
    kind: str,
    obj_id: str,
    body: dict,
    *,
    expected_version: int | None = None,
    require_existing: bool = False,
    require_absent: bool = False,
    connection=None,
) -> dict | None:
    # None only when require_existing finds no row; the overloads say so to the type checker.
    now = _now()
    body = {**body, "id": obj_id}
    with nullcontext(connection) if connection is not None else _conn() as conn:
        definition = kind in {"tool", "automation"}
        if connection is None and (kind == "request" or definition):
            conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT * FROM v2_objects WHERE kind=? AND id=?", (kind, obj_id)
        ).fetchone()
        if require_existing and not existing:
            return None
        if require_absent and existing:
            # Replacing needs the version the caller saw; a blind upsert could undo an edit.
            raise DefinitionConflict(_row(existing).get("version", 1))
        if definition:
            if expected_version is not None and (
                type(expected_version) is not int or expected_version < 1
            ):
                raise ValueError("expected_version must be a positive integer")
            current = _row(existing).get("version", 1) if existing else None
            initial = body.get("version", 1)
            if current is not None and (type(current) is not int or current < 1):
                raise ValueError("Stored definition version is invalid")
            if expected_version is not None and expected_version != current:
                raise DefinitionConflict(current)
            if current is None and (type(initial) is not int or initial < 1):
                raise ValueError("Initial definition version must be a positive integer")
            # Legacy callers may omit the precondition, but can never allocate/reset a
            # stored version. Keep create/upsert compatibility under the same lock.
            retained = (
                conn.execute(
                    "SELECT MAX(version) FROM v2_definition_versions WHERE kind=? AND id=?",
                    (kind, obj_id),
                ).fetchone()[0]
                or 0
            )
            body["version"] = max(current or 0, retained) + 1 if existing or retained else initial
            if existing:
                retain_definition(conn, kind, _row(existing))
        if kind == "request" and existing:
            raise ValueError(
                "Requests cannot be replaced; use the serialized decision or consumption transition"
            )
        created = existing["created_at"] if existing else now
        conn.execute(
            "INSERT INTO v2_objects(kind,id,body,created_at,updated_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body,updated_at=excluded.updated_at",
            (kind, obj_id, json.dumps(body), created, now),
        )
        if definition:
            retain_definition(conn, kind, {**body, "created_at": created, "updated_at": now})
    return {**body, "created_at": created, "updated_at": now}


def retain_definition(conn, kind: str, definition: dict) -> None:
    """Retain only a previously unseen revision; old databases are adopted lazily."""
    key = (kind, definition["id"], definition.get("version", 1))
    if not conn.execute(
        "SELECT 1 FROM v2_definition_versions WHERE kind=? AND id=? AND version=?", key
    ).fetchone():
        conn.execute(
            "INSERT INTO v2_definition_versions VALUES(?,?,?,?)", (*key, json.dumps(definition))
        )


@overload
def _change(kind: str, obj_id: str, change, default: dict) -> dict: ...
@overload
def _change(kind: str, obj_id: str, change, default: None = None) -> dict | None: ...
def _change(kind: str, obj_id: str, change, default: dict | None = None) -> dict | None:
    """Read, change and write one object under one write lock, so two writers never undo each other."""
    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM v2_objects WHERE kind=? AND id=?", (kind, obj_id)
        ).fetchone()
        current = _row(row) if row else (dict(default) if default is not None else None)
        if current is None:
            return None
        return _put(kind, obj_id, change(current), connection=conn)


def get(kind: str, obj_id: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM v2_objects WHERE kind=? AND id=?", (kind, obj_id)
        ).fetchone()
    return _row(row) if row else None


def list_objects(kind: str) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM v2_objects WHERE kind=? ORDER BY updated_at DESC", (kind,)
        ).fetchall()
    return [_row(row) for row in rows]


def remove(kind: str, obj_id: str) -> bool:
    with _conn() as conn:
        if kind in {"tool", "automation"}:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM v2_objects WHERE kind=? AND id=?", (kind, obj_id)
            ).fetchone()
            if row:
                retain_definition(conn, kind, _row(row))
        return (
            conn.execute("DELETE FROM v2_objects WHERE kind=? AND id=?", (kind, obj_id)).rowcount
            > 0
        )


_SETTINGS = {"id": "control-plane", "lockdown": False}


def settings() -> dict:
    return get("settings", "control-plane") or dict(_SETTINGS)


def set_lockdown(enabled: bool, actor: str, reason: str = "") -> dict:
    state = _change(
        "settings",
        "control-plane",
        lambda state: {**state, "lockdown": enabled, "reason": reason, "changed_by": actor},
        _SETTINGS,
    )
    event(
        "lockdown_enabled" if enabled else "lockdown_disabled",
        "critical" if enabled else "info",
        "settings",
        "control-plane",
        actor,
        {"reason": reason},
    )
    return state


def update_settings(changes: dict, actor: str) -> dict:
    protected = {"id", "created_at", "updated_at", "lockdown", "changed_by", "reason"}
    allowed = {key: value for key, value in changes.items() if key not in protected}
    state = _change("settings", "control-plane", lambda state: {**state, **allowed}, _SETTINGS)
    event("settings_updated", "info", "settings", "control-plane", actor, {"keys": sorted(changes)})
    return state


def issue_agent_key(name: str, scopes: list[str]) -> tuple[dict, str]:
    raw = "tgx_" + secrets.token_urlsafe(32)
    record = {
        "id": str(uuid.uuid4()),
        "name": name,
        "key_hash": hashlib.sha256(raw.encode()).hexdigest(),
        "scopes": scopes or [],
        "status": "active",
        "created_at": _now(),
    }
    with _conn() as conn:
        conn.execute(
            "INSERT INTO v2_agent_keys(id,name,key_hash,scopes,status,created_at) VALUES(?,?,?,?,?,?)",
            (
                record["id"],
                record["name"],
                record["key_hash"],
                json.dumps(record["scopes"]),
                record["status"],
                record["created_at"],
            ),
        )
    event(
        "agent_key_created",
        "info",
        "agent_key",
        record["id"],
        "admin",
        {"name": name, "scopes": scopes},
    )
    return public_agent_key(record), raw


def ensure_bootstrap_agent_key(raw: str, scopes: list[str], name: str = "AgentGate Pi") -> dict:
    """Seed a missing deployment key; never reconcile an existing key to configuration."""
    if not raw.startswith("tgx_") or len(raw) < 20:
        raise ValueError(
            "TOOLGATE_BOOTSTRAP_EXECUTION_KEY must start with tgx_ and be at least 20 characters"
        )
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    normalized_scopes = scopes or []
    created_record: dict | None = None
    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT * FROM v2_agent_keys WHERE key_hash=?", (hashed,)
        ).fetchone()
        if existing:
            # Deployment configuration seeds authority; the owner's persisted decisions govern it thereafter.
            return public_agent_key(existing)
        record = {
            "id": str(uuid.uuid4()),
            "name": name,
            "key_hash": hashed,
            "scopes": normalized_scopes,
            "status": "active",
            "created_at": _now(),
        }
        conn.execute(
            "INSERT INTO v2_agent_keys(id,name,key_hash,scopes,status,created_at) VALUES(?,?,?,?,?,?)",
            (
                record["id"],
                record["name"],
                record["key_hash"],
                json.dumps(record["scopes"]),
                record["status"],
                record["created_at"],
            ),
        )
        created_record = record
        result = public_agent_key(record)
    if created_record:
        event(
            "agent_key_bootstrapped",
            "info",
            "agent_key",
            created_record["id"],
            "deployment",
            {"name": name, "scopes": normalized_scopes},
        )
    return result


def public_agent_key(record: dict | sqlite3.Row) -> dict:
    value = dict(record)
    value.pop("key_hash", None)
    if isinstance(value.get("scopes"), str):
        value["scopes"] = json.loads(value["scopes"])
    return value


def list_agent_keys() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute("SELECT * FROM v2_agent_keys ORDER BY created_at DESC").fetchall()
    return [public_agent_key(row) for row in rows]


def update_agent_key_scopes(key_id: str, scopes: list[str], actor: str = "admin") -> dict | None:
    normalized = [str(scope).strip() for scope in scopes if str(scope).strip()]
    with _conn() as conn:
        row = conn.execute("SELECT * FROM v2_agent_keys WHERE id=?", (key_id,)).fetchone()
        if not row:
            return None
        conn.execute(
            "UPDATE v2_agent_keys SET scopes=? WHERE id=?",
            (json.dumps(normalized), key_id),
        )
        updated = conn.execute("SELECT * FROM v2_agent_keys WHERE id=?", (key_id,)).fetchone()
    event("agent_key_scopes_updated", "info", "agent_key", key_id, actor, {"scopes": normalized})
    return public_agent_key(updated)


def authenticate_agent(raw: str | None) -> dict | None:
    if not raw:
        return None
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM v2_agent_keys WHERE key_hash=? AND status='active'", (hashed,)
        ).fetchone()
        if row:
            conn.execute("UPDATE v2_agent_keys SET last_used_at=? WHERE id=?", (_now(), row["id"]))
    return public_agent_key(row) if row else None


def revoke_agent_key(key_id: str, actor: str = "admin") -> bool:
    with _conn() as conn:
        changed = conn.execute(
            "UPDATE v2_agent_keys SET status='revoked' WHERE id=?", (key_id,)
        ).rowcount
    if changed:
        event("agent_key_revoked", "warning", "agent_key", key_id, actor)
    return bool(changed)
