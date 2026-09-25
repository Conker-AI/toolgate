"""Typed v2 control-plane storage and enforcement helpers.

This module deliberately keeps ToolGate's owner data in SQLite and exposes a
small declarative model.  Generated executors may consume these definitions,
but agents never get write access to them directly.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import uuid
from contextlib import contextmanager, nullcontext
from datetime import UTC, datetime, timedelta

from toolgate.core.paths import DB_PATH


def _now() -> str:
    return datetime.now(UTC).isoformat()


@contextmanager
def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS v2_objects (
      kind TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      PRIMARY KEY (kind, id)
    );
    CREATE TABLE IF NOT EXISTS v2_agent_keys (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE,
      scopes TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
      last_used_at TEXT
    );
    CREATE TABLE IF NOT EXISTS v2_verification_origins (
      request_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS v2_events (
      id TEXT PRIMARY KEY, event_type TEXT NOT NULL, severity TEXT NOT NULL,
      subject_type TEXT, subject_id TEXT, actor TEXT, payload TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS v2_definition_versions (
      kind TEXT NOT NULL, id TEXT NOT NULL, version INTEGER NOT NULL,
      body TEXT NOT NULL, PRIMARY KEY(kind,id,version)
    );
    CREATE TABLE IF NOT EXISTS v2_publications (
      kind TEXT NOT NULL, id TEXT NOT NULL, version INTEGER NOT NULL,
      body TEXT NOT NULL, PRIMARY KEY(kind,id,version)
    );
    CREATE TRIGGER IF NOT EXISTS v2_versions_no_update BEFORE UPDATE ON v2_definition_versions
    BEGIN SELECT RAISE(ABORT, 'definition history is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS v2_versions_no_delete BEFORE DELETE ON v2_definition_versions
    BEGIN SELECT RAISE(ABORT, 'definition history is permanent'); END;
    CREATE TRIGGER IF NOT EXISTS v2_versions_no_replace BEFORE INSERT ON v2_definition_versions
    WHEN EXISTS(SELECT 1 FROM v2_definition_versions WHERE kind=NEW.kind AND id=NEW.id AND version=NEW.version)
    BEGIN SELECT RAISE(ABORT, 'definition revision already exists'); END;
    CREATE TRIGGER IF NOT EXISTS v2_publications_no_update BEFORE UPDATE ON v2_publications
    BEGIN SELECT RAISE(ABORT, 'publication is immutable'); END;
    CREATE TRIGGER IF NOT EXISTS v2_publications_no_delete BEFORE DELETE ON v2_publications
    BEGIN SELECT RAISE(ABORT, 'publication is permanent'); END;
    CREATE TRIGGER IF NOT EXISTS v2_publications_no_replace BEFORE INSERT ON v2_publications
    WHEN EXISTS(SELECT 1 FROM v2_publications WHERE kind=NEW.kind AND id=NEW.id AND version=NEW.version)
    BEGIN SELECT RAISE(ABORT, 'publication already exists'); END;
    """)
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


def _put(kind: str, obj_id: str, body: dict, *, expected_version: int | None = None,
         require_existing: bool = False, connection=None) -> dict | None:
    now = _now()
    body = {**body, "id": obj_id}
    with (nullcontext(connection) if connection is not None else _conn()) as conn:
        definition = kind in {"tool", "automation"}
        if connection is None and (kind == "request" or definition):
            conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute("SELECT * FROM v2_objects WHERE kind=? AND id=?", (kind, obj_id)).fetchone()
        if require_existing and not existing:
            return None
        if definition:
            if expected_version is not None and (type(expected_version) is not int or expected_version < 1):
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
            retained = conn.execute("SELECT MAX(version) FROM v2_definition_versions WHERE kind=? AND id=?",
                                    (kind, obj_id)).fetchone()[0] or 0
            body["version"] = max(current or 0, retained) + 1 if existing or retained else initial
            if existing:
                retain_definition(conn, kind, _row(existing))
        if kind == "request" and existing:
            raise ValueError("Requests cannot be replaced; use the serialized decision or consumption transition")
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
    if not conn.execute("SELECT 1 FROM v2_definition_versions WHERE kind=? AND id=? AND version=?", key).fetchone():
        conn.execute("INSERT INTO v2_definition_versions VALUES(?,?,?,?)", (*key, json.dumps(definition)))


def get(kind: str, obj_id: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM v2_objects WHERE kind=? AND id=?", (kind, obj_id)).fetchone()
    return _row(row) if row else None


def list_objects(kind: str) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute("SELECT * FROM v2_objects WHERE kind=? ORDER BY updated_at DESC", (kind,)).fetchall()
    return [_row(row) for row in rows]


def remove(kind: str, obj_id: str) -> bool:
    with _conn() as conn:
        if kind in {"tool", "automation"}:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM v2_objects WHERE kind=? AND id=?", (kind, obj_id)).fetchone()
            if row:
                retain_definition(conn, kind, _row(row))
        return conn.execute("DELETE FROM v2_objects WHERE kind=? AND id=?", (kind, obj_id)).rowcount > 0


def cache_research_result(result: dict, expires_at: str) -> dict:
    """Store a short-lived search result for provenance-bound page fetching."""
    result_id = "rr_" + secrets.token_urlsafe(18)
    return _put("research_result", result_id, {
        "title": result.get("title", ""),
        "url": result["url"],
        "source": result.get("source", "general"),
        "published_at": result.get("published_at"),
        "document": str(result.get("document", ""))[:20000] if result.get("document") else None,
        "expires_at": expires_at,
    })


def get_research_result(result_id: str) -> dict | None:
    if not isinstance(result_id, str) or not re.fullmatch(r"rr_[A-Za-z0-9_-]{20,40}", result_id):
        return None
    return get("research_result", result_id)


def purge_expired_research_results(now: datetime | None = None) -> int:
    cutoff = now or datetime.now(UTC)
    removed = 0
    for record in list_objects("research_result"):
        try:
            expired = datetime.fromisoformat(record["expires_at"]) <= cutoff
        except (KeyError, TypeError, ValueError):
            expired = True
        if expired and remove("research_result", record["id"]):
            removed += 1
    return removed


def event(event_type: str, severity: str = "info", subject_type: str | None = None,
          subject_id: str | None = None, actor: str | None = None, payload: dict | None = None) -> dict:
    record = {"id": str(uuid.uuid4()), "event_type": event_type, "severity": severity,
              "subject_type": subject_type, "subject_id": subject_id, "actor": actor,
              "payload": payload or {}, "created_at": _now()}
    with _conn() as conn:
        conn.execute("INSERT INTO v2_events VALUES(?,?,?,?,?,?,?,?)", (
            record["id"], record["event_type"], record["severity"], record["subject_type"],
            record["subject_id"], record["actor"], json.dumps(record["payload"]), record["created_at"],
        ))
    return record


def events(limit: int = 100, event_type: str | None = None) -> list[dict]:
    query, params = "SELECT * FROM v2_events", []
    if event_type:
        query += " WHERE event_type=?"
        params.append(event_type)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(min(max(limit, 1), 500))
    with _conn() as conn:
        rows = conn.execute(query, params).fetchall()
    return [{**dict(row), "payload": json.loads(row["payload"])} for row in rows]


def event_count_since(event_type: str, subject_type: str, subject_id: str, seconds: int) -> int:
    cutoff = (datetime.now(UTC) - timedelta(seconds=max(seconds, 0))).isoformat()
    with _conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS count FROM v2_events "
            "WHERE event_type=? AND subject_type=? AND subject_id=? AND created_at>=?",
            (event_type, subject_type, subject_id, cutoff),
        ).fetchone()
    return int(row["count"])


def latest_event_at(event_type: str, subject_type: str, subject_id: str) -> datetime | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT created_at FROM v2_events WHERE event_type=? AND subject_type=? AND subject_id=? "
            "ORDER BY created_at DESC LIMIT 1",
            (event_type, subject_type, subject_id),
        ).fetchone()
    return datetime.fromisoformat(row["created_at"]) if row else None


def settings() -> dict:
    return get("settings", "control-plane") or {"id": "control-plane", "lockdown": False}


def set_lockdown(enabled: bool, actor: str, reason: str = "") -> dict:
    state = {**settings(), "lockdown": enabled, "reason": reason, "changed_by": actor}
    state = _put("settings", "control-plane", state)
    event("lockdown_enabled" if enabled else "lockdown_disabled", "critical" if enabled else "info",
          "settings", "control-plane", actor, {"reason": reason})
    return state


def update_settings(changes: dict, actor: str) -> dict:
    protected = {"id", "created_at", "updated_at", "lockdown", "changed_by", "reason"}
    state = settings()
    state.update({key: value for key, value in changes.items() if key not in protected})
    state = _put("settings", "control-plane", state)
    event("settings_updated", "info", "settings", "control-plane", actor, {"keys": sorted(changes)})
    return state


def issue_agent_key(name: str, scopes: list[str]) -> tuple[dict, str]:
    raw = "tgx_" + secrets.token_urlsafe(32)
    record = {"id": str(uuid.uuid4()), "name": name, "key_hash": hashlib.sha256(raw.encode()).hexdigest(),
              "scopes": scopes or [], "status": "active", "created_at": _now()}
    with _conn() as conn:
        conn.execute("INSERT INTO v2_agent_keys(id,name,key_hash,scopes,status,created_at) VALUES(?,?,?,?,?,?)",
                     (record["id"], record["name"], record["key_hash"], json.dumps(record["scopes"]),
                      record["status"], record["created_at"]))
    event("agent_key_created", "info", "agent_key", record["id"], "admin", {"name": name, "scopes": scopes})
    return public_agent_key(record), raw


def ensure_bootstrap_agent_key(raw: str, scopes: list[str], name: str = "AgentGate Pi") -> dict:
    """Seed a missing deployment key; never reconcile an existing key to configuration."""
    if not raw.startswith("tgx_") or len(raw) < 20:
        raise ValueError("TOOLGATE_BOOTSTRAP_EXECUTION_KEY must start with tgx_ and be at least 20 characters")
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    normalized_scopes = scopes or []
    created_record: dict | None = None
    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute("SELECT * FROM v2_agent_keys WHERE key_hash=?", (hashed,)).fetchone()
        if existing:
            # Deployment configuration seeds authority; the owner's persisted decisions govern it thereafter.
            return public_agent_key(existing)
        record = {
            "id": str(uuid.uuid4()), "name": name, "key_hash": hashed,
            "scopes": normalized_scopes, "status": "active", "created_at": _now(),
        }
        conn.execute(
            "INSERT INTO v2_agent_keys(id,name,key_hash,scopes,status,created_at) VALUES(?,?,?,?,?,?)",
            (record["id"], record["name"], record["key_hash"], json.dumps(record["scopes"]), record["status"], record["created_at"]),
        )
        created_record = record
        result = public_agent_key(record)
    if created_record:
        event("agent_key_bootstrapped", "info", "agent_key", created_record["id"], "deployment", {"name": name, "scopes": normalized_scopes})
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
        row = conn.execute("SELECT * FROM v2_agent_keys WHERE key_hash=? AND status='active'", (hashed,)).fetchone()
        if row:
            conn.execute("UPDATE v2_agent_keys SET last_used_at=? WHERE id=?", (_now(), row["id"]))
    return public_agent_key(row) if row else None


def revoke_agent_key(key_id: str, actor: str = "admin") -> bool:
    with _conn() as conn:
        changed = conn.execute("UPDATE v2_agent_keys SET status='revoked' WHERE id=?", (key_id,)).rowcount
    if changed:
        event("agent_key_revoked", "warning", "agent_key", key_id, actor)
    return bool(changed)


def is_scoped(agent: dict, capability: str) -> bool:
    scopes = agent.get("scopes", [])
    if "*" in scopes or capability in scopes:
        return True
    if any(isinstance(scope, str) and scope.endswith("*") and capability.startswith(scope[:-1]) for scope in scopes):
        return True
    if capability.startswith("automation:"):
        return "automation:*" in scopes
    tool_id = capability.removeprefix("tool:")
    return (
        "tool:*" in scopes
        or f"tool:{tool_id}" in scopes
        or tool_id in scopes
        or any(isinstance(scope, str) and scope.endswith("*") and tool_id.startswith(scope[:-1]) for scope in scopes)
        or any(isinstance(scope, str) and scope.startswith("tool:") and scope.endswith("*") and tool_id.startswith(scope[5:-1]) for scope in scopes)
    )


def validate_inputs(schema: list[dict], args: dict) -> list[str]:
    errors: list[str] = []
    known = {field.get("name") for field in schema}
    for key in args:
        if key not in known:
            errors.append(f"'{key}' is not an allowed argument")
    for field in schema:
        name, value = field.get("name"), args.get(field.get("name"))
        if field.get("required") and name not in args:
            errors.append(f"'{name}' is required")
            continue
        if value is None:
            continue
        kind = field.get("type", "string")
        if kind == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
            errors.append(f"'{name}' must be an integer")
        elif kind == "number" and (isinstance(value, bool) or not isinstance(value, (int, float))):
            errors.append(f"'{name}' must be a number")
        elif kind == "boolean" and not isinstance(value, bool):
            errors.append(f"'{name}' must be true or false")
        elif kind == "string" and not isinstance(value, str):
            errors.append(f"'{name}' must be text")
        elif kind == "array" and not isinstance(value, list):
            errors.append(f"'{name}' must be an array")
        if isinstance(value, (int, float)):
            if field.get("minimum") is not None and value < field["minimum"]:
                errors.append(f"'{name}' must be at least {field['minimum']}")
            if field.get("maximum") is not None and value > field["maximum"]:
                errors.append(f"'{name}' must be at most {field['maximum']}")
        if isinstance(value, str):
            if field.get("min_length") is not None and len(value) < field["min_length"]:
                errors.append(f"'{name}' is too short")
            if field.get("max_length") is not None and len(value) > field["max_length"]:
                errors.append(f"'{name}' is too long")
            if field.get("pattern") and not re.search(field["pattern"], value):
                errors.append(f"'{name}' does not match the required format")
        if isinstance(value, list):
            if field.get("min_items") is not None and len(value) < field["min_items"]:
                errors.append(f"'{name}' must contain at least {field['min_items']} items")
            if field.get("max_items") is not None and len(value) > field["max_items"]:
                errors.append(f"'{name}' must contain at most {field['max_items']} items")
            if field.get("unique_items") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
                errors.append(f"'{name}' must not contain duplicate items")
            if field.get("item_type") == "string" and any(not isinstance(item, str) for item in value):
                errors.append(f"'{name}' items must be text")
            pattern = field.get("item_pattern")
            if pattern and any(not isinstance(item, str) or not re.fullmatch(pattern, item) for item in value):
                errors.append(f"'{name}' contains an invalid item")
        allowed = field.get("allowed_values") or []
        if allowed and value not in allowed:
            errors.append(f"'{name}' must be one of: {', '.join(map(str, allowed))}")
    return errors


def create_service(body: dict) -> dict:
    service_id = body.get("id") or body["name"].lower().replace(" ", "-")
    return _put("service", service_id, {"name": body["name"], "description": body.get("description", ""),
        "secret_refs": body.get("secret_refs", []), "health": body.get("health", "unknown"),
        "destination_policy": body.get("destination_policy", {}), "status": body.get("status", "active")})


def update_service(service_id: str, changes: dict) -> dict | None:
    service = get("service", service_id)
    if not service:
        return None
    service.update({key: value for key, value in changes.items()
                    if key not in {"id", "created_at", "updated_at"}})
    return _put("service", service_id, service)


def create_verification_method(body: dict) -> dict:
    method_id = body.get("id") or str(uuid.uuid4())
    return _put("verification_method", method_id, {
        "name": body.get("name", "Verification adapter"),
        "method_type": body.get("method_type", "signed_callback"),
        "secret_ref": body.get("secret_ref"),
        "status": body.get("status", "active"),
        "last_seen_at": body.get("last_seen_at"),
    })


def update_verification_method(method_id: str, changes: dict) -> dict | None:
    method = get("verification_method", method_id)
    if not method:
        return None
    method.update({key: value for key, value in changes.items()
                   if key not in {"id", "created_at", "updated_at"}})
    return _put("verification_method", method_id, method)


# A tool with no ceiling is a tool that can run until something else breaks -
# the disk, the rate limit of an upstream provider, or the owner's credit. The
# enforcement has always been here; what was missing was that an absent limit
# read as "unlimited" rather than as "nobody said, so be careful".
#
# Deliberately conservative. A tool that genuinely needs more says so
# explicitly, which makes it a decision someone made rather than an oversight.
DEFAULT_USAGE_LIMITS = {
    "max_per_minute": 6,
    "max_per_hour": 60,
    "max_runtime_seconds": 30,
    "cooldown_seconds": 0,
}


def with_default_limits(policy: dict | None) -> dict:
    """Fill in any ceiling the caller did not set.

    An explicit value always wins, including a deliberately high one - the
    point is not to cap what the owner chose, it is that nothing arrives
    uncapped by accident. `cooldown_seconds` is the exception that may legally
    be zero, so only genuinely missing keys are filled.
    """
    policy = dict(policy or {})
    limits = dict(policy.get("usage_limits") or {})
    for name, fallback in DEFAULT_USAGE_LIMITS.items():
        if limits.get(name) is None:
            limits[name] = fallback
    policy["usage_limits"] = limits
    return policy


def create_tool(body: dict, *, require_existing: bool = False) -> dict | None:
    tool_id = body["id"]
    return _put("tool", tool_id, {"name": body.get("name", tool_id), "description": body.get("description", ""),
        "service_id": body.get("service_id"), "category": body.get("category", "controlled"),
        "inputs": body.get("inputs", []), "outputs": body.get("outputs", []),
        "execution": body.get("execution", {}), "policy": with_default_limits(body.get("policy")),
        "authorization": body.get("authorization", "auto"), "version": body.get("version", 1), "status": body.get("status", "active")},
        expected_version=body.get("expected_version"), require_existing=require_existing)


def update_tool(tool_id: str, body: dict) -> dict | None:
    return create_tool({**body, "id": tool_id}, require_existing=True)


def create_automation(body: dict, *, require_existing: bool = False) -> dict | None:
    automation_id = body["id"]
    return _put("automation", automation_id, {"name": body.get("name", automation_id),
        "description": body.get("description", ""), "inputs": body.get("inputs", []),
        "workflow": body.get("workflow", []), "policy": with_default_limits(body.get("policy")),
        "authorization": body.get("authorization", "auto"), "schedule": body.get("schedule"),
        "version": body.get("version", 1), "status": body.get("status", "draft")},
        expected_version=body.get("expected_version"), require_existing=require_existing)


def update_automation(automation_id: str, body: dict) -> dict | None:
    return create_automation({**body, "id": automation_id}, require_existing=True)






# These requests are messages to the owner, never execution credentials.
INFORMATIONAL_REQUEST_KINDS = frozenset({
    "create-tool", "create-automation", "edit", "delete", "secret",
    "warning", "update", "suggestion", "info",
})


def _insert_request(conn: sqlite3.Connection, record: dict) -> dict:
    now = _now()
    record = {**record, "id": str(uuid.uuid4()), "status": "pending"}
    conn.execute("INSERT INTO v2_objects(kind,id,body,created_at,updated_at) VALUES('request',?,?,?,?)",
                 (record["id"], json.dumps(record), now, now))
    _request_event(conn, "request_created", record["severity"], record["id"], record["actor"],
                   {"kind": record["kind"], "title": record["title"]})
    return {**record, "created_at": now, "updated_at": now}


def _request_event(conn: sqlite3.Connection, event_type: str, severity: str,
                   request_id: str, actor: str, payload: dict) -> None:
    # A committed transition without its audit event is an incomplete account of authority.
    conn.execute("INSERT INTO v2_events VALUES(?,?,?,?,?,?,?,?)",
                 (str(uuid.uuid4()), event_type, severity, "request", request_id,
                  actor, json.dumps(payload), _now()))


def create_request(kind: str, title: str, details: str, actor: str, payload: dict | None = None,
                   severity: str = "info") -> dict:
    if kind not in INFORMATIONAL_REQUEST_KINDS:
        raise ValueError("Request kind is not informational; request execution through the tool invoke or automation run endpoint")
    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        return _insert_request(conn, {"kind": kind, "title": title, "details": details,
                                     "actor": actor, "payload": payload or {}, "severity": severity})


def _verification_fingerprint(record: dict) -> str:
    payload = {**record.get("payload", {})}
    payload["binding"] = {key: value for key, value in payload.get("binding", {}).items()
                          if key not in {"consumed_at", "consumed_by"}}
    immutable = {key: record.get(key) for key in ("id", "kind", "title", "details", "actor", "severity")}
    immutable["payload"] = payload
    return hashlib.sha256(json.dumps(immutable, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True).encode()).hexdigest()


def _verification_origin_valid(conn: sqlite3.Connection, record: dict) -> bool:
    origin = conn.execute("SELECT fingerprint FROM v2_verification_origins WHERE request_id=?",
                          (record["id"],)).fetchone()
    return bool(origin and secrets.compare_digest(origin[0], _verification_fingerprint(record)))


def invalidate_legacy_verifications() -> int:
    """Old records may be forged; preserving their text is not permission to use them."""
    changed = 0
    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute("SELECT * FROM v2_objects WHERE kind='request'").fetchall()
        for row in rows:
            record = _row(row)
            binding = record.get("payload", {}).get("binding")
            consumed = isinstance(binding, dict) and binding.get("consumed_at")
            if (record.get("kind") != "verification" or record.get("status") not in {"pending", "approved"}
                    or (record.get("status") == "approved" and consumed)
                    or _verification_origin_valid(conn, record)):
                continue
            record["status"] = "cancelled"
            record["decision"] = {"actor": "system", "at": _now(),
                                  "note": "Untrusted legacy approval; request fresh confirmation through the invoke path"}
            _save_request(conn, record)
            _request_event(conn, "verification_invalidated", "warning", record["id"], "system",
                           {"reason": "untrusted issuance"})
            changed += 1
    return changed


def _save_request(conn: sqlite3.Connection, record: dict) -> None:
    now = _now()
    conn.execute("UPDATE v2_objects SET body=?,updated_at=? WHERE kind='request' AND id=?",
                 (json.dumps({key: value for key, value in record.items()
                              if key not in {"created_at", "updated_at"}}), now, record["id"]))
    record["updated_at"] = now


def action_digest(subject_type: str, subject_id: str, args: dict, version: int | None = None) -> str:
    canonical = json.dumps({"subject_type": subject_type, "subject_id": subject_id,
                            "version": version, "args": args}, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def automation_tool_snapshot(conn, automation_id: str, version: int | None) -> dict:
    row = conn.execute("SELECT * FROM v2_objects WHERE kind='automation' AND id=?", (automation_id,)).fetchone()
    if not row or _row(row).get("version") != version:
        raise ValueError("Automation changed; request fresh confirmation")
    tools = {}

    def visit(steps):
        for step in steps:
            kind = step.get("type")
            if kind == "tool_call":
                tool_id = step["tool_id"]
                child = conn.execute("SELECT * FROM v2_objects WHERE kind='tool' AND id=?", (tool_id,)).fetchone()
                if not child or _row(child).get("status") != "active":
                    raise ValueError(f"Child tool {tool_id} is unavailable; review the automation")
                tools[tool_id] = _row(child)
            elif kind == "condition":
                visit(step.get("then", []))
                visit(step.get("else", []))
            elif kind == "switch":
                for branch in step.get("cases", {}).values():
                    visit(branch)
                visit(step.get("default", []))
            elif kind == "loop":
                visit(step.get("steps", []))
            elif kind == "retry":
                visit([step["step"]])

    visit(_row(row).get("workflow", []))
    return tools


def child_bindings(tools: dict) -> dict:
    # Bind definitions as well as versions: delete/recreate must not reuse an approval.
    return {key: {"version": tool.get("version"), "digest": hashlib.sha256(
        json.dumps(tool, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
        for key, tool in tools.items()}


def create_verification_request(title: str, details: str, actor: str, subject_type: str,
                                subject_id: str, args: dict, version: int | None,
                                expiry_seconds: int = 60, actor_id: str | None = None, *,
                                publication_digest: str | None = None) -> dict:
    expiry = datetime.now(UTC) + timedelta(seconds=max(15, min(expiry_seconds, 900)))
    binding = {
        "subject_type": subject_type,
        "subject_id": subject_id,
        "version": version,
        "args_digest": action_digest(subject_type, subject_id, args, version),
        "nonce": secrets.token_urlsafe(24),
        "expires_at": expiry.isoformat(),
        "consumed_at": None,
    }
    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if publication_digest is not None:
            from toolgate.core import publications
            publication = publications.for_execution(conn, subject_type, subject_id, version)
            if publication["digest"] != publication_digest:
                raise ValueError("Publication identity changed")
            binding["publication_digest"] = publication_digest
            binding["child_tools"] = child_bindings(publication["tools"])
            binding["child_automations"] = publications.automation_bindings(publication)
        elif subject_type == "automation":
            binding["child_tools"] = child_bindings(automation_tool_snapshot(conn, subject_id, version))
        record = _insert_request(conn, {
            "kind": "verification", "title": title, "details": details, "actor": actor,
            "payload": {"subject_type": subject_type, "subject_id": subject_id,
                        "args": args, "binding": binding, "created_by_agent_key": actor_id},
            "severity": "warning",
        })
        conn.execute("INSERT INTO v2_verification_origins(request_id,fingerprint) VALUES(?,?)",
                     (record["id"], _verification_fingerprint(record)))
        return record


def consume_verification(request_id: str, subject_type: str, subject_id: str,
                         args: dict, version: int | None, actor: str,
                         actor_id: str | None = None) -> tuple[bool, str]:
    """Atomically consume an approved action binding exactly once."""
    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        return consume_verification_in_transaction(
            conn, request_id, subject_type, subject_id, args, version, actor, actor_id)


def consume_verification_in_transaction(conn, request_id: str, subject_type: str, subject_id: str,
                                        args: dict, version: int | None, actor: str,
                                        actor_id: str | None = None, *,
                                        publication_digest: str | None = None) -> tuple[bool, str]:
    now = datetime.now(UTC)
    row = conn.execute("SELECT * FROM v2_objects WHERE kind='request' AND id=?", (request_id,)).fetchone()
    if not row:
        return False, "Approval request was not found"
    record = _row(row)
    binding = record.get("payload", {}).get("binding", {})
    if record.get("kind") != "verification" or record.get("status") != "approved":
        return False, f"Approval request is {record.get('status', 'invalid')}"
    if not _verification_origin_valid(conn, record):
        return False, "Approval was not issued intact by ToolGate; request fresh confirmation"
    created_by = record.get("payload", {}).get("created_by_agent_key")
    if not created_by or actor_id != created_by:
        return False, "Approval request belongs to a different originating agent"
    if binding.get("consumed_at"):
        return False, "Approval request has already been consumed"
    try:
        expires_at = datetime.fromisoformat(binding["expires_at"])
    except (KeyError, TypeError, ValueError):
        return False, "Approval request has an invalid expiry"
    if expires_at.tzinfo is None:
        return False, "Approval request has an invalid expiry"
    if expires_at <= now:
        return False, "Approval request has expired"
    expected = action_digest(subject_type, subject_id, args, version)
    if not secrets.compare_digest(str(binding.get("args_digest", "")), expected):
        return False, "Approval does not match this exact action"
    if binding.get("publication_digest") != publication_digest:
        return False, "Approval does not match this exact publication"
    if publication_digest is not None:
        from toolgate.core import publications
        try:
            publication = publications.for_execution(conn, subject_type, subject_id, version)
        except ValueError as exc:
            return False, str(exc)
        if publication["digest"] != publication_digest or binding.get("child_tools") != child_bindings(publication["tools"]):
            return False, "Publication identity changed; request fresh confirmation"
        if binding.get("child_automations", {}) != publications.automation_bindings(publication):
            return False, "Nested publication identities changed; request fresh confirmation"
    elif subject_type == "automation":
        try:
            current = child_bindings(automation_tool_snapshot(conn, subject_id, version))
        except ValueError as exc:
            return False, str(exc)
        if binding.get("child_tools") != current:
            return False, "Automation child definitions changed; request fresh confirmation"
    binding["consumed_at"] = now.isoformat()
    binding["consumed_by"] = actor
    record["payload"]["binding"] = binding
    _save_request(conn, record)
    _request_event(conn, "verification_consumed", "info", request_id, actor,
                   {"subject_type": subject_type, "subject_id": subject_id})
    return True, "approved"


def decide_request(request_id: str, status: str, actor: str, note: str = "", *, guard=None) -> dict | None:
    if status not in {"approved", "rejected", "dismissed"}:
        raise ValueError("Decision must be approved, rejected, or dismissed")
    with _conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM v2_objects WHERE kind='request' AND id=?", (request_id,)).fetchone()
        if not row:
            return None
        record = _row(row)
        if guard is not None:
            guard(conn, record)
        if record.get("status") != "pending":
            raise ValueError(f"request is already {record.get('status')}")
        if record.get("kind") == "verification":
            if not _verification_origin_valid(conn, record):
                raise ValueError("Approval was not issued intact by ToolGate; request fresh confirmation")
            if status == "approved":
                try:
                    expires_at = datetime.fromisoformat(record["payload"]["binding"]["expires_at"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise ValueError("Approval expiry is invalid; request fresh confirmation") from exc
                if expires_at.tzinfo is None or expires_at <= datetime.now(UTC):
                    raise ValueError("Approval has expired; request fresh confirmation")
        record["status"] = status
        record["decision"] = {"actor": actor, "note": note, "at": _now()}
        _save_request(conn, record)
        _request_event(conn, "request_decided", "info" if status == "approved" else "warning",
                       request_id, actor, {"status": status})
    return record
