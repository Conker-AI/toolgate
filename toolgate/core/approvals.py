"""Approval requests and owner verifications: creating, deciding and consuming each exactly once."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

from toolgate.core.control_plane import _conn, _now, _row

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


# Once the owner approves a request that waited for him, the action has this long to run.
EXECUTION_WINDOW = timedelta(minutes=15)


def create_verification_request(title: str, details: str, actor: str, subject_type: str,
                                subject_id: str, args: dict, version: int | None,
                                expiry_seconds: int = 60, actor_id: str | None = None, *,
                                publication_digest: str | None = None, card: str = "do") -> dict:
    """A request for the owner's decision on one exact action. A positive expiry bounds the wait
    (15 to 900 seconds); 0 means it waits until he answers, and the action then has
    EXECUTION_WINDOW from his approval to run. `card` is the tool's button template, copied now
    so the Inbox shows the buttons he chose when he was asked."""
    expiry = (
        datetime.now(UTC) + timedelta(seconds=max(15, min(expiry_seconds, 900)))
        if expiry_seconds > 0
        else None
    )
    binding = {
        "subject_type": subject_type,
        "subject_id": subject_id,
        "version": version,
        "args_digest": action_digest(subject_type, subject_id, args, version),
        "nonce": secrets.token_urlsafe(24),
        "expires_at": expiry.isoformat() if expiry else None,
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
                        "args": args, "binding": binding, "created_by_agent_key": actor_id,
                        "card": card},
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
    deadline = _execution_deadline(record, binding)
    if deadline is None:
        return False, "Approval request has an invalid expiry"
    if deadline <= now:
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


def _execution_deadline(record: dict, binding: dict) -> datetime | None:
    """When an approved action stops being runnable; None when the record is malformed.

    A bounded request ends at its own expiry. One that waited for the owner (no expiry) ends
    EXECUTION_WINDOW after his approval, which is recorded outside the immutable binding."""
    if "expires_at" not in binding:
        return None
    raw = binding["expires_at"]
    if raw is None:
        raw = (record.get("decision") or {}).get("at")
        if not isinstance(raw, str):
            return None
        try:
            decided = datetime.fromisoformat(raw)
        except ValueError:
            return None
        return decided + EXECUTION_WINDOW if decided.tzinfo is not None else None
    try:
        expires_at = datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return None
    return expires_at if expires_at.tzinfo is not None else None


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
                binding = record.get("payload", {}).get("binding", {})
                if "expires_at" not in binding:
                    raise ValueError("Approval expiry is invalid; request fresh confirmation")
                if binding["expires_at"] is not None:
                    try:
                        expires_at = datetime.fromisoformat(binding["expires_at"])
                    except (TypeError, ValueError) as exc:
                        raise ValueError("Approval expiry is invalid; request fresh confirmation") from exc
                    if expires_at.tzinfo is None or expires_at <= datetime.now(UTC):
                        raise ValueError("Approval has expired; request fresh confirmation")
        record["status"] = status
        record["decision"] = {"actor": actor, "note": note, "at": _now()}
        _save_request(conn, record)
        _request_event(conn, "request_decided", "info" if status == "approved" else "warning",
                       request_id, actor, {"status": status})
    return record
