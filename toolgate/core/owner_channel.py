"""Narrow owner review: exact bounded arguments, never a vault or execution channel."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
from datetime import datetime, timezone

from . import control_plane as cp
from . import vault

OWNER_HASH = "TOOLGATE_OWNER_KEY_SHA256"
ARGUMENT_BYTES = 32768
PAGE_BYTES = 6 * 1024 * 1024


class OwnerError(ValueError):
    def __init__(self, code: str, message: str, status: int = 409):
        super().__init__(message)
        self.code, self.status = code, status


def authenticate(raw: str | None) -> None:
    pinned = os.environ.get(OWNER_HASH, "")
    if not re.fullmatch(r"[0-9a-f]{64}", pinned):
        raise OwnerError("owner_channel_unavailable", "The owner channel is not configured.", 503)
    if not isinstance(raw, str) or not 32 <= len(raw) <= 256:
        raise OwnerError("owner_credential_required", "A dedicated owner credential is required.", 401)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    # Accidental reuse of an admin/execution credential must never widen that channel.
    admin = vault.get_control_key("TOOLGATE_ADMIN_KEY")
    with cp._conn() as db:
        execution = db.execute("SELECT 1 FROM v2_agent_keys WHERE key_hash=?", (hashed,)).fetchone()
    if (not secrets.compare_digest(hashed, pinned) or execution or
            (admin and secrets.compare_digest(raw.encode(), admin.encode()))):
        raise OwnerError("owner_credential_required", "A dedicated owner credential is required.", 401)


def _text(value, maximum):
    if not isinstance(value, str):
        return ""
    # These are display labels only. Action arguments are never truncated.
    value = value.encode("utf-8", errors="replace").decode("utf-8")
    return value if len(value) <= maximum else value[:maximum - 1] + "…"


def _date(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        date = datetime.fromisoformat(value)
        return value if date.tzinfo is not None else None
    except ValueError:
        return None


def _arguments(value):
    if not isinstance(value, dict):
        return None
    count = 0

    def check(item, depth=0):
        nonlocal count
        count += 1
        if count > 2048 or depth > 16:
            raise ValueError("bounds")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise TypeError("key")
                check(key, depth + 1)
                check(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                check(child, depth + 1)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("number")
        elif isinstance(item, (int, float)) and abs(item) > 9007199254740991:
            # JSON.parse cannot display these integers without rounding the approved action.
            raise ValueError("number precision")
        elif not isinstance(item, (str, bool, int, float, type(None))):
            raise ValueError("value")
    try:
        check(value)
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
        return value if len(encoded) <= ARGUMENT_BYTES else None
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return None


def project(db, record):
    payload = record.get("payload")
    payload = payload if isinstance(payload, dict) else {}
    binding = payload.get("binding")
    binding = binding if isinstance(binding, dict) else {}
    try:
        origin_valid = cp._verification_origin_valid(db, record)
    except (ValueError, TypeError, AttributeError, RecursionError):
        origin_valid = False
    subject_type = binding.get("subject_type")
    subject_id = binding.get("subject_id")
    version = binding.get("version")
    subject_type = subject_type if isinstance(subject_type, str) and subject_type in {
        "tool", "automation"} else None
    subject_id = subject_id if isinstance(subject_id, str) and re.fullmatch(
        r"[A-Za-z0-9_.:-]{1,200}", subject_id) else None
    version = version if type(version) is int and 1 <= version <= 2147483647 else None
    args = _arguments(payload.get("args")) if origin_valid else None
    expires, consumed = _date(binding.get("expires_at")), _date(binding.get("consumed_at"))
    reason = None
    if not origin_valid:
        reason = "invalid_origin"
    elif (not subject_type or not subject_id or version is None or not expires or
          payload.get("subject_type") != subject_type or payload.get("subject_id") != subject_id):
        reason = "invalid_action"
    elif args is None:
        reason = "arguments_unavailable"
    elif subject_type != "tool":
        reason = "unsupported_subject"
    elif binding.get("consumed_at"):
        reason = "consumed"
    elif datetime.fromisoformat(expires) <= datetime.now(timezone.utc):
        reason = "expired"
    elif record.get("status") != "pending":
        reason = "already_decided"
    decision = record.get("decision")
    decision = ({"status": _text(record.get("status"), 32),
                 "actor": _text(decision.get("actor"), 200),
                 "note": _text(decision.get("note"), 2000),
                 "at": _date(decision.get("at"))} if isinstance(decision, dict) else None)
    return {
        "id": record["id"], "kind": "verification", "title": _text(record.get("title"), 500),
        "details": _text(record.get("details"), 2000), "actor": _text(record.get("actor"), 200),
        "severity": _text(record.get("severity"), 32), "status": _text(record.get("status"), 32),
        "created_at": _date(record.get("created_at")), "updated_at": _date(record.get("updated_at")),
        "decision": decision,
        "action": {"subject_type": subject_type, "subject_id": subject_id,
                   "version": version, "args": args},
        "approval": {"expires_at": expires, "consumed_at": consumed, "origin_valid": origin_valid},
        "reviewable": reason is None, "unavailable_reason": reason,
    }


def _record(row):
    return {**cp._row(row), "created_at": row["created_at"], "updated_at": row["updated_at"]}


def _row(db, identity):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identity):
        raise OwnerError("not_found", "Owner request not found.", 404)
    row = db.execute("SELECT * FROM v2_objects WHERE kind='request' AND id=?", (identity,)).fetchone()
    if not row or cp._row(row).get("kind") != "verification":
        raise OwnerError("not_found", "Owner request not found.", 404)
    return row


def get(identity):
    with cp._conn() as db:
        db.execute("BEGIN")
        return project(db, _record(_row(db, identity)))


def list_requests(limit=50, cursor=None):
    with cp._conn() as db:
        db.execute("BEGIN")
        before, values = "", []
        if cursor is not None:
            row = _row(db, cursor)
            before = " AND (created_at,id)<(?,?)"
            values = [row["created_at"], row["id"]]
        rows = db.execute("SELECT * FROM v2_objects WHERE kind='request' "
                          "AND json_extract(body,'$.kind')='verification'" + before +
                          " ORDER BY created_at DESC,id DESC LIMIT ?", (*values, limit + 1)).fetchall()
        results, size = [], 0
        for row in rows[:limit]:
            value = project(db, _record(row))
            length = len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
            if results and size + length > PAGE_BYTES:
                break
            results.append(value)
            size += length
        return {"results": results,
                "next_cursor": results[-1]["id"] if len(rows) > len(results) else None}


def decide(identity, status, note):
    def guard(db, record):
        if record.get("kind") != "verification":
            raise OwnerError("not_found", "Owner request not found.", 404)
        view = project(db, record)
        permitted = (view["reviewable"] if status == "approved" else
                     view["unavailable_reason"] in {None, "expired", "unsupported_subject"})
        if not view["approval"]["origin_valid"] or not permitted:
            raise OwnerError("not_reviewable", "This exact action cannot be approved from this view.")
    try:
        record = cp.decide_request(identity, status, "gateway-owner", note, guard=guard)
    except OwnerError:
        raise
    except ValueError:
        raise OwnerError("decision_conflict", "The request cannot accept this decision. Reload it.") from None
    if record is None:
        raise OwnerError("not_found", "Owner request not found.", 404)
    return get(identity)
