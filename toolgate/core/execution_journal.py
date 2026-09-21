"""Durable dispatch identities. Missing replies never authorize another dispatch."""
from __future__ import annotations

import hashlib
import json
import re
import time

from toolgate.core import container_admission, control_plane, spending

SCHEMA = """
CREATE TABLE IF NOT EXISTS v2_actions (
    action_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    version INTEGER,
    args TEXT NOT NULL,
    job_id TEXT,
    parent_action_id TEXT REFERENCES v2_actions(action_id),
    publication_digest TEXT,
    status TEXT NOT NULL CHECK(status IN ('dispatching','completed','outcome_unknown')),
    response TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TRIGGER IF NOT EXISTS v2_action_identity_immutable BEFORE UPDATE ON v2_actions
WHEN NEW.action_id IS NOT OLD.action_id OR NEW.fingerprint IS NOT OLD.fingerprint
  OR NEW.actor_id IS NOT OLD.actor_id OR NEW.subject_type IS NOT OLD.subject_type
  OR NEW.subject_id IS NOT OLD.subject_id OR NEW.version IS NOT OLD.version
  OR NEW.args IS NOT OLD.args OR NEW.job_id IS NOT OLD.job_id
  OR NEW.parent_action_id IS NOT OLD.parent_action_id OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'action identity is immutable'); END;
CREATE TRIGGER IF NOT EXISTS v2_actions_no_delete BEFORE DELETE ON v2_actions
BEGIN SELECT RAISE(ABORT, 'execution records are permanent'); END;
CREATE TRIGGER IF NOT EXISTS v2_actions_no_replace BEFORE INSERT ON v2_actions
WHEN EXISTS (SELECT 1 FROM v2_actions WHERE action_id=NEW.action_id)
BEGIN SELECT RAISE(ABORT, 'action identity already exists'); END;
CREATE TRIGGER IF NOT EXISTS v2_action_result_immutable BEFORE UPDATE ON v2_actions
WHEN OLD.status='completed'
BEGIN SELECT RAISE(ABORT, 'completed execution records are immutable'); END;
"""


class ExecutionConflict(ValueError):
    pass


def initialize(conn) -> None:
    conn.executescript(SCHEMA)
    conn.executescript(container_admission.SCHEMA)
    # Additive upgrade: legacy identities keep their exact original fingerprint.
    if "publication_digest" not in {row["name"] for row in conn.execute("PRAGMA table_info(v2_actions)")}:
        conn.execute("BEGIN IMMEDIATE")
        if "publication_digest" not in {row["name"] for row in conn.execute("PRAGMA table_info(v2_actions)")}:
            conn.execute("ALTER TABLE v2_actions ADD COLUMN publication_digest TEXT")
        conn.commit()
    conn.executescript("""
    CREATE TRIGGER IF NOT EXISTS v2_action_publication_immutable BEFORE UPDATE ON v2_actions
    WHEN NEW.publication_digest IS NOT OLD.publication_digest
    BEGIN SELECT RAISE(ABORT, 'action publication is immutable'); END;
    """)
    spending.initialize(conn)


def fingerprint(subject_type: str, subject_id: str, args: dict, actor_id: str,
                job_id: str | None, parent_action_id: str | None,
                publication_digest: str | None = None) -> str:
    identity = [subject_type, subject_id, args, actor_id, job_id, parent_action_id]
    if publication_digest is not None:
        identity.append({"publication_digest": publication_digest})
    encoded = json.dumps(identity,
                         sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


def existing(action_id: str, subject_type: str, subject_id: str, args: dict, actor_id: str,
             job_id: str | None = None, parent_action_id: str | None = None, *,
             publication_digest: str | None = None) -> dict | None:
    if not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,160}", action_id):
        raise ExecutionConflict("Use an action_id of 1-160 ASCII letters, digits or _ . : / -")
    expected = fingerprint(subject_type, subject_id, args, actor_id, job_id, parent_action_id, publication_digest)
    with control_plane._conn() as conn:
        initialize(conn)
        row = conn.execute("SELECT * FROM v2_actions WHERE action_id=?", (action_id,)).fetchone()
        if row and row["fingerprint"] != expected:
            raise ExecutionConflict("This action_id is already bound to a different invocation")
        return _row(row) if row else None


def _row(row) -> dict:
    return {**dict(row), "args": json.loads(row["args"]),
            "response": json.loads(row["response"]) if row["response"] else None}


def begin(action_id: str, subject_type: str, subject_id: str, args: dict, actor_id: str,
          version: int | None, *, job_id: str | None = None,
          parent_action_id: str | None = None, authorize=None, reserve=None,
          publication_digest: str | None = None) -> tuple[dict, bool]:
    expected = fingerprint(subject_type, subject_id, args, actor_id, job_id, parent_action_id, publication_digest)
    with control_plane._conn() as conn:
        initialize(conn)
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM v2_actions WHERE action_id=?", (action_id,)).fetchone()
        if row:
            if row["fingerprint"] != expected:
                raise ExecutionConflict("This action_id is already bound to a different invocation")
            return _row(row), False
        if parent_action_id:
            parent = conn.execute("SELECT * FROM v2_actions WHERE action_id=?",
                                  (parent_action_id,)).fetchone()
            if (not parent or parent["actor_id"] != actor_id or parent["job_id"] != job_id
                    or parent["status"] != "dispatching"):
                raise ExecutionConflict("Child dispatch must inherit its active parent's job and identity")
        if authorize:
            authorize(conn)
        now = time.time()
        conn.execute("INSERT INTO v2_actions(action_id,fingerprint,actor_id,subject_type,subject_id,version,args,"
                     "job_id,parent_action_id,publication_digest,status,response,created_at,updated_at) "
                     "VALUES (?,?,?,?,?,?,?,?,?,?,'dispatching',NULL,?,?)",
                     (action_id, expected, actor_id, subject_type, subject_id, version,
                      json.dumps(args, allow_nan=False), job_id, parent_action_id, publication_digest, now, now))
        if reserve:
            reserve(conn)
        row = conn.execute("SELECT * FROM v2_actions WHERE action_id=?", (action_id,)).fetchone()
        # The context manager commits before the caller can enter its executor.
        return _row(row), True


def finish(action_id: str, response: dict, reconcile=None) -> dict:
    with control_plane._conn() as conn:
        initialize(conn)
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM v2_actions WHERE action_id=?", (action_id,)).fetchone()
        if row["status"] == "completed":
            return _row(row)
        if reconcile:
            reconcile(conn)
        conn.execute("UPDATE v2_actions SET status='completed',response=?,updated_at=? WHERE action_id=?",
                     (json.dumps(response, allow_nan=False), time.time(), action_id))
        return _row(conn.execute("SELECT * FROM v2_actions WHERE action_id=?", (action_id,)).fetchone())


def unknown(action_id: str) -> None:
    with control_plane._conn() as conn:
        initialize(conn)
        conn.execute("UPDATE v2_actions SET status='outcome_unknown',updated_at=?"
                     " WHERE action_id=? AND status='dispatching'", (time.time(), action_id))


def recover_interrupted() -> int:
    with control_plane._conn() as conn:
        initialize(conn)
        return conn.execute("UPDATE v2_actions SET status='outcome_unknown',updated_at=?"
                            " WHERE status='dispatching'", (time.time(),)).rowcount


def get(action_id: str) -> dict | None:
    with control_plane._conn() as conn:
        initialize(conn)
        row = conn.execute("SELECT * FROM v2_actions WHERE action_id=?", (action_id,)).fetchone()
        return _row(row) if row else None


def list_actions(limit: int = 100) -> list[dict]:
    with control_plane._conn() as conn:
        initialize(conn)
        return [_row(row) for row in conn.execute(
            "SELECT * FROM v2_actions ORDER BY created_at DESC LIMIT ?", (limit,))]


def response(record: dict) -> dict:
    target = {"definition_version": record["version"], "publication_digest": record["publication_digest"]} if record.get("publication_digest") else {}
    if record["response"] is not None:
        return {**record["response"], **target, "action_id": record["action_id"], "status": "completed"}
    return {**target, "code": "OUTCOME_UNKNOWN" if record["status"] == "outcome_unknown" else "IN_PROGRESS",
            "action_id": record["action_id"], "status": record["status"],
            "message": "Dispatch is recorded but its outcome is not confirmed. Do not repeat it."}
