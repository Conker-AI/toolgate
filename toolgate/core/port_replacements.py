"""Private replacement payloads and once-only steps under the execution journal."""

import json
import re
import time

from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import vault
from toolgate.executors.port_spec import Replacement

SCHEMA = """
CREATE TABLE IF NOT EXISTS v2_port_replacements (
 action_id TEXT PRIMARY KEY REFERENCES v2_actions(action_id), sealed TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS v2_port_steps (
 action_id TEXT NOT NULL REFERENCES v2_port_replacements(action_id),
 ordinal INTEGER NOT NULL, name TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('dispatching','observed','outcome_unknown')),
 reference TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL,
 PRIMARY KEY(action_id,ordinal)
);
CREATE TRIGGER IF NOT EXISTS port_payload_no_update BEFORE UPDATE ON v2_port_replacements
BEGIN SELECT RAISE(ABORT,'replacement identity is immutable'); END;
CREATE TRIGGER IF NOT EXISTS port_payload_no_delete BEFORE DELETE ON v2_port_replacements
BEGIN SELECT RAISE(ABORT,'replacement identity is permanent'); END;
CREATE TRIGGER IF NOT EXISTS port_payload_no_replace BEFORE INSERT ON v2_port_replacements
WHEN EXISTS(SELECT 1 FROM v2_port_replacements WHERE action_id=NEW.action_id)
BEGIN SELECT RAISE(ABORT,'replacement identity already exists'); END;
CREATE TRIGGER IF NOT EXISTS port_step_no_delete BEFORE DELETE ON v2_port_steps
BEGIN SELECT RAISE(ABORT,'replacement step is permanent'); END;
CREATE TRIGGER IF NOT EXISTS port_step_no_replace BEFORE INSERT ON v2_port_steps
WHEN EXISTS(SELECT 1 FROM v2_port_steps WHERE action_id=NEW.action_id AND ordinal=NEW.ordinal)
BEGIN SELECT RAISE(ABORT,'replacement step already exists'); END;
CREATE TRIGGER IF NOT EXISTS port_step_identity BEFORE UPDATE ON v2_port_steps
WHEN NEW.action_id IS NOT OLD.action_id OR NEW.ordinal IS NOT OLD.ordinal
 OR NEW.name IS NOT OLD.name OR NEW.created_at IS NOT OLD.created_at
 OR OLD.status='observed'
BEGIN SELECT RAISE(ABORT,'replacement step is immutable'); END;
"""


class ReplacementError(ValueError):
    def __init__(self):
        super().__init__("Replacement state is unavailable or conflicts with this operation.")


def _initialize(conn):
    journal.initialize(conn)
    conn.executescript(SCHEMA)


def _parent(conn, action_id, *, active=False):
    parent = conn.execute("SELECT * FROM v2_actions WHERE action_id=?", (action_id,)).fetchone()
    if (not parent or parent["subject_type"] != "tool"
            or parent["subject_id"] != "system.port-control"
            or (active and parent["status"] != "dispatching")):
        raise ReplacementError()
    return parent


def save(action_id, replacement):
    """Called after ordinary owner-approved action admission, before any effect."""
    if not isinstance(replacement, Replacement):
        raise ReplacementError()
    with cp._conn() as conn:
        _initialize(conn)
        conn.execute("BEGIN IMMEDIATE")
        parent = _parent(conn, action_id, active=True)
        if conn.execute("SELECT 1 FROM v2_port_replacements WHERE action_id=?", (action_id,)).fetchone():
            raise ReplacementError()
        args = json.loads(parent["args"])
        if args.get("container_id") != replacement.preview["containerId"]:
            raise ReplacementError()
        payload = json.dumps({"action_id": action_id, "fingerprint": parent["fingerprint"],
                              "preview": replacement.preview, "body": replacement._body,
                              "source": replacement._source, "name": replacement.name}, allow_nan=False)
        if len(payload.encode()) > 2 * 1024 * 1024:
            raise ReplacementError()
        sealed = vault._encrypt(payload)
        conn.execute("INSERT INTO v2_port_replacements VALUES (?,?)", (action_id, sealed))


def load_private(action_id):
    """Executor/recovery use only. Not an owner/agent response object."""
    with cp._conn() as conn:
        _initialize(conn)
        parent = _parent(conn, action_id)
        row = conn.execute("SELECT sealed FROM v2_port_replacements WHERE action_id=?", (action_id,)).fetchone()
        if not row or not row["sealed"].startswith(vault.ENCRYPTED_PREFIX):
            raise ReplacementError()
        try:
            payload = json.loads(vault._decrypt("replacement payload", row["sealed"]))
            if payload["action_id"] != action_id or payload["fingerprint"] != parent["fingerprint"]:
                raise ReplacementError()
            return Replacement(payload["preview"], payload["body"], payload["source"], payload["name"])
        except (vault.VaultError, KeyError, TypeError, ValueError):
            raise ReplacementError() from None


def begin_step(action_id, ordinal, name, *, authorize):
    """Commit before dispatch; a duplicate claim never permits a second effect."""
    if (type(ordinal) is not int or not 0 <= ordinal < 150
            or name not in ("stop", "snapshot", "retire", "rename", "disconnect", "create", "connect", "start", "verify")
            or not callable(authorize)):
        raise ReplacementError()
    with cp._conn() as conn:
        _initialize(conn)
        conn.execute("BEGIN IMMEDIATE")
        _parent(conn, action_id, active=True)
        if not conn.execute("SELECT 1 FROM v2_port_replacements WHERE action_id=?", (action_id,)).fetchone():
            raise ReplacementError()
        previous = conn.execute("SELECT * FROM v2_port_steps WHERE action_id=? ORDER BY ordinal", (action_id,)).fetchall()
        if ordinal < len(previous):
            if previous[ordinal]["name"] != name:
                raise ReplacementError()
            return False
        if ordinal != len(previous) or any(row["status"] != "observed" for row in previous):
            raise ReplacementError()
        authorize(conn)
        now = time.time()
        conn.execute("INSERT INTO v2_port_steps VALUES (?,?,?,'dispatching',NULL,?,?)",
                     (action_id, ordinal, name, now, now))
        return True


def observed(action_id, ordinal, *, reference=None):
    # No arbitrary Docker response/diagnostic can enter a public step receipt.
    if reference is not None and (not isinstance(reference, str)
                                  or not re.fullmatch(r"(?:sha256:)?[a-f0-9]{64}", reference)):
        raise ReplacementError()
    with cp._conn() as conn:
        _initialize(conn)
        conn.execute("BEGIN IMMEDIATE")
        _parent(conn, action_id)
        row = conn.execute("SELECT * FROM v2_port_steps WHERE action_id=? AND ordinal=?", (action_id, ordinal)).fetchone()
        if not row:
            raise ReplacementError()
        if row["status"] == "observed":
            if row["reference"] != reference:
                raise ReplacementError()
            return
        conn.execute("UPDATE v2_port_steps SET status='observed',reference=?,updated_at=? WHERE action_id=? AND ordinal=?",
                     (reference, time.time(), action_id, ordinal))


def unknown(action_id, ordinal):
    with cp._conn() as conn:
        _initialize(conn)
        conn.execute("UPDATE v2_port_steps SET status='outcome_unknown',updated_at=?"
                     " WHERE action_id=? AND ordinal=? AND status='dispatching'", (time.time(), action_id, ordinal))
    journal.unknown(action_id)


def steps(action_id):
    with cp._conn() as conn:
        _initialize(conn)
        parent = _parent(conn, action_id)
        result = []
        for row in conn.execute("SELECT * FROM v2_port_steps WHERE action_id=? ORDER BY ordinal", (action_id,)):
            status = row["status"]
            if status == "dispatching" and parent["status"] != "dispatching":
                status = "outcome_unknown"
            result.append({"ordinal": row["ordinal"], "name": row["name"],
                           "status": status, "reference": row["reference"]})
        return result
