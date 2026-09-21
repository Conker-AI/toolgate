"""Derive managed replacements from verified, completed actions and current roots."""

import hashlib
import json
import re
import sqlite3

from toolgate.core import control_plane as cp
from toolgate.core import port_replacements as records

SCHEMA = """
CREATE TABLE IF NOT EXISTS v2_container_lineage (
 action_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, target_id TEXT NOT NULL UNIQUE,
 socket_digest TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS lineage_no_update BEFORE UPDATE ON v2_container_lineage
BEGIN SELECT RAISE(ABORT,'container lineage is immutable'); END;
CREATE TRIGGER IF NOT EXISTS lineage_no_delete BEFORE DELETE ON v2_container_lineage
BEGIN SELECT RAISE(ABORT,'container lineage is permanent'); END;
CREATE TRIGGER IF NOT EXISTS lineage_no_replace BEFORE INSERT ON v2_container_lineage
WHEN EXISTS(SELECT 1 FROM v2_container_lineage WHERE action_id=NEW.action_id OR target_id=NEW.target_id)
BEGIN SELECT RAISE(ABORT,'container lineage already exists'); END;
"""


def _digest(socket):
    return hashlib.sha256(socket.encode()).hexdigest()


def record(action_id, source_id, target_id, socket):
    if (source_id == target_id or any(not isinstance(value, str) or not re.fullmatch(
            r"[a-f0-9]{64}", value) for value in (source_id, target_id))):
        raise records.ReplacementError()
    with cp._conn() as conn:
        records._initialize(conn)
        conn.executescript(SCHEMA)
        conn.execute("BEGIN IMMEDIATE")
        parent = records._parent(conn, action_id, active=True)
        if json.loads(parent["args"]).get("container_id") != source_id:
            raise records.ReplacementError()
        verified = conn.execute("SELECT reference FROM v2_port_steps WHERE action_id=?"
                                " AND name='verify' AND status='observed'", (action_id,)).fetchall()
        if len(verified) != 1 or verified[0]["reference"] != target_id:
            raise records.ReplacementError()
        conn.execute("INSERT INTO v2_container_lineage VALUES (?,?,?,?)",
                     (action_id, source_id, target_id, _digest(socket)))


def targets(socket, roots):
    """Read-only; pending/uncertain actions cannot grant a replacement identity."""
    if not cp.DB_PATH.exists():
        return frozenset(roots)
    with sqlite3.connect(cp.DB_PATH.resolve().as_uri() + "?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='v2_container_lineage'").fetchone():
            return frozenset(roots)
        rows = conn.execute(
            "SELECT l.*, a.response FROM v2_container_lineage l JOIN v2_actions a ON a.action_id=l.action_id"
            " WHERE l.socket_digest=? AND a.status='completed' AND a.subject_id='system.port-control'"
            " AND a.subject_type='tool'", (_digest(socket),)).fetchall()
    edges = {}
    for row in rows:
        value = json.loads(row["response"])
        result = value.get("result", {})
        observed = result.get("result", {})
        if (value.get("code") != "OK" or result.get("ok") is not True
                or observed.get("containerId") != row["source_id"]
                or observed.get("replacementId") != row["target_id"]
                or observed.get("outcome") != "observed" or observed.get("originalRetained") is not True):
            continue
        if row["source_id"] in edges:
            raise records.ReplacementError()
        edges[row["source_id"]] = row["target_id"]
    active = set()
    for root in roots:
        current, seen = root, set()
        while current in edges:
            if current in seen:
                raise records.ReplacementError()
            seen.add(current)
            current = edges[current]
        active.add(current)
    # An explicitly listed historical intermediate must not revive a retired node.
    return frozenset(active)


def busy(container_id):
    """A pending/uncertain replacement source is reserved for recovery/execution."""
    if not cp.DB_PATH.exists():
        return False
    with sqlite3.connect(cp.DB_PATH.resolve().as_uri() + "?mode=ro", uri=True) as conn:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='v2_port_replacements'").fetchone():
            return False
        return conn.execute(
            "SELECT 1 FROM v2_port_replacements p JOIN v2_actions a ON p.action_id=a.action_id"
            " WHERE a.status IN ('dispatching','outcome_unknown') AND json_extract(a.args,'$.container_id')=?",
            (container_id,)).fetchone() is not None
