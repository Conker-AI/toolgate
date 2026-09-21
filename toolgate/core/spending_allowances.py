"""Finite owner grants allocating immutable per-root spending ceilings.

An allocation consumes its full ceiling permanently, regardless of actual usage.
Revocation and expiry block new reservations, including unfinished allocated runs.
"""
from __future__ import annotations

import json
import math
import re
import time
import uuid

from toolgate.core import control_plane, spending

SCHEMA = """
CREATE TABLE IF NOT EXISTS v2_spend_allowances (
    allowance_id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, target TEXT NOT NULL,
    per_run_cap INTEGER NOT NULL, total_cap INTEGER NOT NULL,
    max_runs INTEGER NOT NULL, expires_at REAL NOT NULL, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS v2_spend_allowance_allocations (
    job_id TEXT PRIMARY KEY REFERENCES v2_spend_jobs(job_id),
    allowance_id TEXT NOT NULL REFERENCES v2_spend_allowances(allowance_id),
    root_action_id TEXT NOT NULL UNIQUE, cap INTEGER NOT NULL, created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS v2_spend_allowance_allocation_grant
ON v2_spend_allowance_allocations(allowance_id);
CREATE TABLE IF NOT EXISTS v2_spend_allowance_revocations (
    allowance_id TEXT PRIMARY KEY REFERENCES v2_spend_allowances(allowance_id),
    revoked_at REAL NOT NULL
);
"""
for _table, _key in (
    ("v2_spend_allowances", "allowance_id"),
    ("v2_spend_allowance_allocations", "job_id"),
    ("v2_spend_allowance_revocations", "allowance_id"),
):
    SCHEMA += f"""
CREATE TRIGGER IF NOT EXISTS {_table}_no_update BEFORE UPDATE ON {_table}
BEGIN SELECT RAISE(ABORT, 'allowance records are immutable'); END;
CREATE TRIGGER IF NOT EXISTS {_table}_no_delete BEFORE DELETE ON {_table}
BEGIN SELECT RAISE(ABORT, 'allowance records are permanent'); END;
CREATE TRIGGER IF NOT EXISTS {_table}_no_replace BEFORE INSERT ON {_table}
WHEN EXISTS(SELECT 1 FROM {_table} WHERE {_key}=NEW.{_key})
BEGIN SELECT RAISE(ABORT, 'allowance record already exists'); END;
"""
# REPLACE must not be able to remove an allocation by its other unique key.
SCHEMA += """
CREATE TRIGGER IF NOT EXISTS v2_spend_allowance_allocations_no_root_replace
BEFORE INSERT ON v2_spend_allowance_allocations
WHEN EXISTS(SELECT 1 FROM v2_spend_allowance_allocations WHERE root_action_id=NEW.root_action_id)
BEGIN SELECT RAISE(ABORT, 'root allocation already exists'); END;
"""


def initialize(conn) -> None:
    """Initialize before beginning a transaction; enforcement never calls this."""
    spending.initialize(conn)
    conn.executescript(SCHEMA)


def _json_value(value) -> bool:
    if value is None or type(value) in (str, bool, int):
        return True
    if type(value) is float:
        return math.isfinite(value)
    if type(value) is list:
        return all(_json_value(item) for item in value)
    if type(value) is dict:
        return all(type(key) is str and _json_value(item) for key, item in value.items())
    return False


def _target(target) -> str:
    try:
        valid = (type(target) is dict
                 and set(target) == {"kind", "id", "publishedVersion", "digest", "args"}
                 and target["kind"] in ("tool", "automation")
                 and type(target["id"]) is str and bool(target["id"].strip())
                 and type(target["publishedVersion"]) is int and target["publishedVersion"] > 0
                 and type(target["digest"]) is str and bool(target["digest"].strip())
                 and type(target["args"]) is dict and _json_value(target["args"]))
        if valid:
            return json.dumps(target, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        pass
    raise spending.BudgetDenied("Bind the allowance to an exact published target and JSON arguments")


def _policy(conn, cap):
    policy = conn.execute("SELECT * FROM v2_spend_policy WHERE id=1").fetchone()
    if not policy or not policy["enabled"] or cap > policy["max_job_cap"]:
        raise spending.BudgetDenied("Enable a spending policy with a sufficient per-job ceiling first")


def _active(conn, grant):
    if (not grant or grant["expires_at"] <= time.time()
            or conn.execute("SELECT 1 FROM v2_spend_allowance_revocations WHERE allowance_id=?",
                            (grant["allowance_id"],)).fetchone()):
        raise spending.BudgetDenied("The spending allowance is unavailable, expired or revoked")


def _read(conn, allowance_id, actor_id=None):
    row = conn.execute("SELECT * FROM v2_spend_allowances WHERE allowance_id=?", (allowance_id,)).fetchone()
    if not row or (actor_id is not None and actor_id != row["actor_id"]):
        return None
    used = conn.execute("SELECT COUNT(*),COALESCE(SUM(cap),0) FROM v2_spend_allowance_allocations"
                        " WHERE allowance_id=?", (allowance_id,)).fetchone()
    revoked = conn.execute("SELECT revoked_at FROM v2_spend_allowance_revocations WHERE allowance_id=?",
                           (allowance_id,)).fetchone()
    state = ("revoked" if revoked else "expired" if row["expires_at"] <= time.time() else
             "exhausted" if used[0] >= row["max_runs"] or used[1] + row["per_run_cap"] > row["total_cap"]
             else "active")
    return {**dict(row), "target": json.loads(row["target"]), "allocated_runs": used[0],
            "allocated_cap": used[1], "remaining_runs": min(row["max_runs"] - used[0],
                (row["total_cap"] - used[1]) // row["per_run_cap"]),
            "remaining_cap": row["total_cap"] - used[1],
            "revoked_at": revoked[0] if revoked else None, "status": state}


def create(actor_id, target, per_run_cap, total_cap, max_runs, expires_at):
    encoded = _target(target)
    if type(actor_id) is not str or not actor_id.strip():
        raise spending.BudgetDenied("Bind the allowance to an execution identity")
    for value, label in ((per_run_cap, "per_run_cap"), (total_cap, "total_cap"), (max_runs, "max_runs")):
        spending._integer(value, label, 1)
    if per_run_cap > total_cap:
        raise spending.BudgetDenied("The per-run ceiling cannot exceed the allowance total")
    try:
        valid_expiry = (type(expires_at) in (int, float) and math.isfinite(expires_at)
                        and expires_at > time.time())
    except OverflowError:
        valid_expiry = False
    if not valid_expiry:
        raise spending.BudgetDenied("The allowance needs a finite future expiry")
    with control_plane._conn() as conn:
        initialize(conn)
        conn.execute("BEGIN IMMEDIATE")
        _policy(conn, per_run_cap)
        allowance_id = "allowance_" + uuid.uuid4().hex
        conn.execute("INSERT INTO v2_spend_allowances VALUES (?,?,?,?,?,?,?,?)",
                     (allowance_id, actor_id, encoded, per_run_cap, total_cap, max_runs, expires_at, time.time()))
        return _read(conn, allowance_id)


def get(allowance_id, actor_id=None):
    with control_plane._conn() as conn:
        initialize(conn)
        return _read(conn, allowance_id, actor_id)


def revoke(allowance_id):
    with control_plane._conn() as conn:
        initialize(conn)
        conn.execute("BEGIN IMMEDIATE")
        if not _read(conn, allowance_id):
            raise spending.BudgetDenied("The spending allowance is unavailable")
        if not conn.execute("SELECT 1 FROM v2_spend_allowance_revocations WHERE allowance_id=?",
                            (allowance_id,)).fetchone():
            conn.execute("INSERT INTO v2_spend_allowance_revocations VALUES (?,?)", (allowance_id, time.time()))
        return _read(conn, allowance_id)


def allocate(allowance_id, actor_id, root_action_id, target):
    encoded = _target(target)
    if type(root_action_id) is not str or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,160}", root_action_id):
        raise spending.BudgetDenied("Use a stable root action ID of 1-160 ASCII letters, digits or _ . : / -")
    with control_plane._conn() as conn:
        initialize(conn)
        conn.execute("BEGIN IMMEDIATE")
        grant = conn.execute("SELECT * FROM v2_spend_allowances WHERE allowance_id=?", (allowance_id,)).fetchone()
        if not grant or grant["actor_id"] != actor_id or grant["target"] != encoded:
            raise spending.BudgetDenied("The allowance does not match this execution identity and target")
        existing = conn.execute("SELECT * FROM v2_spend_jobs WHERE root_action_id=?", (root_action_id,)).fetchone()
        if existing:
            allocation = conn.execute("SELECT * FROM v2_spend_allowance_allocations WHERE job_id=?",
                                      (existing["job_id"],)).fetchone()
            if not allocation or allocation["allowance_id"] != allowance_id or existing["actor_id"] != actor_id:
                raise spending.BudgetDenied("This root action already belongs to another spending job")
            # A replay returns the same identity even after revocation/expiry. It
            # creates no authority: enforce still blocks any new paid dispatch.
            return {key: existing[key] for key in ("job_id", "actor_id", "root_action_id", "cap")}
        _active(conn, grant)
        _policy(conn, grant["per_run_cap"])
        used = conn.execute("SELECT COUNT(*),COALESCE(SUM(cap),0) FROM v2_spend_allowance_allocations"
                            " WHERE allowance_id=?", (allowance_id,)).fetchone()
        if used[0] >= grant["max_runs"] or used[1] + grant["per_run_cap"] > grant["total_cap"]:
            raise spending.BudgetDenied("The spending allowance has exhausted its run or total ceiling")
        job = {"job_id": "job_" + uuid.uuid4().hex, "actor_id": actor_id,
               "root_action_id": root_action_id, "cap": grant["per_run_cap"]}
        now = time.time()
        conn.execute("INSERT INTO v2_spend_jobs VALUES (?,?,?,?,?)", (*job.values(), now))
        conn.execute("INSERT INTO v2_spend_allowance_allocations VALUES (?,?,?,?,?)",
                     (job["job_id"], allowance_id, root_action_id, job["cap"], now))
        return job


def enforce(conn, job, root_row):
    """Check the journal's actual root, inside its existing reservation transaction."""
    allocation = conn.execute("SELECT * FROM v2_spend_allowance_allocations WHERE job_id=?",
                              (job["job_id"],)).fetchone()
    if not allocation:
        return
    grant = conn.execute("SELECT * FROM v2_spend_allowances WHERE allowance_id=?",
                         (allocation["allowance_id"],)).fetchone()
    _active(conn, grant)
    _policy(conn, job["cap"])
    if (root_row is None or root_row["action_id"] != job["root_action_id"]
            or root_row["actor_id"] != grant["actor_id"] or job["actor_id"] != grant["actor_id"]):
        raise spending.BudgetDenied("The actual execution root does not match the spending allowance")
    try:
        args = json.loads(root_row["args"]) if isinstance(root_row["args"], str) else root_row["args"]
        actual = _target({"kind": root_row["subject_type"], "id": root_row["subject_id"],
                          "publishedVersion": root_row["version"], "digest": root_row["publication_digest"],
                          "args": args})
    except (ValueError, TypeError, KeyError):
        raise spending.BudgetDenied("The actual execution root does not match the spending allowance") from None
    if actual != grant["target"]:
        raise spending.BudgetDenied("The actual execution root does not match the spending allowance")
