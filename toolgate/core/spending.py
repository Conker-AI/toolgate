"""Owner budgets in integer microdollars; unresolved requests keep their reservation.

The journal calls reserve and reconcile inside its own transaction. There is no
independent counter to refund or reset after a dispatch whose outcome is unknown.
"""
from __future__ import annotations

import json
import time
import uuid

from toolgate.core import control_plane

SCHEMA = """
CREATE TABLE IF NOT EXISTS v2_spend_policy (
    id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL DEFAULT 0,
    cumulative_cap INTEGER NOT NULL, max_job_cap INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS v2_spend_prices (
    model TEXT PRIMARY KEY, input_per_million INTEGER NOT NULL,
    output_per_million INTEGER NOT NULL, valid_until REAL NOT NULL, source TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS v2_spend_jobs (
    job_id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, root_action_id TEXT NOT NULL UNIQUE,
    cap INTEGER NOT NULL, created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS v2_spend_reservations (
    action_id TEXT PRIMARY KEY REFERENCES v2_actions(action_id),
    job_id TEXT NOT NULL REFERENCES v2_spend_jobs(job_id),
    reserved INTEGER NOT NULL, accounted INTEGER, quote TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS v2_spend_releases (
    action_id TEXT PRIMARY KEY, evidence TEXT NOT NULL, released_at REAL NOT NULL,
    actor TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS v2_spend_release_disputes (action_id TEXT PRIMARY KEY);
CREATE TRIGGER IF NOT EXISTS v2_spend_releases_no_update BEFORE UPDATE ON v2_spend_releases
BEGIN SELECT RAISE(ABORT, 'release receipts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS v2_spend_releases_no_delete BEFORE DELETE ON v2_spend_releases
BEGIN SELECT RAISE(ABORT, 'release receipts are permanent'); END;
CREATE TRIGGER IF NOT EXISTS v2_spend_releases_no_replace BEFORE INSERT ON v2_spend_releases
WHEN EXISTS(SELECT 1 FROM v2_spend_releases WHERE action_id=NEW.action_id)
BEGIN SELECT RAISE(ABORT, 'release receipt already exists'); END;
CREATE VIEW IF NOT EXISTS v2_spend_effective AS
SELECT r.*, COALESCE(r.accounted, CASE WHEN o.action_id IS NOT NULL AND d.action_id IS NULL
    THEN 0 ELSE r.reserved END) AS effective
FROM v2_spend_reservations r LEFT JOIN v2_spend_releases o USING(action_id)
LEFT JOIN v2_spend_release_disputes d USING(action_id);
CREATE TRIGGER IF NOT EXISTS v2_spend_jobs_no_update BEFORE UPDATE ON v2_spend_jobs
BEGIN SELECT RAISE(ABORT, 'job ceilings and identity are immutable'); END;
CREATE TRIGGER IF NOT EXISTS v2_spend_jobs_no_delete BEFORE DELETE ON v2_spend_jobs
BEGIN SELECT RAISE(ABORT, 'spend jobs are permanent'); END;
CREATE TRIGGER IF NOT EXISTS v2_spend_jobs_no_replace BEFORE INSERT ON v2_spend_jobs
WHEN EXISTS(SELECT 1 FROM v2_spend_jobs WHERE job_id=NEW.job_id OR root_action_id=NEW.root_action_id)
BEGIN SELECT RAISE(ABORT, 'spend jobs are permanent'); END;
CREATE TRIGGER IF NOT EXISTS v2_spend_reservations_no_delete BEFORE DELETE ON v2_spend_reservations
BEGIN SELECT RAISE(ABORT, 'spend reservations are permanent'); END;
CREATE TRIGGER IF NOT EXISTS v2_spend_reservations_no_replace BEFORE INSERT ON v2_spend_reservations
WHEN EXISTS(SELECT 1 FROM v2_spend_reservations WHERE action_id=NEW.action_id)
BEGIN SELECT RAISE(ABORT, 'spend reservations are permanent'); END;
CREATE TRIGGER IF NOT EXISTS v2_spend_reservations_immutable BEFORE UPDATE ON v2_spend_reservations
WHEN NEW.action_id IS NOT OLD.action_id OR NEW.job_id IS NOT OLD.job_id
  OR NEW.reserved IS NOT OLD.reserved OR NEW.quote IS NOT OLD.quote OR OLD.accounted IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'reservation identity and reconciled usage are immutable'); END;
"""

# One adapter with an enforceable text-only request contract. Other paid routes
# remain disabled until their own ceilings and usage reconciliation are implemented.
MODEL = "gemini-2.5-flash-lite"
MAX_INPUT_TOKENS = 1_048_576


class BudgetDenied(ValueError):
    pass


def initialize(conn) -> None:
    from toolgate.core import spending_allowances
    conn.executescript(SCHEMA)
    conn.executescript(spending_allowances.SCHEMA)


def _integer(value, label: str, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= 10**15:
        raise BudgetDenied(f"{label} must be an integer from {minimum} to 10^15 microdollars/tokens")
    return value


def configure(enabled: bool, cumulative_cap: int, max_job_cap: int) -> dict:
    _integer(cumulative_cap, "cumulative_cap", 1)
    _integer(max_job_cap, "max_job_cap", 1)
    if max_job_cap > cumulative_cap:
        raise BudgetDenied("The per-job ceiling cannot exceed the cumulative ceiling")
    with control_plane._conn() as conn:
        initialize(conn)
        conn.execute("INSERT INTO v2_spend_policy VALUES (1,?,?,?) ON CONFLICT(id) DO UPDATE SET"
                     " enabled=excluded.enabled,cumulative_cap=excluded.cumulative_cap,"
                     " max_job_cap=excluded.max_job_cap", (int(enabled), cumulative_cap, max_job_cap))
    return status()


def set_price(model: str, input_per_million: int, output_per_million: int,
              valid_until: float, source: str) -> None:
    if model != MODEL:
        raise BudgetDenied("This model has no supported bounded paid adapter")
    _integer(input_per_million, "input_per_million", 1)
    _integer(output_per_million, "output_per_million", 1)
    if not time.time() < valid_until <= time.time() + 86400 or not source.startswith("https://"):
        raise BudgetDenied("Record a pricing source and an expiry within the next 24 hours")
    with control_plane._conn() as conn:
        initialize(conn)
        conn.execute("INSERT INTO v2_spend_prices VALUES (?,?,?,?,?) ON CONFLICT(model) DO UPDATE SET"
                     " input_per_million=excluded.input_per_million,"
                     " output_per_million=excluded.output_per_million,"
                     " valid_until=excluded.valid_until,source=excluded.source",
                     (model, input_per_million, output_per_million, valid_until, source))


def create_job(actor_id: str, root_action_id: str, cap: int) -> dict:
    _integer(cap, "job cap", 1)
    if not actor_id or not root_action_id:
        raise BudgetDenied("Bind the job to an execution key and a stable root action ID")
    with control_plane._conn() as conn:
        initialize(conn)
        conn.execute("BEGIN IMMEDIATE")
        policy = conn.execute("SELECT * FROM v2_spend_policy WHERE id=1").fetchone()
        if not policy or not policy["enabled"] or cap > policy["max_job_cap"]:
            raise BudgetDenied("Enable a spending policy with a sufficient per-job ceiling first")
        job_id = "job_" + uuid.uuid4().hex
        conn.execute("INSERT INTO v2_spend_jobs VALUES (?,?,?,?,?)",
                     (job_id, actor_id, root_action_id, cap, time.time()))
        return {"job_id": job_id, "actor_id": actor_id, "root_action_id": root_action_id, "cap": cap}


def quote(model: str, max_output_tokens: int) -> dict:
    if model != MODEL or type(max_output_tokens) is not int or not 128 <= max_output_tokens <= 2048:
        raise BudgetDenied("Paid adapter requires gemini-2.5-flash-lite and 128-2048 output tokens")
    with control_plane._conn() as conn:
        initialize(conn)
        policy = conn.execute("SELECT * FROM v2_spend_policy WHERE id=1").fetchone()
        price = conn.execute("SELECT * FROM v2_spend_prices WHERE model=?", (model,)).fetchone()
        if not policy or not policy["enabled"]:
            raise BudgetDenied("Paid routes are disabled; the owner must configure both spending ceilings")
        if not price or price["valid_until"] <= time.time():
            raise BudgetDenied("Pricing is unknown or expired; the owner must record current prices")
        # Reserve the provider's entire enforced input window, not an optimistic
        # character/token estimate. Short prompts still remain under this ceiling.
        return {**dict(price), "max_input_tokens": MAX_INPUT_TOKENS,
                "max_output_tokens": max_output_tokens}


def amount(price: dict, input_tokens: int, output_tokens: int) -> int:
    return (input_tokens * price["input_per_million"]
            + output_tokens * price["output_per_million"] + 999_999) // 1_000_000


def reserve(conn, action_id: str, job_id: str | None, actor_id: str,
            parent_action_id: str | None, price: dict) -> None:
    policy = conn.execute("SELECT * FROM v2_spend_policy WHERE id=1").fetchone()
    job = conn.execute("SELECT * FROM v2_spend_jobs WHERE job_id=?", (job_id,)).fetchone()
    if not policy or not policy["enabled"] or price["valid_until"] <= time.time():
        raise BudgetDenied("Paid dispatch is disabled or its price expired before reservation")
    current_price = conn.execute("SELECT * FROM v2_spend_prices WHERE model=?", (price["model"],)).fetchone()
    # sqlite3.Row iterates values, not keys: .keys() is required here.
    if not current_price or any(price[key] != current_price[key] for key in current_price.keys()):  # noqa: SIM118
        raise BudgetDenied("Pricing changed before reservation; request a fresh quote")
    if not job or job["actor_id"] != actor_id:
        raise BudgetDenied("Use the owner's job for this exact agent and root action")
    root = action_id
    if parent_action_id:
        parent = conn.execute("SELECT * FROM v2_actions WHERE action_id=?", (parent_action_id,)).fetchone()
        if not parent or parent["job_id"] != job_id or parent["actor_id"] != actor_id:
            raise BudgetDenied("A child must inherit its parent's spending job")
        root = parent["action_id"]
        while parent["parent_action_id"]:
            parent = conn.execute("SELECT * FROM v2_actions WHERE action_id=?",
                                  (parent["parent_action_id"],)).fetchone()
            root = parent["action_id"]
    if root != job["root_action_id"]:
        raise BudgetDenied("Child spending belongs to another root job")
    from toolgate.core import spending_allowances
    spending_allowances.enforce(conn, job, conn.execute(
        "SELECT * FROM v2_actions WHERE action_id=?", (root,)).fetchone())
    reserved = amount(price, price["max_input_tokens"], price["max_output_tokens"])
    used = conn.execute("SELECT COALESCE(SUM(effective),0)"
                        " FROM v2_spend_effective").fetchone()[0]
    job_used = conn.execute("SELECT COALESCE(SUM(effective),0)"
                            " FROM v2_spend_effective WHERE job_id=?", (job_id,)).fetchone()[0]
    if used + reserved > policy["cumulative_cap"] or job_used + reserved > job["cap"]:
        raise BudgetDenied("The conservative reservation exceeds the job or cumulative spending ceiling")
    conn.execute("INSERT INTO v2_spend_reservations VALUES (?,?,?,NULL,?)",
                 (action_id, job_id, reserved, json.dumps(price)))


def reconcile(conn, action_id: str, usage: dict | None) -> None:
    row = conn.execute("SELECT * FROM v2_spend_reservations WHERE action_id=?", (action_id,)).fetchone()
    if not row:
        return
    if conn.execute("SELECT 1 FROM v2_spend_releases WHERE action_id=?", (action_id,)).fetchone():
        # A late provider reply contradicts the owner's no-effect assertion. Restore
        # conservative accounting and freeze paid work instead of trusting the release.
        conn.execute("INSERT INTO v2_spend_release_disputes VALUES (?) ON CONFLICT DO NOTHING", (action_id,))
        conn.execute("UPDATE v2_spend_policy SET enabled=0 WHERE id=1")
    price = json.loads(row["quote"])
    usage = usage or {}
    incoming, outgoing = usage.get("prompt_tokens"), usage.get("completion_tokens")
    total, thoughts = usage.get("total_tokens"), usage.get("thought_tokens")
    if (type(incoming) is not int or type(outgoing) is not int or type(total) is not int
            or incoming < 0 or outgoing < 0 or total != incoming + outgoing or type(thoughts) is not int or thoughts != 0):
        # Missing billing telemetry is never interpreted as a free request.
        return
    actual = amount(price, incoming, outgoing)
    if incoming > price["max_input_tokens"] or outgoing > price["max_output_tokens"]:
        conn.execute("UPDATE v2_spend_policy SET enabled=0 WHERE id=1")
        actual = max(actual, row["reserved"])
    conn.execute("UPDATE v2_spend_reservations SET accounted=? WHERE action_id=?", (actual, action_id))


def status() -> dict:
    with control_plane._conn() as conn:
        initialize(conn)
        policy = conn.execute("SELECT * FROM v2_spend_policy WHERE id=1").fetchone()
        used = conn.execute("SELECT COALESCE(SUM(effective),0),"
                            " COALESCE(SUM(CASE WHEN accounted IS NULL THEN effective ELSE 0 END),0)"
                            " FROM v2_spend_effective").fetchone()
        return {"policy": dict(policy) if policy else {"enabled": 0},
                "accounted_and_reserved_microusd": used[0], "held_microusd": used[1]}


def release_hold(action_id: str, evidence: str, confirmed_not_executed: bool) -> dict:
    from toolgate.core import execution_journal

    if confirmed_not_executed is not True or not isinstance(evidence, str) or not 10 <= len(evidence.strip()) <= 2000:
        raise BudgetDenied("Confirm the action did not execute and record how you checked with the provider")
    with control_plane._conn() as conn:
        execution_journal.initialize(conn)
        conn.execute("BEGIN IMMEDIATE")
        action = conn.execute("SELECT * FROM v2_actions WHERE action_id=?", (action_id,)).fetchone()
        row = conn.execute("SELECT * FROM v2_spend_reservations WHERE action_id=?", (action_id,)).fetchone()
        if not action or action["status"] != "outcome_unknown" or not row or row["accounted"] is not None:
            raise BudgetDenied("Only an unresolved held action can be released; verify its outcome first")
        if conn.execute("SELECT 1 FROM v2_spend_release_disputes WHERE action_id=?", (action_id,)).fetchone():
            raise BudgetDenied("A provider reply disputed this release; reconcile externally before changing the policy")
        previous = conn.execute("SELECT * FROM v2_spend_releases WHERE action_id=?", (action_id,)).fetchone()
        if previous:
            if previous["evidence"] != evidence.strip():
                raise BudgetDenied("This release already has an immutable owner receipt")
            return {**dict(previous), "status": "local_hold_released", "released_microusd": row["reserved"]}
        conn.execute("INSERT INTO v2_spend_releases VALUES (?,?,?,?)",
                     (action_id, evidence.strip(), time.time(), "owner"))
        receipt = dict(conn.execute("SELECT * FROM v2_spend_releases WHERE action_id=?", (action_id,)).fetchone())
        return {**receipt, "status": "local_hold_released", "released_microusd": row["reserved"]}


def agent_job(job_id: str, actor_id: str) -> dict | None:
    """Read only this execution identity's budget; never issue new authority."""
    with control_plane._conn() as conn:
        initialize(conn)
        row = conn.execute(
            "SELECT job_id,root_action_id,cap FROM v2_spend_jobs WHERE job_id=? AND actor_id=?",
            (job_id, actor_id),
        ).fetchone()
        return dict(row) if row else None
