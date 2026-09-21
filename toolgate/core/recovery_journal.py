"""Offline authoritative receipt overlay. Never replays effects or releases a hold."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS v2_recovery_hold(id INTEGER PRIMARY KEY CHECK(id=1));
CREATE TABLE IF NOT EXISTS v2_recovery_receipts(action_id TEXT PRIMARY KEY, record TEXT NOT NULL);
"""


def lookup(conn, action_id):
    row = conn.execute("SELECT record FROM v2_recovery_receipts WHERE action_id=?", (action_id,)).fetchone()
    return json.loads(row[0]) if row else conn.execute(
        "SELECT * FROM v2_actions WHERE action_id=?", (action_id,)).fetchone()


def assert_not_held(conn):
    exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='v2_recovery_hold'").fetchone()
    if exists and conn.execute("SELECT 1 FROM v2_recovery_hold").fetchone():
        raise ValueError("Recovery is held; keep ToolGate stopped for reconciliation.")


def reconcile(source_path, target_path):
    from toolgate.core import execution_journal as journal
    source_path, target_path = Path(source_path).resolve(), Path(target_path).resolve()
    if source_path == target_path or not source_path.is_file() or not target_path.is_file():
        raise ValueError("Use separate existing authoritative and recovery databases.")
    with (closing(sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True)) as source,
          closing(sqlite3.connect(target_path.as_uri() + "?mode=rw", uri=True)) as target):
        source.row_factory = target.row_factory = sqlite3.Row
        source.execute("BEGIN")
        target.executescript(SCHEMA)
        target.execute("INSERT OR IGNORE INTO v2_recovery_hold VALUES (1)")
        target.commit()
        target.execute("BEGIN IMMEDIATE")
        try:
            assert_not_held(source)
            if source.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("Authoritative journal integrity check failed.")
            newer = {row["action_id"]: dict(row) for row in source.execute("SELECT * FROM v2_actions")}
            for row in newer.values():
                expected = journal.fingerprint(row["subject_type"], row["subject_id"],
                    json.loads(row["args"]), row["actor_id"], row["job_id"], row["parent_action_id"],
                    row["publication_digest"])
                if expected != row["fingerprint"] or row["status"] not in ("completed", "dispatching", "outcome_unknown"):
                    raise ValueError("Authoritative action identity is inconsistent.")
                if row["status"] == "completed" and not isinstance(json.loads(row["response"]), dict):
                    raise ValueError("Authoritative completed receipt is missing.")
                if row["parent_action_id"] and row["parent_action_id"] not in newer:
                    raise ValueError("Authoritative journal has a missing parent.")
            old = {row["action_id"]: dict(row) for row in target.execute("SELECT * FROM v2_actions")}
            old.update({row["action_id"]: json.loads(row["record"]) for row in target.execute("SELECT * FROM v2_recovery_receipts")})
            for identity, row in old.items():
                current = newer.get(identity)
                keys = ("fingerprint", "actor_id", "subject_type", "subject_id", "version", "job_id", "parent_action_id", "publication_digest", "created_at")
                if not current or any(row[key] != current[key] for key in keys):
                    raise ValueError("Authoritative journal does not cover the restored identities.")
                if current["updated_at"] < row["updated_at"]:
                    raise ValueError("Supplied journal is older than restored evidence.")
                if row["status"] == "completed" and (current["status"] != "completed" or
                        json.loads(row["response"]) != json.loads(current["response"])):
                    raise ValueError("Completed action receipts conflict.")
            for identity, row in newer.items():
                if row["status"] == "dispatching":
                    row["status"] = "outcome_unknown"
                target.execute("INSERT INTO v2_recovery_receipts VALUES (?,?) "
                    "ON CONFLICT(action_id) DO UPDATE SET record=excluded.record",
                    (identity, json.dumps(row, sort_keys=True)))
            target.commit()
            return {"recoveryHeld": True, "receipts": len(newer),
                    "unresolved": sorted(key for key, row in newer.items() if row["status"] != "completed"),
                    "promotesRecovery": False, "spendingReconciled": False}
        except BaseException:
            target.rollback()
            raise


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    try:
        result = reconcile(args.source, args.target)
    except (ValueError, TypeError, KeyError, sqlite3.Error):
        parser.exit(1, "Receipt reconciliation failed; keep recovery services stopped.\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
