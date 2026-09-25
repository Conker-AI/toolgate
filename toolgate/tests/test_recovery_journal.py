import sqlite3

import pytest

from toolgate.api import server
from toolgate.core import control_plane, recovery_journal
from toolgate.core import execution_journal as journal


@pytest.fixture
def databases(tmp_path, monkeypatch):
    source, target = tmp_path / "current.db", tmp_path / "restored.db"
    monkeypatch.setattr(control_plane, "DB_PATH", source)
    journal.begin("before", "tool", "post", {}, "agent", 1)
    with sqlite3.connect(source) as src, sqlite3.connect(target) as dst:
        src.backup(dst)
    return source, target


def test_completed_and_new_receipts_replay_without_dispatch(databases, monkeypatch):
    source, target = databases
    receipt = {"ok": True, "receipt": "posted"}
    journal.finish("before", receipt)
    journal.begin("after", "tool", "post", {"next": True}, "agent", 1)
    journal.finish("after", receipt)
    result = recovery_journal.reconcile(source, target)
    assert result == {"recoveryHeld": True, "receipts": 2, "unresolved": [],
                      "promotesRecovery": False, "spendingReconciled": False}
    assert recovery_journal.reconcile(source, target) == result
    monkeypatch.setattr(control_plane, "DB_PATH", target)
    for identity, args in [("before", {}), ("after", {"next": True})]:
        record, dispatched = journal.begin(identity, "tool", "post", args, "agent", 1,
            authorize=lambda _: pytest.fail("must not authorize again"),
            reserve=lambda _: pytest.fail("must not reserve again"))
        assert not dispatched
        assert record["response"] == receipt
        assert journal.existing(identity, "tool", "post", args, "agent") == record
        assert journal.get(identity) == record
    assert {row["action_id"] for row in journal.list_actions()} == {"before", "after"}
    with sqlite3.connect(target) as db:
        assert db.execute("SELECT status FROM v2_actions WHERE action_id='before'").fetchone()[0] == "dispatching"
    with pytest.raises(journal.ExecutionConflict, match="held"):
        journal.begin("fresh", "tool", "post", {}, "agent", 1)
    monkeypatch.setattr(control_plane, "purge_legacy_state", lambda: pytest.fail("startup must stop first"))
    with pytest.raises(ValueError, match="held"):
        server.startup()
    with pytest.raises(ValueError, match="held"):
        journal.finish("before", {})


def test_unresolved_stays_unknown(databases, monkeypatch):
    source, target = databases
    assert recovery_journal.reconcile(source, target)["unresolved"] == ["before"]
    monkeypatch.setattr(control_plane, "DB_PATH", target)
    record, dispatched = journal.begin("before", "tool", "post", {}, "agent", 1)
    assert not dispatched
    assert journal.response(record)["code"] == "OUTCOME_UNKNOWN"


def test_older_source_fails_and_leaves_hold(databases, monkeypatch):
    source, target = databases
    monkeypatch.setattr(control_plane, "DB_PATH", target)
    journal.begin("uncovered", "tool", "post", {}, "agent", 1)
    with pytest.raises(ValueError, match="cover"):
        recovery_journal.reconcile(source, target)
    with sqlite3.connect(target) as db:
        assert db.execute("SELECT count(*) FROM v2_recovery_receipts").fetchone()[0] == 0
        with pytest.raises(ValueError, match="held"):
            recovery_journal.assert_not_held(db)


def test_conflicting_completed_receipts_fail(databases, monkeypatch):
    source, target = databases
    journal.finish("before", {"receipt": "one"})
    monkeypatch.setattr(control_plane, "DB_PATH", target)
    journal.finish("before", {"receipt": "two"})
    # Ensure freshness is not the reason for rejection.
    with sqlite3.connect(source) as db:
        db.execute("DROP TRIGGER v2_action_result_immutable")
        db.execute("UPDATE v2_actions SET updated_at=updated_at+60")
    with pytest.raises(ValueError, match="conflict"):
        recovery_journal.reconcile(source, target)


def test_held_source_is_not_authoritative(databases):
    source, target = databases
    with sqlite3.connect(source) as db:
        db.execute("INSERT INTO v2_recovery_hold VALUES (1)")
    with pytest.raises(ValueError, match="held"):
        recovery_journal.reconcile(source, target)
