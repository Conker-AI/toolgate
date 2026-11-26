"""What the journal keeps of a mail.recent read (core/execution_journal.py, docs/mail.md): the
answer's count, UIDs, UIDVALIDITY and partial flag, marked redacted, never a message. The live
reply and the steps after it in a workflow get the answer itself; a replay, a listing, a lookup,
a recovery receipt and an editor run get the kept form. Step 0002 of the schema ledger redacts
what was kept whole before."""

from __future__ import annotations

import json
import sqlite3

import pytest

from toolgate.core import control_plane, editor_runs, recovery_journal, schema_ledger
from toolgate.core import execution_journal as journal
from toolgate.tests.test_schema_ledger import _schema

SUBJECT = "[UNTRUSTED_MAIL_CONTENT field=subject]\nLunch\n[/UNTRUSTED_MAIL_CONTENT]"
MESSAGE = {"uid": 21, "date": "2026-11-25T08:00:00+00:00", "subject": SUBJECT, "snippet": "noon"}
ANSWER = {
    "connected": True,
    "messages": [MESSAGE, {**MESSAGE, "uid": 20}],
    "source": "imap",
    "partial": True,
    "uid_validity": 3857529045,
}
KEPT = {
    "connected": True,
    "count": 2,
    "uids": [21, 20],
    "uid_validity": 3857529045,
    "partial": True,
    "note": journal.REDACTED_MAIL_NOTE,
    "redacted": True,
}
# The tool envelope as invocation.py writes it: the answer, and its outputs copied beside it.
OUTPUTS = {name: ANSWER[name] for name in ("messages", "connected", "source", "partial")}
ENVELOPE = {
    "code": "OK",
    "message": "Tool completed",
    "result": {"ok": True, "result": ANSWER, **OUTPUTS},
}


@pytest.fixture
def database(tmp_path, monkeypatch):
    path = tmp_path / "gate.db"
    monkeypatch.setattr(control_plane, "DB_PATH", path)
    return path


def kept_whole(action_id: str, response: dict = ENVELOPE) -> None:
    """A receipt as a ToolGate from before redaction kept it."""
    journal.begin(action_id, "tool", "mail.recent", {"hours": 24}, "agent", 1)
    with sqlite3.connect(control_plane.DB_PATH) as db:
        db.execute(
            "UPDATE v2_actions SET status='completed', response=? WHERE action_id=?",
            (json.dumps(response), action_id),
        )


def before_step_two() -> None:
    with sqlite3.connect(control_plane.DB_PATH) as db:
        db.execute("DELETE FROM v2_schema_migrations WHERE id='0002-mail-receipts'")


def stored(table: str, column: str = "response") -> list[str]:
    with sqlite3.connect(control_plane.DB_PATH) as db:
        return [row[0] for row in db.execute(f"SELECT {column} FROM {table}")]


def test_an_answer_is_kept_as_its_count_uids_and_flags():
    assert journal.redact_mail(ANSWER) == KEPT
    unset = {**ANSWER, "connected": False, "messages": [], "note": "Set MAIL_IMAP_HOST."}
    assert journal.redact_mail(unset) == {
        **KEPT,
        "connected": False,
        "count": 0,
        "uids": [],
        "note": "Set MAIL_IMAP_HOST.",
    }
    assert journal.redact_mail(journal.redact_mail(ANSWER)) == KEPT  # once is all it changes


def test_every_copy_in_a_receipt_is_redacted_and_the_rest_kept_as_it_was():
    receipt = {"steps": [{"type": "tool_call", "result": ENVELOPE}], "variables": {"all": ANSWER}}
    original = json.dumps(receipt)
    redacted = journal.redact_mail(receipt)
    assert json.dumps(receipt) == original  # a copy: the live answer is left whole
    step = redacted["steps"][0]["result"]
    assert step["code"] == "OK" and step["result"]["ok"] is True
    assert step["result"]["result"] == KEPT and redacted["variables"]["all"] == KEPT
    assert step["result"] == {"ok": True, "result": KEPT, **KEPT, "uid_validity": None}
    assert "Lunch" not in json.dumps(redacted)
    other = {"source": "imap", "messages": "not a list", "connected": True}
    assert journal.redact_mail(other) == other
    assert journal.kept(json.dumps(other)) == json.dumps(other)


def test_no_depth_of_a_result_stops_the_redaction():
    deep: dict = {"answer": ANSWER}
    for _ in range(5000):
        deep = {"inner": [deep]}
    redacted = journal.redact_mail(deep)
    for _ in range(5000):
        redacted = redacted["inner"][0]
    assert redacted == {"answer": KEPT}


def test_finish_answers_live_and_keeps_the_redacted_form(database):
    journal.begin("mail-1", "tool", "mail.recent", {"hours": 24}, "agent", 1)
    record = journal.finish("mail-1", ENVELOPE)
    assert record["response"] == ENVELOPE  # the live reply, and the next workflow step
    kept = {**ENVELOPE, "result": {"ok": True, "result": KEPT, **KEPT, "uid_validity": None}}
    assert journal.get("mail-1")["response"] == kept
    assert journal.response(journal.get("mail-1"))["result"]["result"] == KEPT
    assert [row["response"] for row in journal.list_actions()] == [kept]
    assert journal.finish("mail-1", ENVELOPE)["response"] == kept  # finished: the kept one
    assert "Lunch" not in "".join(stored("v2_actions"))


def test_a_receipt_without_mail_is_kept_byte_for_byte(database):
    journal.begin("echo-1", "tool", "echo", {}, "agent", 1)
    response = {"code": "OK", "result": {"ok": True, "result": {"x": 1.5, "imap": "word"}}}
    journal.finish("echo-1", response)
    assert stored("v2_actions") == [json.dumps(response)]


def test_an_editor_run_keeps_the_redacted_form_and_answers_live(database):
    with control_plane._conn() as conn:
        editor_runs._table(conn)
        conn.execute(
            "INSERT INTO v2_editor_runs VALUES ('run-1','d','agent',1,'x','{}','held',NULL,'t')"
        )
    assert editor_runs.finish("run-1", ENVELOPE) == ENVELOPE
    [kept] = [json.loads(text) for text in stored("v2_editor_runs")]
    assert kept["result"]["result"] == KEPT and "Lunch" not in json.dumps(kept)


def test_step_two_redacts_what_was_kept_whole_and_only_once(database):
    kept_whole("mail-old")
    with control_plane._conn() as conn:
        editor_runs._table(conn)
        conn.execute(
            "INSERT INTO v2_editor_runs VALUES ('run-1','d','agent',1,'x','{}','finished',?,'t')",
            (json.dumps(ENVELOPE),),
        )
        record = dict(conn.execute("SELECT * FROM v2_actions").fetchone())
        conn.execute(
            "INSERT INTO v2_recovery_receipts VALUES ('mail-old', ?)",
            (json.dumps(record, sort_keys=True),),
        )
    shape = _schema(database)
    before_step_two()
    with control_plane._conn():
        pass  # a new connection runs the missing step
    assert "Lunch" not in "".join(stored("v2_actions") + stored("v2_editor_runs"))
    assert "Lunch" not in "".join(stored("v2_recovery_receipts", "record"))
    assert journal.get("mail-old")["response"]["result"]["result"] == KEPT
    assert json.loads(stored("v2_editor_runs")[0])["result"]["result"] == KEPT
    # The schema is as it was, the completed receipt as immutable as before.
    assert _schema(database) == shape
    with sqlite3.connect(database) as db:
        steps = [row[0] for row in db.execute("SELECT id FROM v2_schema_migrations ORDER BY id")]
        assert steps == list(schema_ledger.STEPS)
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute("UPDATE v2_actions SET response='{}' WHERE action_id='mail-old'")
    # Run again, it finds nothing left to change and writes nothing.
    with sqlite3.connect(database) as db:
        seen: list[str] = []
        db.set_trace_callback(seen.append)
        journal.redact_kept_mail(db)
    assert not [s for s in seen if s.lstrip().upper().startswith(("BEGIN", "UPDATE", "DROP"))]


def test_step_two_leaves_a_forgotten_action_alone_and_still_runs(database):
    kept_whole("mail-old")
    kept_whole("mail-gone")
    with sqlite3.connect(database) as db:
        db.execute("INSERT INTO v2_forgotten VALUES ('action','mail-gone','t','owner')")
    before_step_two()
    with control_plane._conn():
        pass
    assert journal.get("mail-old")["response"]["result"]["result"] == KEPT
    # A trigger keeps a forgotten action as it is; forgetting, not this step, blanks it.
    assert journal.get("mail-gone")["response"] == ENVELOPE


def test_step_two_stopped_midway_changes_nothing(database):
    kept_whole("mail-old")
    before_step_two()
    db = sqlite3.connect(database)

    class Stops:
        def __getattr__(self, name):
            return getattr(db, name)

        def executemany(self, sql, rows):
            if sql.startswith("UPDATE v2_actions"):
                raise KeyboardInterrupt  # the process stopped after the trigger was dropped
            return db.executemany(sql, rows)

    with pytest.raises(KeyboardInterrupt):
        journal.redact_kept_mail(Stops())
    db.close()  # never committed
    with sqlite3.connect(database) as check:
        names = {row[0] for row in check.execute("SELECT name FROM sqlite_master")}
        assert "v2_action_result_fixed" in names
    assert "Lunch" in "".join(stored("v2_actions"))
    with control_plane._conn():
        pass  # the next connection runs the step again, whole
    assert journal.get("mail-old")["response"]["result"]["result"] == KEPT


@pytest.mark.parametrize("redacted", ["authoritative", "restored"])
def test_recovery_takes_a_receipt_kept_whole_and_its_redacted_form_as_one(
    tmp_path, database, redacted
):
    kept_whole("mail-old")
    restored = tmp_path / "restored.db"
    with sqlite3.connect(database) as src, sqlite3.connect(restored) as dst:
        src.backup(dst)
    if redacted == "authoritative":
        before_step_two()
        with control_plane._conn():
            pass
    else:
        with sqlite3.connect(restored) as db:
            db.execute("DROP TRIGGER v2_action_result_fixed")
            db.execute("UPDATE v2_actions SET response=?", (journal.kept(json.dumps(ENVELOPE)),))
    result = recovery_journal.reconcile(database, restored)
    assert result["receipts"] == 1
    with sqlite3.connect(restored) as db:
        [record] = [
            json.loads(row[0]) for row in db.execute("SELECT record FROM v2_recovery_receipts")
        ]
    assert "Lunch" not in record["response"]
    assert json.loads(record["response"])["result"]["result"] == KEPT


def test_recovery_still_refuses_receipts_that_differ_in_what_was_kept(tmp_path, database):
    kept_whole("mail-old")
    restored = tmp_path / "restored.db"
    with sqlite3.connect(database) as src, sqlite3.connect(restored) as dst:
        src.backup(dst)
    other = {**ENVELOPE, "result": {**ENVELOPE["result"], "result": {**ANSWER, "messages": []}}}
    with sqlite3.connect(restored) as db:
        db.execute("DROP TRIGGER v2_action_result_fixed")
        db.execute("UPDATE v2_actions SET response=?", (json.dumps(other),))
    with pytest.raises(ValueError, match="receipts conflict"):
        recovery_journal.reconcile(database, restored)
