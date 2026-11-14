"""Forgetting, hunt 2 (context/reviews/2026-11-14/hunt2/toolgate-forget.md): the reviewer's
words, a late editor-run write, receipt-only children, a running parent and a forged receipt."""

import json
import shutil
import sqlite3

import pytest

from toolgate.core import control_plane as cp
from toolgate.core import editor_runs, forgetting, recovery_journal
from toolgate.core import execution_journal as journal
from toolgate.tests.test_forget_records import (  # noqa: F401
    OWNER_HEADERS,
    SECRET,
    agent,
    api,
    forget,
    stored,
)


def test_forgetting_an_action_drops_the_reviewers_words_about_it(api):
    client, pi_key, _ = api
    delegate = client.post("/v2/owner/access/delegate", json={"enabled": True},
                           headers={**OWNER_HEADERS, **agent(pi_key)})
    assert delegate.status_code == 200, delegate.text
    response = client.post("/v2/tools/echo.ask/invoke", headers=agent(pi_key), json={
        "args": {"value": "hi"}, "action_id": "rev-1",
        "decision": {"outcome": "run", "decided_by": "ai_reviewer", "reason": f"Fine: {SECRET}"}})
    assert response.json().get("status") == "completed", response.text
    assert SECRET in stored("v2_events")
    assert forget(client, pi_key, actions=["rev-1"])["actions"]["forgotten"] == ["rev-1"]
    assert SECRET not in stored("v2_events")
    decided = cp.events(event_type="action_decided")[0]["payload"]
    assert decided["decided_by"] == "ai_reviewer" and decided["action_id"] == "rev-1"


def test_an_editor_run_finishing_after_its_forget_does_not_write_its_result_back(api):
    _client, pi_key, _ = api
    agent_id = cp.authenticate_agent(pi_key)["id"]
    with cp._conn() as conn:
        editor_runs._table(conn)
        conn.execute("INSERT INTO v2_editor_runs VALUES(?,?,?,?,?,?,?,?,?)",
                     ("run-1", "draft", agent_id, 1, "d", json.dumps({"value": SECRET}), "held", None, "now"))
    journal.begin("run-1", "automation", "draft", {"value": SECRET}, agent_id, 1)
    journal.finish("run-1", {"ok": True, "proof": SECRET})
    assert forgetting.forget([], ["run-1"], "Pi", agent_id)["actions"]["forgotten"] == ["run-1"]
    assert SECRET not in stored("v2_editor_runs", "v2_actions")
    editor_runs.finish("run-1", {"ok": True, "proof": SECRET, "action_id": "run-1"})
    assert SECRET not in stored("v2_editor_runs")


def test_a_child_known_only_by_its_recovery_receipt_is_blanked_with_its_root(api):
    _client, pi_key, _ = api
    agent_id = cp.authenticate_agent(pi_key)["id"]
    journal.begin("root", "automation", "flow", {"value": SECRET}, agent_id, 1)
    journal.finish("root", {"ok": True, "proof": SECRET})
    child = {"action_id": "child", "parent_action_id": "root", "status": "completed", "actor_id": agent_id,
             "subject_type": "tool", "subject_id": "echo.free", "args": json.dumps({"value": SECRET}),
             "response": json.dumps({"ok": True, "proof": SECRET})}
    with cp._conn() as conn:
        conn.executescript(recovery_journal.SCHEMA)
        conn.execute("INSERT INTO v2_recovery_receipts VALUES(?,?)", ("child", json.dumps(child)))
    result = forgetting.forget([], ["root"], "Pi", agent_id)
    assert result["actions"]["forgotten"] == ["root"]
    assert SECRET not in stored("v2_actions", "v2_recovery_receipts")


def test_a_receipt_only_child_still_running_holds_back_its_root(api):
    _client, pi_key, _ = api
    agent_id = cp.authenticate_agent(pi_key)["id"]
    journal.begin("root", "automation", "flow", {"value": SECRET}, agent_id, 1)
    journal.finish("root", {"ok": True})
    child = {"action_id": "child", "parent_action_id": "root", "status": "dispatching",
             "actor_id": agent_id, "args": json.dumps({"value": SECRET})}
    with cp._conn() as conn:
        conn.executescript(recovery_journal.SCHEMA)
        conn.execute("INSERT INTO v2_recovery_receipts VALUES(?,?)", ("child", json.dumps(child)))
    result = forgetting.forget([], ["root"], "Pi", agent_id)
    assert result["actions"]["refused"] == [{"id": "root", "code": "still_running"}]


def test_a_child_of_a_running_workflow_is_refused_until_the_workflow_ends(api):
    _client, pi_key, _ = api
    agent_id = cp.authenticate_agent(pi_key)["id"]
    journal.begin("root", "automation", "flow", {"value": SECRET}, agent_id, 1)
    journal.begin("child", "tool", "echo.free", {"value": SECRET}, agent_id, 1, parent_action_id="root")
    journal.finish("child", {"ok": True, "proof": SECRET})
    result = forgetting.forget([], ["child"], "Pi", agent_id)
    assert result["actions"]["refused"] == [{"id": "child", "code": "still_running"}]
    assert journal.get("child")["args"] == {"value": SECRET}
    journal.finish("root", {"ok": True})
    assert forgetting.forget([], ["child"], "Pi", agent_id)["actions"]["forgotten"] == ["child"]


def test_a_forgotten_row_does_not_excuse_a_rewritten_response(tmp_path, monkeypatch):
    source, target = tmp_path / "source.db", tmp_path / "target.db"
    monkeypatch.setattr(cp, "DB_PATH", source)
    journal.begin("kept", "tool", "post", {"value": "x"}, "agent", 1)
    journal.finish("kept", {"ok": True})
    shutil.copyfile(source, target)
    with sqlite3.connect(source) as db:
        db.execute("INSERT INTO v2_forgotten VALUES('action','kept','now','someone')")
        for name in ("v2_action_identity_fixed", "v2_action_result_fixed", "v2_action_forgotten_stays"):
            db.execute(f"DROP TRIGGER {name}")
        db.execute("UPDATE v2_actions SET response=?, updated_at=updated_at+60 WHERE action_id='kept'",
                   (json.dumps({"ok": True, "proof": "rewritten"}),))
    with pytest.raises(ValueError, match="conflict"):
        recovery_journal.reconcile(source, target)


def test_an_action_that_asked_and_never_ran_loses_the_reviewers_words_too(api):
    client, pi_key, other_key = api
    client.post("/v2/owner/access/delegate", json={"enabled": True}, headers={**OWNER_HEADERS, **agent(pi_key)})
    asked = client.post("/v2/tools/echo.free/invoke", headers=agent(pi_key), json={
        "args": {"value": "hi"}, "action_id": "ask-9",
        "decision": {"outcome": "ask", "decided_by": "ai_reviewer", "reason": f"Ask: {SECRET}"}})
    assert asked.json().get("code") == "CONFIRMATION_REQUIRED", asked.text
    # Another key cannot reach it, and the answer is the same as for any unknown id.
    assert forget(client, other_key, actions=["ask-9"])["actions"]["unknown"] == ["ask-9"]
    assert SECRET in stored("v2_events")
    assert forget(client, pi_key, actions=["ask-9"])["actions"]["unknown"] == ["ask-9"]
    assert SECRET not in stored("v2_events")
