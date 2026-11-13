"""Forgetting a chat's tool records (gap 9): arguments, results and words go, the audit line
stays, nothing waiting or running is touched, and a forgotten action can never run again."""

import hashlib
import json
import shutil
import sqlite3

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import forgetting, recovery_journal

ADMIN = "forget-admin-key-" + "a" * 32
OWNER = "forget-owner-key-" + "o" * 32
OWNER_HEADERS = {"X-ToolGate-Owner-Key": OWNER}
SECRET = "my-private-words"


def _tool(tool_id, authorization):
    cp.create_tool({
        "id": tool_id, "name": tool_id, "description": "Local echo.", "category": "safe",
        "inputs": [{"name": "value", "type": "string", "required": True}],
        "outputs": [{"name": "proof", "type": "object"}],
        "execution": {"type": "local_echo"},
        "policy": {"usage_limits": {"max_per_minute": 60, "max_per_hour": 600}},
        "authorization": authorization, "version": 1, "status": "active",
    })


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(server.vault, "get_control_key", lambda _: ADMIN)
    monkeypatch.setenv("TOOLGATE_OWNER_KEY_SHA256", hashlib.sha256(OWNER.encode()).hexdigest())
    _tool("echo.ask", "owner_confirmation")
    _tool("echo.free", "auto")
    _, pi_key = cp.issue_agent_key("Pi", ["echo.ask", "echo.free"])
    _, other_key = cp.issue_agent_key("Other agent", ["echo.ask", "echo.free"])
    client = TestClient(server.app)
    yield client, pi_key, other_key
    client.close()


def agent(key):
    return {"X-ToolGate-Execution-Key": key}


def invoke(client, key, tool="echo.free", value=SECRET, action="act-1", approval=None):
    body = {"args": {"value": value}, "action_id": action}
    if approval:
        body["approval_request_id"] = approval
    return client.post(f"/v2/tools/{tool}/invoke", json=body, headers=agent(key))


def park(client, key, action="ask-1"):
    response = invoke(client, key, "echo.ask", action=action)
    assert response.json()["code"] == "CONFIRMATION_REQUIRED", response.text
    return response.json()["request_id"]


def decide(client, request_id, status="approved", note="yes, send my private words"):
    response = client.post(f"/v2/owner/requests/{request_id}/decision",
                           json={"status": status, "note": note}, headers=OWNER_HEADERS)
    assert response.status_code == 200, response.text


def forget(client, key=None, requests=(), actions=()):
    headers = agent(key) if key else {"X-ToolGate-Key": ADMIN}
    route = "/v2/agent/forget" if key else "/v2/admin/forget"
    response = client.post(route, json={"request_ids": list(requests), "action_ids": list(actions)},
                           headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def stored(*tables):
    with sqlite3.connect(cp.DB_PATH) as db:
        return " ".join(str(row) for table in tables for row in db.execute(f"SELECT * FROM {table}"))


def test_a_completed_action_is_blanked_and_a_retry_never_runs_it_again(api):
    client, pi_key, _ = api
    assert invoke(client, pi_key).json()["status"] == "completed"
    assert SECRET in stored("v2_actions")
    result = forget(client, pi_key, actions=["act-1"])
    assert result["actions"]["forgotten"] == ["act-1"]
    assert SECRET not in stored("v2_actions")
    row = journal.get("act-1")
    assert row["args"] == {} and row["response"]["code"] == "FORGOTTEN"
    assert row["status"] == "completed" and row["actor_id"]
    # Same id, same words: the forgotten receipt, no second dispatch.
    retry = invoke(client, pi_key)
    assert retry.json()["code"] == "FORGOTTEN"
    assert len(journal.list_actions()) == 1
    # Same id, other words: still bound to the first invocation.
    assert invoke(client, pi_key, value="other").status_code == 409
    events = cp.events(event_type="action_forgotten")
    assert [(event["subject_id"], event["actor"]) for event in events] == [("act-1", "Pi")]
    assert events[0]["payload"] == {"subject_type": "tool", "subject_id": "echo.free",
                                    "status": "completed", "children": 0}


def test_an_answered_request_keeps_who_when_and_the_decision_but_not_the_words(api):
    client, pi_key, _ = api
    request_id = park(client, pi_key)
    decide(client, request_id)
    assert invoke(client, pi_key, "echo.ask", action="ask-1", approval=request_id).json()["status"] == "completed"
    result = forget(client, pi_key, requests=[request_id], actions=["ask-1"])
    assert result["requests"]["forgotten"] == [request_id]
    assert result["actions"]["forgotten"] == ["ask-1"]
    assert SECRET not in stored("v2_objects", "v2_actions", "v2_events")
    record = cp.get("request", request_id)
    assert record["status"] == "approved" and record["kind"] == "verification"
    assert record["payload"]["args"] == {} and record["details"] == forgetting.FORGOTTEN_TEXT
    assert record["decision"]["actor"] and record["decision"]["at"] and record["decision"]["note"] == ""
    assert record["payload"]["subject_id"] == "echo.ask"
    # The owner's history still opens it as intact.
    detail = client.get(f"/v2/owner/requests/{request_id}", headers=OWNER_HEADERS)
    assert detail.status_code == 200, detail.text
    assert [event["subject_id"] for event in cp.events(event_type="request_forgotten")] == [request_id]


def test_an_approval_not_used_yet_can_never_run_once_forgotten(api):
    client, pi_key, _ = api
    request_id = park(client, pi_key)
    decide(client, request_id)
    assert forget(client, pi_key, requests=[request_id])["requests"]["forgotten"] == [request_id]
    assert cp.get("request", request_id)["payload"]["binding"]["consumed_by"] == "forgetting"
    late = invoke(client, pi_key, "echo.ask", action="ask-2", approval=request_id)
    assert late.json().get("status") != "completed", late.text
    assert journal.get("ask-2") is None or journal.get("ask-2")["status"] != "completed"


def test_a_waiting_request_and_a_running_action_are_refused_and_left_as_they_are(api):
    client, pi_key, _ = api
    request_id = park(client, pi_key)
    agent_id = cp.authenticate_agent(pi_key)["id"]
    journal.begin("running", "tool", "echo.free", {"value": SECRET}, agent_id, 1)
    result = forget(client, pi_key, requests=[request_id], actions=["running"])
    assert result["requests"]["refused"] == [{"id": request_id, "code": "still_pending"}]
    assert result["actions"]["refused"] == [{"id": "running", "code": "still_running"}]
    assert cp.get("request", request_id)["payload"]["args"] == {"value": SECRET}
    assert journal.get("running")["args"] == {"value": SECRET}
    # Withdrawn first, as Pi does, it is forgotten.
    client.post(f"/v2/agent/requests/{request_id}/withdraw", headers=agent(pi_key))
    assert forget(client, pi_key, requests=[request_id])["requests"]["forgotten"] == [request_id]


def test_another_keys_records_and_unknown_ids_look_the_same_and_stay(api):
    client, pi_key, other_key = api
    invoke(client, pi_key)
    request_id = park(client, pi_key)
    decide(client, request_id, "rejected")
    result = forget(client, other_key, requests=[request_id, "nope"], actions=["act-1", "nope"])
    assert result["requests"]["unknown"] == [request_id, "nope"]
    assert result["actions"]["unknown"] == ["act-1", "nope"]
    assert SECRET in stored("v2_actions") and journal.get("act-1")["args"] == {"value": SECRET}
    assert not cp.events(event_type="action_forgotten")
    # The owner's admin key reaches any record.
    admin = forget(client, requests=[request_id], actions=["act-1"])
    assert admin["requests"]["forgotten"] == [request_id] and admin["actions"]["forgotten"] == ["act-1"]
    assert cp.events(event_type="action_forgotten")[0]["actor"] == "admin"


def test_forgetting_again_answers_already_and_records_nothing_new(api):
    client, pi_key, _ = api
    invoke(client, pi_key)
    forget(client, pi_key, actions=["act-1"])
    again = forget(client, pi_key, actions=["act-1", "act-1"])
    assert again["actions"] == {"forgotten": [], "already": ["act-1"], "unknown": [], "refused": []}
    assert len(cp.events(event_type="action_forgotten")) == 1


def test_an_agents_message_loses_its_title_and_payload_too(api):
    client, pi_key, _ = api
    note = client.post("/v2/requests", headers=agent(pi_key), json={
        "kind": "info", "title": SECRET, "details": SECRET, "payload": {"text": SECRET}})
    assert note.status_code == 200, note.text
    note_id = note.json()["id"]
    client.post(f"/v2/requests/{note_id}/decision", json={"status": "dismissed"},
                headers={"X-ToolGate-Key": ADMIN})
    assert forget(client, pi_key, requests=[note_id])["requests"]["forgotten"] == [note_id]
    assert SECRET not in stored("v2_objects", "v2_events")
    # The key still reads its own (blanked) request.
    assert client.get(f"/v2/agent/requests/{note_id}", headers=agent(pi_key)).status_code == 200


def test_it_works_in_lockdown_and_waits_while_recovery_is_held(api):
    client, pi_key, _ = api
    invoke(client, pi_key)
    invoke(client, pi_key, action="act-2")
    cp.set_lockdown(True, "owner", "test")
    assert forget(client, pi_key, actions=["act-1"])["actions"]["forgotten"] == ["act-1"]
    with sqlite3.connect(cp.DB_PATH) as db:
        db.execute("INSERT INTO v2_recovery_hold VALUES (1)")
    held = client.post("/v2/agent/forget", json={"action_ids": ["act-2"]}, headers=agent(pi_key))
    assert held.status_code == 409 and held.json()["detail"]["code"] == "RECOVERY_HELD"
    assert journal.get("act-2")["args"] == {"value": SECRET}


def test_a_workflows_children_follow_their_parent(api):
    _client, pi_key, _ = api
    agent_id = cp.authenticate_agent(pi_key)["id"]
    journal.begin("root", "automation", "flow", {"value": SECRET}, agent_id, 1)
    journal.begin("child", "tool", "echo.free", {"value": SECRET}, agent_id, 1, parent_action_id="root")
    journal.finish("child", {"ok": True, "proof": SECRET})
    journal.finish("root", {"ok": True, "proof": SECRET})
    result = forgetting.forget([], ["root"], "Pi", agent_id)
    assert result["actions"]["forgotten"] == ["root"]
    assert SECRET not in stored("v2_actions")
    assert cp.events(event_type="action_forgotten")[0]["payload"]["children"] == 1


def test_the_database_itself_refuses_any_other_change_to_an_action(api):
    client, pi_key, _ = api
    invoke(client, pi_key)
    invoke(client, pi_key, action="act-2")
    with sqlite3.connect(cp.DB_PATH) as db, pytest.raises(sqlite3.IntegrityError, match="immutable"):
        db.execute("UPDATE v2_actions SET args='{}' WHERE action_id='act-2'")
    forget(client, pi_key, actions=["act-1"])
    with sqlite3.connect(cp.DB_PATH) as db:
        with pytest.raises(sqlite3.IntegrityError, match=r"forgotten|immutable"):
            db.execute("UPDATE v2_actions SET response=? WHERE action_id='act-1'",
                       (json.dumps({"ok": True, "proof": SECRET}),))
        with pytest.raises(sqlite3.IntegrityError, match="permanent"):
            db.execute("DELETE FROM v2_forgotten")


def test_a_restore_reconciles_against_a_journal_that_forgot(tmp_path, monkeypatch):
    source, target = tmp_path / "source.db", tmp_path / "target.db"
    # The restored copy is a snapshot from before the chat was forgotten; the journal forgot since.
    monkeypatch.setattr(cp, "DB_PATH", source)
    journal.begin("kept", "tool", "post", {"value": SECRET}, "agent", 1)
    journal.finish("kept", {"ok": True, "proof": SECRET})
    shutil.copyfile(source, target)
    forgetting.forget([], ["kept"], "admin")
    with sqlite3.connect(source) as db:
        db.execute("UPDATE v2_actions SET updated_at=updated_at+60 WHERE action_id='kept'")
    result = recovery_journal.reconcile(source, target)
    assert result["receipts"] == 1
    with sqlite3.connect(target) as db:
        record = json.loads(db.execute("SELECT record FROM v2_recovery_receipts").fetchone()[0])
    assert record["args"] == "{}" and SECRET not in json.dumps(record)


def test_a_waiting_message_to_the_owner_leaves_his_inbox_with_its_words(api):
    client, pi_key, _ = api
    note = client.post("/v2/requests", headers=agent(pi_key), json={
        "kind": "info", "title": SECRET, "details": SECRET})
    note_id = note.json()["id"]
    assert forget(client, pi_key, requests=[note_id])["requests"]["forgotten"] == [note_id]
    record = cp.get("request", note_id)
    assert record["status"] == "withdrawn" and record["decision"]["actor"] == "Pi"
    assert SECRET not in stored("v2_objects", "v2_events")
    pending = client.get("/v2/owner/requests", headers=OWNER_HEADERS).json()["results"]
    assert note_id not in [row["id"] for row in pending]


def test_an_editor_run_without_a_journal_row_is_blanked_unless_it_is_starting(api):
    _client, pi_key, _ = api
    agent_id = cp.authenticate_agent(pi_key)["id"]
    with cp._conn() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS v2_editor_runs (action_id TEXT PRIMARY KEY,"
                     " draft_id TEXT NOT NULL, actor_id TEXT NOT NULL, version INTEGER NOT NULL,"
                     " digest TEXT NOT NULL, args TEXT NOT NULL, state TEXT NOT NULL, response TEXT,"
                     " created_at TEXT NOT NULL)")
        for action_id, state in (("waiting", "approval"), ("starting", "held")):
            conn.execute("INSERT INTO v2_editor_runs VALUES(?,?,?,?,?,?,?,?,?)",
                         (action_id, "draft", agent_id, 1, "d", json.dumps({"value": SECRET}),
                          state, json.dumps({"code": "CONFIRMATION_REQUIRED"}), "now"))
    result = forgetting.forget([], ["waiting", "starting", "elsewhere"], "Pi", agent_id)
    assert result["actions"]["forgotten"] == ["waiting"]
    assert result["actions"]["refused"] == [{"id": "starting", "code": "still_running"}]
    assert result["actions"]["unknown"] == ["elsewhere"]
    with cp._conn() as conn:
        args = dict(conn.execute("SELECT action_id, args FROM v2_editor_runs").fetchall())
    assert args == {"waiting": "{}", "starting": json.dumps({"value": SECRET})}


def test_a_forgotten_unknown_outcome_may_settle_only_as_forgotten(api):
    _client, pi_key, _ = api
    agent_id = cp.authenticate_agent(pi_key)["id"]
    journal.begin("lost", "tool", "echo.free", {"value": SECRET}, agent_id, 1)
    journal.unknown("lost")
    forgetting.forget([], ["lost"], "Pi", agent_id)
    assert journal.get("lost")["args"] == {} and journal.get("lost")["response"] is None
    with sqlite3.connect(cp.DB_PATH) as db:
        with pytest.raises(sqlite3.IntegrityError, match="forgotten"):
            db.execute("UPDATE v2_actions SET status='completed', response=? WHERE action_id='lost'",
                       (json.dumps({"ok": True, "proof": SECRET}),))
        db.execute("UPDATE v2_actions SET status='completed', response=? WHERE action_id='lost'",
                   (journal.FORGOTTEN_RESPONSE,))
    assert journal.get("lost")["response"]["code"] == "FORGOTTEN"


def test_an_older_database_trades_its_triggers_once_and_stays_guarded(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "old.db")
    journal.begin("old", "tool", "post", {"value": SECRET}, "agent", 1)
    with sqlite3.connect(cp.DB_PATH) as db:
        # The guard as it was before forgetting existed.
        db.execute("CREATE TRIGGER v2_action_identity_immutable BEFORE UPDATE ON v2_actions"
                   " WHEN NEW.args IS NOT OLD.args BEGIN SELECT RAISE(ABORT, 'old guard'); END")
    journal.get("old")
    with sqlite3.connect(cp.DB_PATH) as db:
        names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
        assert "v2_action_identity_immutable" not in names and "v2_action_identity_fixed" in names
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute("UPDATE v2_actions SET args='{}' WHERE action_id='old'")


def test_a_forged_forgotten_row_does_not_excuse_a_wrong_fingerprint(tmp_path, monkeypatch):
    source, target = tmp_path / "source.db", tmp_path / "target.db"
    monkeypatch.setattr(cp, "DB_PATH", source)
    journal.begin("kept", "tool", "post", {"value": SECRET}, "agent", 1)
    journal.finish("kept", {"ok": True})
    shutil.copyfile(source, target)
    with sqlite3.connect(source) as db:
        db.execute("INSERT INTO v2_forgotten VALUES('action','kept','now','someone')")
        for name in ("v2_action_identity_fixed", "v2_action_result_fixed", "v2_action_forgotten_stays"):
            db.execute(f"DROP TRIGGER {name}")
        db.execute("UPDATE v2_actions SET args=? WHERE action_id='kept'", (json.dumps({"value": "x"}),))
    with pytest.raises(ValueError, match="inconsistent"):
        recovery_journal.reconcile(source, target)
