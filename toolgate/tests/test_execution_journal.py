import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from fastapi import HTTPException

from toolgate.api import server
from toolgate.core import control_plane
from toolgate.core import execution_journal as journal


@pytest.fixture
def tool(tmp_path, monkeypatch):
    monkeypatch.setattr(control_plane, "DB_PATH", tmp_path / "gate.db")
    return {"id": "act", "name": "Action", "version": 1, "authorization": "auto",
            "inputs": [], "outputs": [], "execution": {"type": "http_json", "billing": {"mode": "free"}}}


def invoke(tool, **kwargs):
    return server.invoke_tool(tool, kwargs.pop("args", {}), "actor", actor_id="agent",
                              action_id="job.action", **kwargs)


def test_dispatch_is_durable_before_external_effect_and_replay_is_cached(tool, monkeypatch):
    calls = []

    def execute(tool, args):
        with sqlite3.connect(control_plane.DB_PATH) as db:
            assert db.execute("SELECT status FROM v2_actions").fetchone() == ("dispatching",)
        calls.append(args)
        return {"ok": True, "result": {"receipt": "external-123"}}

    monkeypatch.setattr(server, "_dispatch_tool", execute)
    first = invoke(tool)
    assert first["status"] == "completed"
    assert first["code"] == "OK"
    assert first["result"]["result"]["receipt"] == "external-123"
    assert invoke(tool) == first
    assert calls == [{}]
    assert invoke({**tool, "version": 2}) == first


def test_reusing_identity_with_different_arguments_fails(tool, monkeypatch):
    monkeypatch.setattr(server, "_dispatch_tool", lambda *a: {"ok": True, "result": {}})
    invoke(tool)
    with pytest.raises(HTTPException) as caught:
        invoke(tool, args={"changed": True})
    assert caught.value.detail["code"] == "ACTION_CONFLICT"


def test_interruption_after_external_effect_is_unknown_and_never_retried(tool, monkeypatch):
    calls = []

    def crash(*args):
        calls.append("effect happened")
        raise SystemExit("process died before receipt")

    monkeypatch.setattr(server, "_dispatch_tool", crash)
    with pytest.raises(SystemExit):
        invoke(tool)
    assert journal.recover_interrupted() == 1
    assert invoke(tool)["code"] == "OUTCOME_UNKNOWN"
    assert calls == ["effect happened"]


def test_two_callers_cannot_dispatch_same_action(tool, monkeypatch):
    entered, release = Event(), Event()
    calls = []

    def execute(*args):
        calls.append(1)
        entered.set()
        assert release.wait(5)
        return {"ok": True, "result": {}}

    monkeypatch.setattr(server, "_dispatch_tool", execute)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(invoke, tool)
        assert entered.wait(5)
        try:
            assert invoke(tool)["code"] == "IN_PROGRESS"
        finally:
            release.set()
        assert first.result()["status"] == "completed"
    assert calls == [1]


def test_failed_journal_commit_cannot_dispatch_or_consume_approval(tool, monkeypatch):
    tool["authorization"] = "owner_confirmation"
    request = control_plane.create_verification_request("Run", "exact", "actor", "tool",
                                                        "act", {}, 1, actor_id="agent")
    control_plane.decide_request(request["id"], "approved", "owner")
    with control_plane._conn() as db:
        journal.initialize(db)
        db.execute("CREATE TRIGGER reject_dispatch BEFORE INSERT ON v2_actions "
                   "BEGIN SELECT RAISE(ABORT, 'disk failure'); END")
    monkeypatch.setattr(server, "_dispatch_tool", lambda *a: pytest.fail("dispatched without record"))
    with pytest.raises(sqlite3.IntegrityError):
        invoke(tool, approval_request_id=request["id"])
    assert control_plane.get("request", request["id"])["payload"]["binding"]["consumed_at"] is None


def test_receipt_write_failure_never_becomes_permission_to_retry(tool, monkeypatch):
    calls = []
    monkeypatch.setattr(server, "_dispatch_tool", lambda *a: calls.append(1) or {"ok": True, "result": {}})
    with monkeypatch.context() as patch:
        patch.setattr(journal, "finish", lambda *a, **kw: (_ for _ in ()).throw(sqlite3.OperationalError()))
        with pytest.raises(sqlite3.OperationalError):
            invoke(tool)
    assert invoke(tool)["code"] == "IN_PROGRESS"
    journal.recover_interrupted()
    assert invoke(tool)["code"] == "OUTCOME_UNKNOWN"
    assert calls == [1]


def test_identity_includes_actor_and_parent_job(tool, monkeypatch):
    monkeypatch.setattr(server, "_dispatch_tool", lambda *a: {"ok": True, "result": {}})
    invoke(tool)
    with pytest.raises(HTTPException) as error:
        server.invoke_tool(tool, {}, "other", actor_id="other", action_id="job.action")
    assert error.value.detail["code"] == "ACTION_CONFLICT"
    with pytest.raises(HTTPException):
        invoke(tool, job_id="another-job")


def test_completed_receipt_cannot_be_replaced_or_deleted(tool, monkeypatch):
    monkeypatch.setattr(server, "_dispatch_tool", lambda *a: {"ok": True, "result": {"receipt": 7}})
    first = invoke(tool)
    for sql in ["DELETE FROM v2_actions", "UPDATE v2_actions SET response='{}'",
                "INSERT OR REPLACE INTO v2_actions SELECT * FROM v2_actions"]:
        with control_plane._conn() as db, pytest.raises(sqlite3.IntegrityError):
            db.execute(sql)
    assert invoke(tool) == first


def test_workflow_retry_block_never_repeats_uncertain_child(tool, monkeypatch):
    tool["status"] = "active"
    tool["policy"] = {"usage_limits": {"cooldown_seconds": 0, "max_per_minute": 60, "max_per_hour": 600}}
    control_plane.create_tool(tool)
    control_plane.create_automation({"id": "flow", "name": "Flow", "status": "active", "authorization": "auto",
                                    "workflow": [{"type": "retry", "max_attempts": 3,
                                                  "step": {"type": "tool_call", "tool_id": "act"}}]})
    calls = []

    def interrupted(*args):
        calls.append("effect")
        raise HTTPException(502, "reply lost after effect")

    monkeypatch.setattr(server, "_dispatch_tool", interrupted)
    agent, _ = control_plane.issue_agent_key("Actor", ["automation:flow"])
    payload = server.V2Invoke(action_id="flow-1")
    result = server.run_automation("flow", payload, agent)
    assert result["code"] == "OUTCOME_UNKNOWN"
    assert server.run_automation("flow", payload, agent) == result
    assert calls == ["effect"]
    assert len(journal.list_actions()) == 2


def test_status_is_visible_only_to_owner_or_originating_agent(tool, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setattr(server.vault, "get_control_key", lambda _: "owner")
    actor, key = control_plane.issue_agent_key("origin", ["tool:*"])
    _, other = control_plane.issue_agent_key("stranger", ["tool:*"])
    journal.begin("known", "tool", "act", {"private": True}, actor["id"], 1)
    journal.unknown("known")
    client = TestClient(server.app)
    assert client.get("/v2/actions", headers={"X-ToolGate-Execution-Key": key}).status_code == 401
    assert client.get("/v2/agent/actions/known", headers={"X-ToolGate-Execution-Key": other}).status_code == 404
    response = client.get("/v2/agent/actions/known", headers={"X-ToolGate-Execution-Key": key})
    assert response.status_code == 200
    assert response.json()["code"] == "OUTCOME_UNKNOWN"
    client.close()


def test_process_death_after_effect_leaves_durable_unknown(tool, tmp_path):
    import os
    import subprocess
    import sys

    effect = tmp_path / "external-effect"
    code = """
import os, sys
from pathlib import Path
from toolgate.api import server
from toolgate.core import control_plane
control_plane.DB_PATH = Path(sys.argv[1])
def dispatch(tool, args):
    Path(sys.argv[2]).write_text("happened")
    os._exit(71)
server._dispatch_tool = dispatch
server.invoke_tool({"id":"act","name":"Action","version":1,"execution":{"type":"echo"}},
                   {}, "actor", actor_id="agent", action_id="process-action")
"""
    result = subprocess.run([sys.executable, "-c", code, str(control_plane.DB_PATH), str(effect)],
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                            capture_output=True, timeout=30, check=False)
    assert result.returncode == 71, result.stderr.decode()
    assert effect.read_text() == "happened"
    assert journal.recover_interrupted() == 1
    record = journal.get("process-action")
    assert journal.response(record)["code"] == "OUTCOME_UNKNOWN"
