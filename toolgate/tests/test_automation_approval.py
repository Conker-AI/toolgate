import pytest
from fastapi import HTTPException

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal


@pytest.fixture
def flow(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    child = cp.create_tool({"id": "child", "name": "Child", "version": 1, "status": "active",
                            "authorization": "owner_confirmation", "execution": {"type": "echo"}})
    cp.create_automation({"id": "flow", "name": "Flow", "status": "active", "version": 1,
                          "authorization": "owner_confirmation", "workflow": [
                              {"type": "condition", "left": 1, "operator": "equals", "right": 1,
                               "then": [{"type": "tool_call", "tool_id": "child"}]}]})
    agent, _ = cp.issue_agent_key("Caller", ["automation:flow"])
    payload = server.V2Invoke(action_id="root")
    pending = server.run_automation("flow", payload, agent)
    cp.decide_request(pending["request_id"], "approved", "owner")
    payload.approval_request_id = pending["request_id"]
    return child, agent, payload


def test_changed_child_invalidates_approval_without_consumption(flow, monkeypatch):
    child, agent, payload = flow
    cp.update_tool("child", {**child, "execution": {"type": "local_echo"}})
    calls = []
    monkeypatch.setattr(server, "_dispatch_tool", lambda *a: calls.append(a))
    with pytest.raises(HTTPException) as exc:
        server.run_automation("flow", payload, agent)
    assert exc.value.detail["code"] == "APPROVAL_INVALID"
    assert calls == [] and journal.get("root") is None
    assert cp.get("request", payload.approval_request_id)["payload"]["binding"]["consumed_at"] is None


def test_unchanged_approval_runs_and_replays_only_receipt(flow, monkeypatch):
    _, agent, payload = flow
    calls = []
    monkeypatch.setattr(server, "_dispatch_tool", lambda *a: calls.append(a) or {"ok": True, "result": {}})
    first = server.run_automation("flow", payload, agent)
    assert first["code"] == "OK"
    assert server.run_automation("flow", payload, agent) == first
    assert len(calls) == 1


def test_edit_after_consumption_cannot_replace_pinned_child(flow, monkeypatch):
    child, agent, payload = flow
    run = server._run_workflow_steps
    versions = []
    def race(*args):
        cp.update_tool("child", {**child, "execution": {"type": "local_echo"}})
        return run(*args)
    monkeypatch.setattr(server, "_run_workflow_steps", race)
    monkeypatch.setattr(server, "_dispatch_tool", lambda tool, args: versions.append(tool["version"]) or {"ok": True, "result": {}})
    assert server.run_automation("flow", payload, agent)["code"] == "OK"
    assert versions == [1]
