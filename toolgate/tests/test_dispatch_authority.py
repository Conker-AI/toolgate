"""Changes committed before a dispatch reservation revoke that dispatch's authority."""
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import publications


@pytest.fixture
def flow(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "authority.db")
    cp.create_tool({"id": "child", "name": "Child", "status": "active", "execution": {"type": "echo"}})
    cp.create_automation({"id": "flow", "name": "Flow", "status": "active", "workflow": [
        {"type": "tool_call", "tool_id": "child"}, {"type": "tool_call", "tool_id": "child"}]})
    publications.publish("automation", "flow", 1)
    return cp.issue_agent_key("Caller", ["automation:flow"])


def revoke(agent, change):
    if change == "key":
        cp.revoke_agent_key(agent["id"])
    elif change == "lockdown":
        cp.set_lockdown(True, "owner")
    else:
        cp.update_agent_key_scopes(agent["id"], ["child"] if change == "child_only" else [])


@pytest.mark.parametrize("published_version", [None, 1])
@pytest.mark.parametrize("change", ["key", "scope", "child_only", "lockdown"])
def test_mid_workflow_revocation_stops_next_child_without_scope_union(flow, monkeypatch, published_version, change):
    agent, _ = flow
    calls = []
    def dispatch(tool, args):
        calls.append(tool["id"])
        revoke(agent, change)
        return {"ok": True, "result": {}}
    monkeypatch.setattr(server, "_dispatch_tool", dispatch)
    payload = server.V2Invoke(action_id="root", published_version=published_version)
    result = server.run_automation("flow", payload, agent)
    assert result["code"] == "OUTCOME_UNKNOWN"
    assert calls == ["child"]
    records = journal.list_actions()
    assert len(records) == 2
    assert len([record for record in records if record["status"] == "completed"]) == 1
    # Reconciliation may return a receipt but can never restart the remaining steps.
    assert server.run_automation("flow", payload, agent) == result
    assert calls == ["child"]


@pytest.mark.parametrize("change,code", [("key", "AGENT_REVOKED"), ("scope", "POLICY_DENIED"), ("lockdown", "LOCKED_DOWN")])
def test_http_authority_is_rechecked_inside_root_dispatch_transaction(flow, monkeypatch, change, code):
    agent, raw = flow
    original = journal.begin
    calls = []
    def race(*args, **kwargs):
        revoke(agent, change)
        return original(*args, **kwargs)
    monkeypatch.setattr(journal, "begin", race)
    monkeypatch.setattr(server, "_dispatch_tool", lambda *args: calls.append(args))
    client = TestClient(server.app)
    response = client.post("/v2/automations/flow/run", headers={"X-ToolGate-Execution-Key": raw},
                           json={"action_id": "race", "published_version": 1})
    assert response.status_code in {403, 423}
    assert response.json()["detail"]["code"] == code
    assert journal.get("race") is None and calls == []


def test_revoked_actor_cannot_consume_previously_approved_request(flow, monkeypatch):
    agent, _ = flow
    definition = cp.get("automation", "flow")
    cp.update_automation("flow", {**definition, "authorization": "owner_confirmation"})
    payload = server.V2Invoke(action_id="approved")
    pending = server.run_automation("flow", payload, agent)
    cp.decide_request(pending["request_id"], "approved", "owner")
    payload.approval_request_id = pending["request_id"]
    cp.revoke_agent_key(agent["id"])
    calls = []
    monkeypatch.setattr(server, "_dispatch_tool", lambda *args: calls.append(args))
    with pytest.raises(HTTPException) as error:
        server.run_automation("flow", payload, agent)
    assert error.value.detail["code"] == "AGENT_REVOKED"
    assert cp.get("request", pending["request_id"])["payload"]["binding"]["consumed_at"] is None
    assert journal.get("approved") is None and calls == []
