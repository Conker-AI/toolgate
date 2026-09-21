"""Managed lifecycle retains the existing owner approval and once-only boundary."""

import copy
import json

import httpx
import pytest
from fastapi import HTTPException

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.executors import container_control

ID = "a" * 64
TOOL = "system.container-control"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    server.ensure_builtin_system_capabilities()
    calls = []

    def execute(container_id, action):
        assert journal.get("container-action-01")["status"] == "dispatching"
        calls.append((container_id, action))
        return {"containerId": container_id, "action": action, "outcome": "observed"}

    monkeypatch.setattr(container_control, "control", execute)
    agent, _ = cp.issue_agent_key("Managed containers", [f"tool:{TOOL}"])
    return agent, calls


def payload(**changes):
    return server.V2Invoke(**{
        "action_id": "container-action-01", "args": {"container_id": ID, "action": "restart"},
        **changes,
    })


def approve(agent):
    pending = server.run_tool(TOOL, payload(), agent)
    assert pending["code"] == "CONFIRMATION_REQUIRED"
    cp.decide_request(pending["request_id"], "approved", "owner")
    return pending["request_id"]


def test_approval_scope_and_exact_receipt_replay(setup):
    agent, calls = setup
    denied, _ = cp.issue_agent_key("No container scope", ["tool:system.inventory"])
    with pytest.raises(HTTPException):
        server.run_tool(TOOL, payload(), denied)
    request = approve(agent)
    assert calls == []
    changed = payload(args={"container_id": ID, "action": "stop"}, approval_request_id=request)
    with pytest.raises(HTTPException):
        server.run_tool(TOOL, changed, agent)
    assert calls == []
    body = payload(approval_request_id=request)
    first = server.run_tool(TOOL, body, agent)
    assert first["code"] == "OK"
    assert server.run_tool(TOOL, body, agent) == first
    assert calls == [(ID, "restart")]


def test_lost_mutation_reply_stays_unknown_without_retry(setup, monkeypatch):
    agent, calls = setup
    request = approve(agent)

    def uncertain(*args):
        calls.append(args)
        raise RuntimeError("synthetic lost reply with confidential upstream details")

    monkeypatch.setattr(container_control, "control", uncertain)
    body = payload(approval_request_id=request)
    first = server.run_tool(TOOL, body, agent)
    assert first["code"] == "OUTCOME_UNKNOWN"
    assert "confidential" not in str(first)
    assert server.run_tool(TOOL, body, agent) == first
    assert len(calls) == 1


def test_revocation_after_approval_prevents_dispatch(setup):
    agent, calls = setup
    request = approve(agent)
    cp.revoke_agent_key(agent["id"])
    with pytest.raises(HTTPException):
        server.run_tool(TOOL, payload(approval_request_id=request), agent)
    assert calls == []
    assert journal.get("container-action-01") is None


def test_reconfiguration_cannot_silently_remove_review_or_change_executor(setup):
    _, calls = setup
    tool = cp.get("tool", TOOL)
    assert server.tool_definition_errors(tool) == []
    for changes in ({"authorization": "auto"}, {"execution": {"type": "echo"}},
                    {"execution": {"type": "container_control", "socket": "/other"}}):
        changed = {**copy.deepcopy(tool), **changes}
        assert server.tool_definition_errors(changed)
        assert server._dispatch_tool(changed, payload().args)["ok"] is False
    assert calls == []


def test_registration_preserves_disabled_owner_definition(setup):
    cp.create_tool({**cp.get("tool", TOOL), "status": "disabled"})
    server.ensure_builtin_system_capabilities()
    assert cp.get("tool", TOOL)["status"] == "disabled"


def test_actual_adapter_through_approval_and_journal(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setenv("TOOLGATE_DOCKER_SOCKET", "/synthetic/docker.sock")
    monkeypatch.setenv("TOOLGATE_MANAGED_CONTAINER_IDS", json.dumps([ID]))
    server.ensure_builtin_system_capabilities()
    agent, _ = cp.issue_agent_key("Managed containers", [f"tool:{TOOL}"])
    requests = []

    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            yield json.dumps({"Id": ID, "Config": {"Env": ["SECRET=not-for-response"]},
                              "State": {"Status": "running", "Running": True,
                                        "Paused": False, "Restarting": False, "Dead": False}}).encode()

    class Empty(httpx.SyncByteStream):
        def __iter__(self):
            return iter(())

    def handler(request):
        requests.append((request.method, request.url.path))
        assert journal.get("container-action-01")["status"] == "dispatching"
        return httpx.Response(204, stream=Empty()) if request.method == "POST" else httpx.Response(200, stream=Stream())

    actual = container_control.control
    monkeypatch.setattr(container_control, "control", lambda *args: actual(
        *args, transport=httpx.MockTransport(handler)))
    approval = approve(agent)
    assert requests == []
    body = payload(approval_request_id=approval)
    result = server.run_tool(TOOL, body, agent)
    assert result["code"] == "OK"
    assert "SECRET" not in str(result)
    assert requests == [("GET", f"/v1.45/containers/{ID}/json"),
                        ("POST", f"/v1.45/containers/{ID}/restart"),
                        ("GET", f"/v1.45/containers/{ID}/json")]
    assert server.run_tool(TOOL, body, agent) == result
    assert len(requests) == 3
