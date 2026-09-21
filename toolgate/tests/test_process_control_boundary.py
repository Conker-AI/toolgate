import json
import subprocess

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.executors import process_control

TOOL = "system.process-control"
SERVICE = "user:worker.service"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setenv("TOOLGATE_SYSTEMD_SCOPE", "user")
    monkeypatch.setenv("TOOLGATE_MANAGED_SERVICE_UNITS", json.dumps(["worker.service"]))
    server.ensure_builtin_system_capabilities()
    agent, key = cp.issue_agent_key("Service controls", [f"tool:{TOOL}"])
    calls = []

    def control(*args):
        assert journal.get("service-action-01")["status"] == "dispatching"
        calls.append(args)
        return {"serviceId": args[0], "action": args[1], "outcome": "observed"}

    monkeypatch.setattr(process_control, "control", control)
    return agent, key, calls


def body(**changes):
    return server.V2Invoke(**{"action_id": "service-action-01",
                              "args": {"service_id": SERVICE, "action": "restart"}, **changes})


def approve(agent):
    result = server.run_tool(TOOL, body(), agent)
    assert result["code"] == "CONFIRMATION_REQUIRED"
    cp.decide_request(result["request_id"], "approved", "owner")
    return result["request_id"]


def test_approval_binds_scope_target_action_and_replays_only_receipt(setup):
    agent, _, calls = setup
    pending = approve(agent)
    assert calls == []
    changed = body(args={"service_id": "system:worker.service", "action": "restart"},
                   approval_request_id=pending)
    with pytest.raises(HTTPException):
        server.run_tool(TOOL, changed, agent)
    result = server.run_tool(TOOL, body(approval_request_id=pending), agent)
    assert result["code"] == "OK" and calls == [(SERVICE, "restart")]
    assert server.run_tool(TOOL, body(approval_request_id=pending), agent) == result
    assert len(calls) == 1


def test_unknown_effect_is_never_repeated(setup, monkeypatch):
    agent, _, calls = setup
    pending = approve(agent)

    def unknown(*args):
        calls.append(args)
        raise RuntimeError("private system diagnostics")

    monkeypatch.setattr(process_control, "control", unknown)
    first = server.run_tool(TOOL, body(approval_request_id=pending), agent)
    assert first["code"] == "OUTCOME_UNKNOWN" and "private" not in str(first)
    assert server.run_tool(TOOL, body(approval_request_id=pending), agent) == first
    assert len(calls) == 1


def test_current_revocation_prevents_effect(setup):
    agent, _, calls = setup
    pending = approve(agent)
    cp.revoke_agent_key(agent["id"])
    with pytest.raises(HTTPException):
        server.run_tool(TOOL, body(approval_request_id=pending), agent)
    assert calls == []


def test_reserved_identity_and_confirmation_cannot_be_replaced(setup):
    _, _, calls = setup
    tool = cp.get("tool", TOOL)
    assert server.tool_definition_errors(tool) == []
    for changes in ({"authorization": "auto"}, {"execution": {"type": "echo"}},
                    {"execution": {"type": "process_control", "command": "whoami"}}):
        value = {**tool, **changes}
        assert server.tool_definition_errors(value)
        assert server._dispatch_tool(value, body().args)["ok"] is False
    assert calls == []


def test_discovery_is_scoped_and_not_a_live_observation(setup):
    _, key, calls = setup
    client = TestClient(server.app)
    route = "/v2/agent/system/services"
    assert client.get(route).status_code == 401
    _, wrong = cp.issue_agent_key("Containers only", ["tool:system.container-control"])
    assert client.get(route, headers={"X-ToolGate-Execution-Key": wrong}).status_code == 403
    response = client.get(route, headers={"X-ToolGate-Execution-Key": key})
    assert response.json()["services"] == [SERVICE]
    assert response.json()["observed"] is False
    assert response.headers["cache-control"] == "no-store" and calls == []
    cp.create_tool({**cp.get("tool", TOOL), "status": "disabled"})
    server.ensure_builtin_system_capabilities()
    assert client.get(route, headers={"X-ToolGate-Execution-Key": key}).json()["services"] == []


def test_actual_adapter_runs_fixed_arguments_behind_approved_journal(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setenv("TOOLGATE_SYSTEMD_SCOPE", "user")
    monkeypatch.setenv("TOOLGATE_MANAGED_SERVICE_UNITS", json.dumps(["worker.service"]))
    monkeypatch.setattr(process_control.os, "geteuid", lambda: 1000, raising=False)
    server.ensure_builtin_system_capabilities()
    agent, _ = cp.issue_agent_key("Service controls", [f"tool:{TOOL}"])
    invocations = []

    def runner(argv, **kwargs):
        assert journal.get("service-action-01")["status"] == "dispatching"
        assert kwargs["shell"] is False
        assert kwargs["stdin"] == kwargs["stderr"] == subprocess.DEVNULL
        invocations.append(argv)
        result = (b"Id=worker.service\nLoadState=loaded\nActiveState=active\n"
                  b"SubState=running\nMainPID=1234\n")
        return subprocess.CompletedProcess(argv, 0, stdout=result)

    actual = process_control.control
    monkeypatch.setattr(process_control, "control", lambda *args: actual(*args, runner=runner))
    pending = approve(agent)
    assert invocations == []
    result = server.run_tool(TOOL, body(approval_request_id=pending), agent)
    assert result["code"] == "OK"
    assert result["result"]["result"]["serviceId"] == SERVICE
    assert len(invocations) == 3
    assert invocations[1] == ["/usr/bin/systemctl", "--user", "--no-pager", "--no-ask-password",
                              "restart", "--", "worker.service"]
    assert server.run_tool(TOOL, body(approval_request_id=pending), agent) == result
    assert len(invocations) == 3
