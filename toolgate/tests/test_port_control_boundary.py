import json

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import vault
from toolgate.executors import port_control
from toolgate.tests.test_port_control import Daemon
from toolgate.tests.test_port_spec import CID, MAPPING

TOOL = "system.port-control"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(vault, "ENV_PATH", tmp_path / "vault.env")
    monkeypatch.setenv("TOOLGATE_VAULT_SECRET", "synthetic-boundary-key")
    monkeypatch.setenv("TOOLGATE_VAULT_SALT", "a1" * 16)
    monkeypatch.setenv("TOOLGATE_DOCKER_SOCKET", "/synthetic/docker.sock")
    monkeypatch.setenv("TOOLGATE_MANAGED_CONTAINER_IDS", json.dumps([CID]))
    server.ensure_builtin_system_capabilities()
    daemon = Daemon()
    inspect, execute = port_control.inspect_review, port_control.execute
    monkeypatch.setattr(port_control, "inspect_review", lambda *args, **kw: inspect(
        *args, **kw, transport=httpx.MockTransport(daemon.handle)))
    monkeypatch.setattr(port_control, "execute", lambda *args, **kw: execute(
        *args, **kw, transport=httpx.MockTransport(daemon.handle)))
    agent, key = cp.issue_agent_key("Port controls", [f"tool:{TOOL}"])
    return daemon, agent, key


def review(agent):
    response = server.create_port_review(server.PortReviewRequest(
        container_id=CID, operation="create", mapping=MAPPING), agent)
    assert response.headers["cache-control"] == "no-store"
    return json.loads(response.body)


def payload(review_id, **changes):
    return server.V2Invoke(**{"action_id": "change-1",
                             "args": {"container_id": CID, "review_id": review_id}, **changes})


def test_full_review_owner_approval_real_executor_receipt_replay(setup):
    daemon, agent, _ = setup
    server.require_valid_tool_definition(cp.get("tool", TOOL))
    selected = review(agent)
    assert selected["preview"]["execution"] == "owner_approval_required"
    pending = server.run_tool(TOOL, payload(selected["reviewId"]), agent)
    assert pending["code"] == "CONFIRMATION_REQUIRED"
    assert all(request.method == "GET" for request in daemon.requests)
    request = cp.get("request", pending["request_id"])
    assert "private-value" not in json.dumps(request)
    assert "8080" in json.dumps(request)
    cp.decide_request(pending["request_id"], "approved", "owner")
    approved = payload(selected["reviewId"], approval_request_id=pending["request_id"])
    result = server.run_tool(TOOL, approved, agent)
    assert result["code"] == "OK", result
    assert result["result"]["result"]["originalRetained"]
    count = len(daemon.requests)
    assert server.run_tool(TOOL, approved, agent) == result
    assert len(daemon.requests) == count


def test_review_http_auth_scope_and_private_projection(setup):
    daemon, _agent, key = setup
    client = TestClient(server.app)
    path = "/v2/agent/system/port-reviews"
    body = {"container_id": CID, "operation": "create", "mapping": MAPPING}
    assert client.post(path, json=body).status_code == 401
    _other, other_key = cp.issue_agent_key("Other", ["tool:system.inventory"])
    assert client.post(path, json=body, headers={"X-ToolGate-Execution-Key": other_key}).status_code == 403
    response = client.post(path, json=body, headers={"X-ToolGate-Execution-Key": key})
    assert response.status_code == 200, response.text
    assert "private-value" not in response.text and response.headers["cache-control"] == "no-store"
    assert all(request.method == "GET" for request in daemon.requests)


def test_changed_review_cannot_borrow_approval(setup):
    daemon, agent, _ = setup
    first, second = review(agent), review(agent)
    pending = server.run_tool(TOOL, payload(first["reviewId"]), agent)
    cp.decide_request(pending["request_id"], "approved", "owner")
    with pytest.raises(HTTPException):
        server.run_tool(TOOL, payload(second["reviewId"], approval_request_id=pending["request_id"]), agent)
    assert journal.get("change-1") is None
    assert all(request.method == "GET" for request in daemon.requests)


def test_lost_reply_returns_unknown_and_never_replays(setup):
    daemon, agent, _ = setup
    selected = review(agent)
    pending = server.run_tool(TOOL, payload(selected["reviewId"]), agent)
    cp.decide_request(pending["request_id"], "approved", "owner")
    daemon.fail = "/commit"
    approved = payload(selected["reviewId"], approval_request_id=pending["request_id"])
    result = server.run_tool(TOOL, approved, agent)
    assert result["code"] == "OUTCOME_UNKNOWN"
    count = len(daemon.requests)
    assert server.run_tool(TOOL, approved, agent) == result
    assert len(daemon.requests) == count


@pytest.mark.parametrize("change", ["executor", "auto", "rename"])
def test_reserved_definition_cannot_bypass_approval(setup, change):
    tool = cp.get("tool", TOOL)
    if change == "executor":
        tool["execution"] = {"type": "echo"}
    elif change == "auto":
        tool["authorization"] = "auto"
    else:
        tool["id"] = "other-tool"
    with pytest.raises(HTTPException):
        server.require_valid_tool_definition(tool)
    assert not server._dispatch_tool(tool, {})["ok"]
