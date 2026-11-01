"""Test that an out-of-scope tool call is refused as "no such tool" and queues no approval request."""

import hashlib

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp

ADMIN = "identity-admin-key"
OWNER = "identity-owner-key-" + "o" * 32


def tool(tool_id, authorization="auto"):
    return {
        "id": tool_id,
        "name": tool_id,
        "description": "Local echo.",
        "category": "safe",
        "inputs": [{"name": "value", "type": "string", "required": True}],
        "outputs": [{"name": "proof", "type": "object"}],
        "execution": {"type": "local_echo"},
        "policy": {"usage_limits": {"max_per_minute": 60, "max_per_hour": 600}},
        "authorization": authorization,
        "version": 1,
        "status": "active",
    }


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(server.vault, "get_control_key", lambda _: ADMIN)
    monkeypatch.setenv("TOOLGATE_OWNER_KEY_SHA256", hashlib.sha256(OWNER.encode()).hexdigest())
    client = TestClient(server.app)
    yield client
    client.close()


def headers(key, agent=None):
    return {"X-ToolGate-Execution-Key": key, **({"X-ToolGate-Agent": agent} if agent else {})}


def invoke(client, key, tool_id, agent=None, action="a"):
    return client.post(
        f"/v2/tools/{tool_id}/invoke",
        json={"args": {"value": "x"}, "action_id": f"{action}-{tool_id}-{agent}"},
        headers=headers(key, agent),
    )


def test_an_out_of_scope_tool_answers_no_such_tool_and_queues_nothing(api):
    client = api
    # Create a tool that requires owner confirmation
    cp.create_tool(tool("secure-tool", "owner_confirmation"))

    # Issue an agent key scoped to a different tool
    _, key = cp.issue_agent_key("scoped_agent", ["other-tool"])

    # Define the agent identity
    assert (
        client.put(
            "/v2/agent/identities/scoped_agent",
            json={"scopes": ["other-tool"]},
            headers=headers(key),
        ).status_code
        == 200
    )

    # Try to invoke the out-of-scope tool
    response = invoke(client, key, "secure-tool", "scoped_agent")

    # Should get 404 with TOOL_UNAVAILABLE
    assert response.status_code == 404
    detail = response.json()["detail"]
    assert detail["code"] == "TOOL_UNAVAILABLE"
    assert detail["message"] == "No such tool"

    # No request should be queued
    requests_response = client.get("/v2/requests", headers={"X-ToolGate-Key": ADMIN})
    assert requests_response.status_code == 200
    assert requests_response.json() == []


def test_the_refusal_is_identical_to_a_missing_tool(api):
    client = api
    # Create a tool that requires owner confirmation
    cp.create_tool(tool("secure-tool", "owner_confirmation"))

    # Issue an agent key scoped to a different tool
    _, key = cp.issue_agent_key("scoped_agent", ["other-tool"])

    # Define the agent identity
    assert (
        client.put(
            "/v2/agent/identities/scoped_agent",
            json={"scopes": ["other-tool"]},
            headers=headers(key),
        ).status_code
        == 200
    )

    # Try to invoke the out-of-scope tool
    out_of_scope_response = invoke(client, key, "secure-tool", "scoped_agent")

    # Try to invoke a tool that doesn't exist
    missing_response = invoke(client, key, "nonexistent-tool", "scoped_agent")

    # Both should return identical 404 responses
    assert out_of_scope_response.status_code == 404
    assert missing_response.status_code == 404
    assert out_of_scope_response.json() == missing_response.json()


def test_the_refusal_is_identical_to_a_disabled_tool(api):
    client = api
    # Create a tool that requires owner confirmation
    cp.create_tool(tool("secure-tool", "owner_confirmation"))

    # Create a disabled tool
    cp.create_tool({**tool("disabled-tool", "owner_confirmation"), "status": "disabled"})

    # Issue an agent key scoped to include the disabled tool
    _, key = cp.issue_agent_key("scoped_agent", ["disabled-tool"])

    # Define the agent identity
    assert (
        client.put(
            "/v2/agent/identities/scoped_agent",
            json={"scopes": ["disabled-tool"]},
            headers=headers(key),
        ).status_code
        == 200
    )

    # Try to invoke the disabled tool
    disabled_response = invoke(client, key, "disabled-tool", "scoped_agent")

    # Should get 404 with TOOL_UNAVAILABLE, same as missing tool
    assert disabled_response.status_code == 404
    detail = disabled_response.json()["detail"]
    assert detail["code"] == "TOOL_UNAVAILABLE"
    assert detail["message"] == "No such tool"

    # No request should be queued
    requests_response = client.get("/v2/requests", headers={"X-ToolGate-Key": ADMIN})
    assert requests_response.status_code == 200
    assert requests_response.json() == []


def test_the_same_tool_in_scope_queues_exactly_one_request(api):
    client = api
    # Create a tool that requires owner confirmation
    cp.create_tool(tool("secure-tool", "owner_confirmation"))

    # Issue an agent key scoped to include the tool
    _, key = cp.issue_agent_key("scoped_agent", ["secure-tool"])

    # Define the agent identity
    assert (
        client.put(
            "/v2/agent/identities/scoped_agent",
            json={"scopes": ["secure-tool"]},
            headers=headers(key),
        ).status_code
        == 200
    )

    # Invoke the in-scope tool
    response = invoke(client, key, "secure-tool", "scoped_agent")

    # Should get 200 with CONFIRMATION_REQUIRED
    assert response.status_code == 200
    body = response.json()
    assert body["code"] == "CONFIRMATION_REQUIRED"
    assert "request_id" in body

    # Exactly one request should be queued
    requests_response = client.get("/v2/requests", headers={"X-ToolGate-Key": ADMIN})
    assert requests_response.status_code == 200
    requests = requests_response.json()
    assert len(requests) == 1
    assert requests[0]["id"] == body["request_id"]


def test_an_admin_key_cannot_use_the_invoke_route(api):
    client = api
    # Create a tool that requires owner confirmation
    cp.create_tool(tool("secure-tool", "owner_confirmation"))

    # Try to invoke with admin key using X-ToolGate-Key header
    response = client.post(
        "/v2/tools/secure-tool/invoke",
        json={"args": {"value": "x"}, "action_id": "admin-test"},
        headers={"X-ToolGate-Key": ADMIN},
    )

    # Should get 401
    assert response.status_code == 401

    # No request should be queued
    requests_response = client.get("/v2/requests", headers={"X-ToolGate-Key": ADMIN})
    assert requests_response.status_code == 200
    assert requests_response.json() == []
