"""Agent identities at the HTTP boundary: each agent sees and runs only its toolkit, never more
than its key, and a bound key is always its own agent."""

import hashlib

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.api.invocation import require_current_dispatch_authority
from toolgate.core import control_plane as cp
from toolgate.core import identities

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
    for item in ("notes.read", "mail.send", "bank.pay"):
        cp.create_tool(tool(item))
    pi, key = cp.issue_agent_key("Pi", ["notes.read", "mail.send"])
    client = TestClient(server.app)
    yield client, pi, key
    client.close()


def headers(key, agent=None):
    return {"X-ToolGate-Execution-Key": key, **({"X-ToolGate-Agent": agent} if agent else {})}


def visible(client, key, agent=None):
    response = client.get("/v2/agent/tools", headers=headers(key, agent))
    return (
        sorted(item["id"] for item in response.json())
        if response.status_code == 200
        else response.status_code
    )


def invoke(client, key, tool_id, agent=None, action="a"):
    return client.post(
        f"/v2/tools/{tool_id}/invoke",
        json={"args": {"value": "x"}, "action_id": f"{action}-{tool_id}-{agent}"},
        headers=headers(key, agent),
    )


def define(client, key, agent, scopes):
    response = client.put(
        f"/v2/agent/identities/{agent}", json={"scopes": scopes}, headers=headers(key)
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_an_agent_sees_and_runs_only_its_toolkit(api):
    client, _, key = api
    define(client, key, "researcher", ["notes.read"])
    assert visible(client, key, "researcher") == ["notes.read"]
    assert invoke(client, key, "notes.read", "researcher").status_code == 200
    refused = invoke(client, key, "mail.send", "researcher")
    assert refused.status_code == 404 and refused.json()["detail"]["message"] == "No such tool"
    status = client.get("/v2/agent/status", headers=headers(key, "researcher")).json()
    assert status["identity"] == "researcher" and status["scopes"] == ["notes.read"]


def test_an_identity_never_exceeds_its_key(api):
    client, _, key = api
    define(client, key, "greedy", ["*", "bank.pay"])
    assert visible(client, key, "greedy") == ["mail.send", "notes.read"]
    assert invoke(client, key, "bank.pay", "greedy").status_code == 404


def test_unknown_agents_see_nothing_and_the_companion_keeps_its_key(api):
    client, _, key = api
    assert visible(client, key, "stranger") == []
    assert visible(client, key, "companion") == ["mail.send", "notes.read"]
    assert visible(client, key) == ["mail.send", "notes.read"]
    for bad in ("Conker", "companion!", "a" * 80, "../x"):
        assert visible(client, key, bad) == 403


def test_a_bound_key_is_always_its_own_agent(api):
    client, _, key = api
    define(client, key, "researcher", ["notes.read"])
    minted = client.post(
        "/v2/owner/agents/researcher/keys", headers={"X-ToolGate-Owner-Key": OWNER, **headers(key)}
    )
    assert minted.status_code == 200 and minted.headers["cache-control"] == "no-store"
    bound = minted.json()["key"]
    assert visible(client, bound) == ["notes.read"]
    assert visible(client, bound, "companion") == 403
    assert invoke(client, bound, "mail.send").status_code == 404
    assert (
        client.put(
            "/v2/agent/identities/researcher", json={"scopes": ["*"]}, headers=headers(bound)
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/v2/owner/agents/researcher/keys",
            headers={"X-ToolGate-Owner-Key": OWNER, **headers(bound)},
        ).status_code
        == 422
    )
    # Narrowing the agent narrows its bound key at once.
    define(client, key, "researcher", [])
    assert visible(client, bound) == []


def test_revoking_the_chat_key_stops_its_bound_keys(api):
    client, pi, key = api
    define(client, key, "researcher", ["notes.read"])
    bound = client.post(
        "/v2/owner/agents/researcher/keys", headers={"X-ToolGate-Owner-Key": OWNER, **headers(key)}
    ).json()["key"]
    cp.revoke_agent_key(pi["id"])
    assert visible(client, bound) == 403


def test_owner_lists_and_revokes_only_its_own_bound_keys(api):
    client, _, key = api
    owner = {"X-ToolGate-Owner-Key": OWNER, **headers(key)}
    record = client.post("/v2/owner/agents/researcher/keys", headers=owner).json()["record"]
    assert [
        item["id"]
        for item in client.get("/v2/owner/agents/researcher/keys", headers=owner).json()["keys"]
    ] == [record["id"]]
    _, other = cp.issue_agent_key("Other", [])
    assert (
        client.post(
            f"/v2/owner/agent-keys/{record['id']}/revoke",
            headers={"X-ToolGate-Owner-Key": OWNER, **headers(other)},
        ).status_code
        == 404
    )
    assert (
        client.post(f"/v2/owner/agent-keys/{record['id']}/revoke", headers=owner).json()["revoked"]
        is True
    )
    assert client.post("/v2/owner/agents/researcher/keys", headers=headers(key)).status_code in (
        401,
        403,
    )


def test_dispatch_rechecks_the_identity_as_it_stands(api):
    client, pi, key = api
    define(client, key, "researcher", ["notes.read"])
    with cp._conn() as conn:
        require_current_dispatch_authority(conn, f"{pi['id']}#researcher", "notes.read")
    define(client, key, "researcher", [])
    with cp._conn() as conn, pytest.raises(Exception) as denied:
        require_current_dispatch_authority(conn, f"{pi['id']}#researcher", "notes.read")
    assert "POLICY_DENIED" in str(denied.value)
    assert identities.for_actor(None, None) is None


def test_grants_belong_to_the_chat_key_not_an_agent(api):
    client, _, key = api
    response = client.post(
        "/v2/owner/mcp/tools/mcp.anything/access",
        json={"enabled": True, "expected_digest": "0" * 64},
        headers={"X-ToolGate-Owner-Key": OWNER, **headers(key, "researcher")},
    )
    assert response.status_code in (403, 404)
