"""Owner access policy at the HTTP boundary: who may decide "run", the floor, tightening, no leaks."""

import hashlib
import sqlite3
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import access_policy
from toolgate.core import control_plane as cp

ADMIN = "access-policy-admin-key"
OWNER = "access-policy-owner-key-" + "o" * 32


def tool(tool_id, authorization="owner_confirmation", execution=None):
    return {
        "id": tool_id,
        "name": tool_id,
        "description": "Local echo for access policy tests.",
        "category": "safe",
        "inputs": [{"name": "value", "type": "string", "required": True}],
        "outputs": [{"name": "proof", "type": "object"}],
        "execution": execution or {"type": "local_echo"},
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
    for item in (
        tool("echo.ask"),
        tool("echo.auto", "auto"),
        tool("echo.blocked", "blocked"),
        tool("echo.hidden"),
    ):
        cp.create_tool(item)
    pi, pi_key = cp.issue_agent_key("Pi", ["echo.ask", "echo.auto", "echo.blocked"])
    _, other_key = cp.issue_agent_key("Other agent", ["echo.ask", "echo.auto"])
    client = TestClient(server.app)
    yield client, pi, pi_key, other_key
    client.close()


def owner(key=None):
    return {"X-ToolGate-Owner-Key": OWNER, **({"X-ToolGate-Execution-Key": key} if key else {})}


def invoke(client, key, tool_id, outcome=None, action="a1"):
    body = {"args": {"value": "hi"}, "action_id": f"{action}-{tool_id}-{outcome}"}
    if outcome:
        body["decision"] = {"outcome": outcome, "decided_by": "chat", "reason": "Full access chat"}
    return client.post(
        f"/v2/tools/{tool_id}/invoke", json=body, headers={"X-ToolGate-Execution-Key": key}
    )


def delegate(client, key, enabled=True):
    response = client.post(
        "/v2/owner/access/delegate", json={"enabled": enabled}, headers=owner(key)
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"delegate": enabled}


def asked(response):
    return response.status_code == 200 and response.json().get("code") == "CONFIRMATION_REQUIRED"


def ran(response):
    return response.status_code == 200 and response.json().get("code") != "CONFIRMATION_REQUIRED"


def test_run_is_ignored_until_the_owner_makes_the_key_a_delegate(api):
    client, _, pi_key, _ = api
    assert asked(invoke(client, pi_key, "echo.ask", "run"))
    delegate(client, pi_key)
    response = invoke(client, pi_key, "echo.ask", "run", action="a2")
    assert ran(response), response.text
    decided = cp.events(event_type="action_decided")
    assert decided and decided[0]["payload"]["decided_by"] == "chat"
    delegate(client, pi_key, enabled=False)
    assert asked(invoke(client, pi_key, "echo.ask", "run", action="a3"))


def test_status_tells_a_key_whether_it_decides(api):
    client, _, pi_key, _ = api
    status = lambda: client.get(  # noqa: E731
        "/v2/agent/status", headers={"X-ToolGate-Execution-Key": pi_key}
    ).json()["policyDelegate"]
    assert status() is False
    delegate(client, pi_key)
    assert status() is True


def test_another_key_cannot_decide_for_the_owner(api):
    client, _, pi_key, other_key = api
    delegate(client, pi_key)
    assert asked(invoke(client, other_key, "echo.ask", "run"))


def test_a_sensitive_tool_always_asks(api):
    client, _, pi_key, _ = api
    delegate(client, pi_key)
    response = client.post(
        "/v2/owner/tools/echo.ask/sensitive", json={"sensitive": True}, headers=owner()
    )
    assert response.status_code == 200 and response.json()["sensitive"] is True
    assert asked(invoke(client, pi_key, "echo.ask", "run"))
    listed = client.get("/v2/agent/tools", headers={"X-ToolGate-Execution-Key": pi_key}).json()
    assert {item["id"]: item["sensitive"] for item in listed}["echo.ask"] is True
    state = client.get("/v2/owner/access", headers=owner(pi_key)).json()
    assert state["delegate"] is True and state["sensitive"] == ["echo.ask"]


def test_system_controls_stay_on_the_floor(api):
    for execution in access_policy.FLOOR_EXECUTIONS:
        item = tool("system.x", execution={"type": execution})
        decision = access_policy.Decision(outcome="run", decided_by="chat")
        assert (
            access_policy.resolve(item, "owner_confirmation", decision, {"id": "any"})
            == "owner_confirmation"
        )


def test_anyone_may_tighten_and_blocked_stays_blocked(api):
    client, _, pi_key, other_key = api
    assert ran(invoke(client, other_key, "echo.auto"))
    assert asked(invoke(client, other_key, "echo.auto", "ask"))
    delegate(client, pi_key)
    blocked = invoke(client, pi_key, "echo.blocked", "run")
    assert blocked.status_code == 403 and blocked.json()["detail"]["code"] == "POLICY_DENIED"


def test_out_of_scope_and_missing_tools_look_the_same(api):
    client, _, pi_key, _ = api
    hidden = invoke(client, pi_key, "echo.hidden")
    missing = invoke(client, pi_key, "echo.nowhere")
    assert hidden.status_code == missing.status_code == 404
    assert (
        hidden.json()["detail"]["message"] == missing.json()["detail"]["message"] == "No such tool"
    )


def test_owner_routes_need_the_owner_and_decisions_are_strict(api):
    client, _, pi_key, _ = api
    assert client.post(
        "/v2/owner/access/delegate",
        json={"enabled": True},
        headers={"X-ToolGate-Execution-Key": pi_key},
    ).status_code in (401, 403)
    assert client.post(
        "/v2/owner/tools/echo.ask/sensitive", json={"sensitive": True}
    ).status_code in (401, 403)
    assert (
        client.post(
            "/v2/owner/tools/echo.nowhere/sensitive", json={"sensitive": True}, headers=owner()
        ).status_code
        == 404
    )
    loose = client.post(
        "/v2/tools/echo.ask/invoke",
        json={
            "args": {"value": "hi"},
            "action_id": "strict-1",
            "decision": {"outcome": "run", "decided_by": "chat", "approved": True},
        },
        headers={"X-ToolGate-Execution-Key": pi_key},
    )
    assert loose.status_code == 422


def tool_access(client, key, tool_id, enabled=None, digest=None):
    path = f"/v2/owner/tools/{tool_id}/access"
    if enabled is None:
        return client.get(path, headers=owner(key))
    return client.post(path, json={"enabled": enabled, "expected_digest": digest}, headers=owner(key))


def test_the_owner_lets_the_chat_key_use_a_tool_and_takes_it_back(api):
    """A fresh install's key can use nothing; the owner's switch is the only way in."""
    client, _, pi_key, _ = api
    assert invoke(client, pi_key, "echo.hidden").status_code == 404
    state = tool_access(client, pi_key, "echo.hidden").json()
    assert (state["enabled"], state["requiredScope"]) == (False, "tool:echo.hidden")

    granted = tool_access(client, pi_key, "echo.hidden", True, state["digest"])
    assert granted.status_code == 200 and granted.json()["enabled"] is True
    assert asked(invoke(client, pi_key, "echo.hidden"))

    revoked = tool_access(client, pi_key, "echo.hidden", False, state["digest"])
    assert revoked.status_code == 200 and revoked.json()["enabled"] is False
    assert invoke(client, pi_key, "echo.hidden", action="a2").status_code == 404


def test_tool_access_is_the_owners_and_checks_the_exact_tool(api):
    client, _, pi_key, _ = api
    digest = tool_access(client, pi_key, "echo.hidden").json()["digest"]
    # The key alone cannot grant itself anything.
    assert client.post(
        "/v2/owner/tools/echo.hidden/access",
        json={"enabled": True, "expected_digest": digest},
        headers={"X-ToolGate-Execution-Key": pi_key},
    ).status_code in (401, 403)
    # A stale screen cannot change a tool that was edited since.
    assert tool_access(client, pi_key, "echo.hidden", True, "0" * 64).status_code == 409
    assert tool_access(client, pi_key, "echo.nowhere").status_code == 404
    # An agent acting under the key cannot widen the key.
    as_agent = client.post(
        "/v2/owner/tools/echo.hidden/access",
        json={"enabled": True, "expected_digest": digest},
        headers={**owner(pi_key), "X-ToolGate-Agent": "companion"},
    )
    assert as_agent.status_code == 403


def test_a_grant_whose_audit_event_cannot_be_written_is_not_applied(api):
    client, _, pi_key, _ = api
    digest = tool_access(client, pi_key, "echo.hidden").json()["digest"]
    with closing(sqlite3.connect(cp.DB_PATH)) as db:
        db.execute("CREATE TRIGGER no_events BEFORE INSERT ON v2_events "
                   "BEGIN SELECT RAISE(ABORT, 'events refused'); END")
        db.commit()
    with pytest.raises(sqlite3.Error):
        tool_access(client, pi_key, "echo.hidden", True, digest)
    assert tool_access(client, pi_key, "echo.hidden").json()["enabled"] is False
