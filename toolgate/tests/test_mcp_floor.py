"""External MCP tools are on the floor: a delegate's "run" never lifts their owner confirmation."""

import hashlib

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import access_policy
from toolgate.core import control_plane as cp
from toolgate.executors import mcp_http as mcp
from toolgate.tests.mcp_peer import (
    ADMIN,
    OWNER,
    SCHEMA,
    URL,
    execution,
    peer,  # noqa: F401 - pytest fixture used by name
)

RUN = access_policy.Decision(outcome="run", decided_by="chat", reason="Full access chat")


@pytest.fixture
def api(tmp_path, monkeypatch, peer):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(server.vault, "get_control_key", lambda _: ADMIN)
    monkeypatch.setenv("TOOLGATE_OWNER_KEY_SHA256", hashlib.sha256(OWNER.encode()).hexdigest())
    agent, key = cp.issue_agent_key("Conker", [])
    client = TestClient(server.app)
    yield client, agent, key
    client.close()


def owner(key=None):
    return {"X-ToolGate-Owner-Key": OWNER, **({"X-ToolGate-Execution-Key": key} if key else {})}


def imported_and_granted(client, key):
    body = {
        "id": "mcp.test-echo",
        "name": "External echo",
        "description": "Echo through MCP",
        "url": URL,
        "tool_name": "echo",
        "input_schema": SCHEMA,
        "schema_hash": mcp.schema_hash(SCHEMA),
    }
    response = client.post("/v2/owner/mcp/import", json=body, headers=owner())
    assert response.status_code == 200, response.text
    tool = response.json()["tool"]
    response = client.post(
        "/v2/owner/mcp/tools/mcp.test-echo/access",
        headers=owner(key),
        json={"enabled": True, "expected_digest": tool["digest"]},
    )
    assert response.status_code == 200, response.text


def test_a_delegate_run_never_lifts_an_mcp_tool_off_the_floor(api):
    _, agent, _ = api
    access_policy.set_delegate(agent, True)
    assert access_policy.is_delegate(agent)
    tool = {"id": "mcp.anything", "execution": execution()}
    assert access_policy.on_floor(tool)
    assert access_policy.resolve(tool, "owner_confirmation", RUN, agent) == "owner_confirmation"
    # The same delegate's "run" still lifts a tool that is off the floor.
    plain = {"id": "echo.plain", "execution": {"type": "local_echo"}}
    assert access_policy.resolve(plain, "owner_confirmation", RUN, agent) == "auto"


def test_an_mcp_invocation_with_a_delegate_run_still_parks_for_the_owner(api, peer):
    client, _, key = api
    imported_and_granted(client, key)
    response = client.post("/v2/owner/access/delegate", json={"enabled": True}, headers=owner(key))
    assert response.status_code == 200 and response.json() == {"delegate": True}
    response = client.post(
        "/v2/tools/mcp.test-echo/invoke",
        json={
            "args": {"arguments": {"text": "hello"}},
            "action_id": "mcp.floor-action",
            "decision": RUN.model_dump(),
        },
        headers={"X-ToolGate-Execution-Key": key},
    )
    assert response.status_code == 200, response.text
    assert response.json()["code"] == "CONFIRMATION_REQUIRED"
    assert not peer.tool_calls
    assert not cp.events(event_type="action_decided")
    listed = client.get("/v2/agent/tools", headers={"X-ToolGate-Execution-Key": key}).json()
    assert {item["id"]: item["sensitive"] for item in listed}["mcp.test-echo"] is True
    floor = client.get("/v2/owner/access", headers=owner(key)).json()["floorExecutions"]
    assert "mcp_http" in floor
