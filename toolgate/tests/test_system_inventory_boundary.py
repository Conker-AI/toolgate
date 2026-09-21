"""System telemetry uses ordinary scoped, durable ToolGate invocation."""

import copy
import json

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.executors import system_inventory
from toolgate.tests.test_system_inventory import Stream, envelope


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "system.db")
    monkeypatch.setenv("TOOLGATE_SYSTEMGATE_URL", "http://systemgate.internal:8040")
    monkeypatch.setenv("TOOLGATE_SYSTEMGATE_KEY", "synthetic-private-key")
    server.ensure_builtin_system_capabilities()
    actual = system_inventory.collect
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, stream=Stream([json.dumps(envelope()).encode()]))

    monkeypatch.setattr(
        system_inventory,
        "collect",
        lambda limit=100: actual(
            limit,
            transport=httpx.MockTransport(handler),
        ),
    )
    return requests


def test_actual_transport_requires_scope_and_replays_receipt(setup):
    agent, raw = cp.issue_agent_key("Inventory reader", ["tool:system.inventory"])
    _, denied = cp.issue_agent_key("Other reader", ["tool:research.search"])
    client = TestClient(server.app)
    body = {"action_id": "inventory-read-01", "args": {"limit": 20}}
    route = "/v2/tools/system.inventory/invoke"
    assert client.post(route, json=body).status_code == 401
    assert (
        client.post(
            route, json=body, headers={"X-ToolGate-Execution-Key": denied}
        ).status_code
        == 403
    )
    assert setup == []
    headers = {"X-ToolGate-Execution-Key": raw}
    first = client.post(route, json=body, headers=headers)
    assert first.status_code == 200 and first.json()["code"] == "OK"
    assert first.json()["result"]["inventory"]["mode"] == "observed"
    assert client.post(route, json=body, headers=headers).json() == first.json()
    assert len(setup) == 1 and setup[0].url.path == "/runtime"
    assert "synthetic-private-key" not in first.text
    cp.revoke_agent_key(agent["id"])
    assert (
        client.post(
            route, json={**body, "action_id": "inventory-read-02"}, headers=headers
        ).status_code
        == 401
    )
    assert len(setup) == 1


def test_owner_disabled_definition_is_not_reenabled_on_registration(setup):
    tool = cp.get("tool", "system.inventory")
    cp.create_tool(
        {**tool, "status": "disabled", "authorization": "owner_confirmation"}
    )
    server.ensure_builtin_system_capabilities()
    saved = cp.get("tool", "system.inventory")
    assert saved["status"] == "disabled"
    assert saved["authorization"] == "owner_confirmation"


def test_definition_and_dispatch_cannot_choose_private_destination(setup):
    tool = cp.get("tool", "system.inventory")
    assert server.tool_definition_errors(tool) == []
    changed = copy.deepcopy(tool)
    changed["execution"]["url"] = "http://another.internal/secrets"
    assert server.tool_definition_errors(changed)
    with pytest.raises(HTTPException):
        server._dispatch_tool(changed, {})
    with pytest.raises(HTTPException):
        server._dispatch_tool(tool, {"path": "/files"})
    assert setup == []


def test_failed_read_is_durable_failure_not_unknown_effect(setup, monkeypatch):
    agent, _ = cp.issue_agent_key("Inventory reader", ["tool:system.inventory"])

    def unavailable(limit):
        raise system_inventory.InventoryError("not_configured")

    monkeypatch.setattr(system_inventory, "collect", unavailable)
    body = server.V2Invoke(action_id="unconfigured-inventory", args={})
    result = server.run_tool("system.inventory", body, agent)
    assert result["code"] == "TOOL_UNAVAILABLE"
    assert result["result"]["error_code"] == "not_configured"
    assert server.run_tool("system.inventory", body, agent) == result
    assert setup == []
