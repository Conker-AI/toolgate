import json

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setenv("TOOLGATE_DOCKER_SOCKET", "/secret/daemon.sock")
    monkeypatch.setenv("TOOLGATE_MANAGED_CONTAINER_IDS", json.dumps(["b" * 64, "a" * 64, "a" * 64]))
    server.ensure_builtin_system_capabilities()
    agent, key = cp.issue_agent_key("Managed", ["tool:system.container-control"])
    return TestClient(server.app), agent, {"X-ToolGate-Execution-Key": key}


def test_targets_are_configured_not_observed_and_require_scope(setup):
    client, agent, headers = setup
    route = "/v2/agent/system/targets"
    assert client.get(route).status_code == 401
    _, other = cp.issue_agent_key("Inventory only", ["tool:system.inventory"])
    assert client.get(route, headers={"X-ToolGate-Execution-Key": other}).status_code == 403
    response = client.get(route, headers=headers)
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["containers"] == ["a" * 64, "b" * 64]
    assert body["observed"] is False and body["requiresApproval"] is True
    assert body["actions"] == ["start", "stop", "restart"]
    assert "secret" not in response.text and "daemon" not in response.text
    cp.revoke_agent_key(agent["id"])
    assert client.get(route, headers=headers).status_code == 401


@pytest.mark.parametrize("config,status", [(None, "not_configured"), ("bad", "invalid_configuration"),
                                         ("[]", "configured")])
def test_configuration_states_are_honest(setup, monkeypatch, config, status):
    client, _, headers = setup
    if config is None:
        monkeypatch.delenv("TOOLGATE_MANAGED_CONTAINER_IDS")
    else:
        monkeypatch.setenv("TOOLGATE_MANAGED_CONTAINER_IDS", config)
    body = client.get("/v2/agent/system/targets", headers=headers).json()
    assert body["status"] == status and body["containers"] == []
    if status != "configured":
        assert body["actions"] == []


def test_disabled_definition_hides_targets(setup):
    client, _, headers = setup
    cp.create_tool({**cp.get("tool", "system.container-control"), "status": "disabled"})
    body = client.get("/v2/agent/system/targets", headers=headers).json()
    assert body["status"] == "disabled" and body["containers"] == body["actions"] == []
