import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.executors import filesystem_inventory as files

TOOL = "system.files-list"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setenv("TOOLGATE_FILE_ROOTS", json.dumps({"project": "/configured/project"}))
    server.ensure_builtin_system_capabilities()
    agent, key = cp.issue_agent_key("Directory reader", [f"tool:{TOOL}"])
    calls = []

    def listing(*args):
        calls.append(args)
        return {"mode": "observed", "rootId": "project", "path": "", "entries": [],
                "truncated": False, "sampledAt": "2026-09-21T12:00:00+00:00"}

    monkeypatch.setattr(files, "list_directory", listing)
    return agent, key, calls


def test_read_requires_scope_and_reuses_saved_receipt(setup):
    agent, _, calls = setup
    other, _ = cp.issue_agent_key("Inventory reader", ["tool:system.inventory"])
    body = server.V2Invoke(action_id="listing-01", args={"root_id": "project"})
    with pytest.raises(HTTPException):
        server.run_tool(TOOL, body, other)
    first = server.run_tool(TOOL, body, agent)
    assert first["code"] == "OK" and calls == [("project", "", 200)]
    assert server.run_tool(TOOL, body, agent) == first and len(calls) == 1
    cp.revoke_agent_key(agent["id"])
    with pytest.raises(HTTPException):
        server.run_tool(TOOL, body.model_copy(update={"action_id": "listing-02"}), agent)


def test_reserved_name_and_root_override_are_rejected(setup):
    _, _, calls = setup
    tool = cp.get("tool", TOOL)
    assert server.tool_definition_errors(tool) == []
    for execution in ({"type": "echo"}, {"type": "filesystem_inventory", "root": "/"}):
        changed = {**tool, "execution": execution}
        assert server.tool_definition_errors(changed)
        assert server._dispatch_tool(changed, {"root_id": "project"})["ok"] is False
    assert server._dispatch_tool(tool, {"root_id": "project", "command": "read"})["ok"] is False
    assert calls == []


def test_root_discovery_is_scoped_and_configuration_only(setup):
    _, key, calls = setup
    client = TestClient(server.app)
    route = "/v2/agent/system/file-roots"
    assert client.get(route).status_code == 401
    response = client.get(route, headers={"X-ToolGate-Execution-Key": key})
    assert response.json()["mode"] == "configured"
    assert response.headers["cache-control"] == "no-store" and calls == []
    cp.create_tool({**cp.get("tool", TOOL), "status": "disabled"})
    server.ensure_builtin_system_capabilities()
    assert client.get(route, headers={"X-ToolGate-Execution-Key": key}).json()["roots"] == []


def test_failed_listing_is_known_failure_with_static_receipt(setup, monkeypatch):
    agent, _, calls = setup

    def unavailable(*args):
        calls.append(args)
        raise files.FileError("unavailable")

    monkeypatch.setattr(files, "list_directory", unavailable)
    body = server.V2Invoke(action_id="listing-failed", args={"root_id": "project"})
    result = server.run_tool(TOOL, body, agent)
    assert result["code"] == "TOOL_UNAVAILABLE"
    assert result["result"]["error_code"] == "unavailable"
    assert server.run_tool(TOOL, body, agent) == result and len(calls) == 1
