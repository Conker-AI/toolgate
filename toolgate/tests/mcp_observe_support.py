"""Fixtures and helpers the Observe tests share (split from test_mcp_observe.py; a pure move)."""

import hashlib

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import mcp_imports
from toolgate.core import mcp_observe as observe
from toolgate.executors import mcp_http as mcp
from toolgate.tests.mcp_peer import ADMIN, OWNER, SCHEMA, URL

# Only a name led by a read verb can be Observe, so the fixture tool reads in all its names.
TOOL = "mcp.get-echo"
READ_NAME = "get_echo"


@pytest.fixture
def api(tmp_path, monkeypatch, peer):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(server.vault, "get_control_key", lambda _: ADMIN)
    monkeypatch.setenv("TOOLGATE_OWNER_KEY_SHA256", hashlib.sha256(OWNER.encode()).hexdigest())
    peer.tool = READ_NAME
    agent, key = cp.issue_agent_key("Conker", [])
    client = TestClient(server.app)
    yield client, agent, key
    client.close()


def owner(key=None):
    return {"X-ToolGate-Owner-Key": OWNER, **({"X-ToolGate-Execution-Key": key} if key else {})}


def import_body(**changes):
    return {
        "id": TOOL,
        "name": "Get echo",
        "description": "Echo through MCP",
        "url": URL,
        "tool_name": READ_NAME,
        "input_schema": SCHEMA,
        "schema_hash": mcp.schema_hash(SCHEMA),
        **changes,
    }


def imported(api, **changes):
    client, _, key = api
    response = client.post("/v2/owner/mcp/import", json=import_body(**changes), headers=owner())
    assert response.status_code == 200, response.text
    tool = response.json()["tool"]
    response = client.post(
        f"/v2/owner/mcp/tools/{tool['id']}/access",
        headers=owner(key),
        json={"enabled": True, "expected_digest": tool["digest"]},
    )
    assert response.status_code == 200, response.text
    return tool


def set_class(api, read_class, tool_id=TOOL, version=None):
    client, _, _ = api
    version = version if version is not None else cp.get("tool", tool_id)["version"]
    return client.post(
        f"/v2/owner/mcp/tools/{tool_id}/class",
        json={"read_class": read_class, "expected_version": version},
        headers=owner(),
    )


def invoke(api, action="mcp.observe-1", text="hello", tool_id=TOOL, **extra):
    client, _, key = api
    body = {"args": {"arguments": {"text": text}}, "action_id": action, **extra}
    return client.post(
        f"/v2/tools/{tool_id}/invoke", json=body, headers={"X-ToolGate-Execution-Key": key}
    )


def listed_class(api, tool_id=TOOL):
    tools = {tool["id"]: tool for tool in mcp_imports.list_tools()["tools"]}
    return tools[tool_id]["read_class"]


def confirmed(execution, description="Echo text"):
    """A stored Observe as the class route writes it, for the advert the fixture server gives."""
    return {
        "class": "observe",
        **observe.bound(execution),
        "advert_hash": mcp.advert_hash(description, None),
        "read_only_hint": False,
    }


def requests():
    return [item for item in cp.list_objects("request") if item.get("kind") == "verification"]


def inject(tool_id, **fields):
    """Write a stored tool directly, as only a damaged database or a future bug could."""
    tool = cp.get("tool", tool_id)
    body = {key: value for key, value in tool.items() if key not in {"created_at", "updated_at"}}
    cp._put("tool", tool_id, {**body, **fields}, expected_version=tool["version"])


def observe_execution():
    return {
        "type": "mcp_http",
        "url": URL,
        "tool_name": READ_NAME,
        "input_schema": SCHEMA,
        "schema_hash": mcp.schema_hash(SCHEMA),
        "secret_ref": None,
    }
