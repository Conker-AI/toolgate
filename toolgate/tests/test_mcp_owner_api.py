"""Owner MCP routes end to end: discovery, import, grants, approval-bound invocation and revision-bound state."""

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import mcp_imports, publications
from toolgate.executors import mcp_http as mcp
from toolgate.tests.mcp_peer import (
    ADMIN,
    OWNER,
    SCHEMA,
    SECRET,
    URL,
    execution,
    peer,  # noqa: F401 - pytest fixture used by name
)


@pytest.fixture
def api(tmp_path, monkeypatch, peer):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(server.vault, "get_control_key", lambda _: ADMIN)
    monkeypatch.setenv("TOOLGATE_OWNER_KEY_SHA256", hashlib.sha256(OWNER.encode()).hexdigest())
    agent, key = cp.issue_agent_key("Conker", [])
    client = TestClient(server.app)
    yield client, agent, key
    client.close()


def owner_headers(key=None):
    return {"X-ToolGate-Owner-Key": OWNER, **({"X-ToolGate-Execution-Key": key} if key else {})}


def import_body():
    return {
        "id": "mcp.test-echo",
        "name": "External echo",
        "description": "Echo through MCP",
        "url": URL,
        "tool_name": "echo",
        "input_schema": SCHEMA,
        "schema_hash": mcp.schema_hash(SCHEMA),
    }


def imported(api):
    client, _, _ = api
    response = client.post("/v2/owner/mcp/import", json=import_body(), headers=owner_headers())
    assert response.status_code == 200, response.text
    return response.json()["tool"]


def grant(api, tool):
    client, _, key = api
    response = client.post(
        "/v2/owner/mcp/tools/mcp.test-echo/access",
        headers=owner_headers(key),
        json={"enabled": True, "expected_digest": tool["digest"]},
    )
    assert response.status_code == 200, response.text
    assert response.json()["enabled"] is True


def invoke(api, approval=None):
    client, _, key = api
    body = {"args": {"arguments": {"text": "hello"}}, "action_id": "mcp.test-action"}
    if approval:
        body["approval_request_id"] = approval
    return client.post(
        "/v2/tools/mcp.test-echo/invoke", json=body, headers={"X-ToolGate-Execution-Key": key}
    )


def approve(api):
    response = invoke(api)
    assert response.status_code == 200, response.text
    assert response.json()["code"] == "CONFIRMATION_REQUIRED"
    identity = response.json()["request_id"]
    cp.decide_request(identity, "approved", "owner")
    return identity


def test_discovery_is_owner_only_and_rejects_unknown_fields(api, peer):
    client, _, key = api
    for headers in ({}, {"X-ToolGate-Key": ADMIN}, {"X-ToolGate-Execution-Key": key}):
        assert (
            client.post("/v2/owner/mcp/discover", json={"url": URL}, headers=headers).status_code
            == 401
        )
    assert not peer.calls
    response = client.post(
        "/v2/owner/mcp/discover", json={"url": URL, "token": SECRET}, headers=owner_headers()
    )
    assert response.status_code == 422
    assert SECRET not in response.text
    assert (
        client.post(
            "/v2/owner/mcp/discover", json={"url": URL}, headers=owner_headers()
        ).status_code
        == 200
    )


def test_import_is_new_only_published_and_grants_nothing(api, peer):
    client, _agent, key = api
    tool = imported(api)
    assert tool["authorization"] == "owner_confirmation"
    assert tool["version"] == 1
    assert publications.get("tool", tool["id"], 1, published=True)
    assert cp.authenticate_agent(key)["scopes"] == []
    assert invoke(api).status_code == 403
    assert not peer.tool_calls
    assert (
        client.post("/v2/owner/mcp/import", json=import_body(), headers=owner_headers()).status_code
        == 409
    )
    listed = client.get("/v2/owner/mcp/tools", headers=owner_headers()).json()
    assert listed == {"schemaVersion": 1, "tools": [tool]}
    cp.remove("tool", tool["id"])
    assert (
        client.post("/v2/owner/mcp/import", json=import_body(), headers=owner_headers()).status_code
        == 409
    )


def test_grant_requires_both_channels_and_exact_definition(api):
    client, _, key = api
    tool = imported(api)
    path = "/v2/owner/mcp/tools/mcp.test-echo/access"
    body = {"enabled": True, "expected_digest": tool["digest"]}
    assert client.post(path, json=body, headers=owner_headers()).status_code == 401
    assert (
        client.post(path, json=body, headers={"X-ToolGate-Execution-Key": key}).status_code == 401
    )
    assert (
        client.post(
            path, json={**body, "expected_digest": "0" * 64}, headers=owner_headers(key)
        ).status_code
        == 409
    )
    grant(api, tool)
    value = client.get(path, headers=owner_headers(key)).json()
    assert value["requiredScope"] == "tool:mcp.test-echo" and value["enabled"] is True
    value = client.post(path, json={**body, "enabled": False}, headers=owner_headers(key)).json()
    assert value["enabled"] is False


def test_broad_grant_cannot_be_falsely_revoked(api):
    client, agent, key = api
    tool = imported(api)
    cp.update_agent_key_scopes(agent["id"], ["tool:mcp.*"])
    response = client.post(
        "/v2/owner/mcp/tools/mcp.test-echo/access",
        headers=owner_headers(key),
        json={"enabled": False, "expected_digest": tool["digest"]},
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "broad_execution_grant"


def test_approval_is_required_and_exact_invocation_is_journaled_once(api, peer):
    tool = imported(api)
    grant(api, tool)
    approval = approve(api)
    assert not peer.tool_calls
    result = invoke(api, approval)
    assert result.status_code == 200, result.text
    assert result.json()["code"] == "OK"
    assert invoke(api, approval).json() == result.json()
    assert len(peer.tool_calls) == 1


def test_unknown_call_outcome_is_durable_and_not_repeated(api, peer):
    tool = imported(api)
    grant(api, tool)
    approval = approve(api)
    peer.unknown = True
    result = invoke(api, approval)
    assert result.status_code == 200
    assert result.json()["code"] == "OUTCOME_UNKNOWN"
    assert invoke(api, approval).json() == result.json()
    assert len(peer.tool_calls) == 1


def test_schema_drift_receipt_confirms_no_external_call(api, peer):
    tool = imported(api)
    grant(api, tool)
    approval = approve(api)
    peer.schema["properties"]["text"]["maxLength"] = 29
    result = invoke(api, approval).json()
    assert result["code"] == "TOOL_UNAVAILABLE"
    assert result["result"]["error_code"] == "schema_changed"
    assert not peer.tool_calls


def test_state_is_revision_bound_and_revokes_published_tool(api):
    client, _, _ = api
    tool = imported(api)
    grant(api, tool)
    path = "/v2/owner/mcp/tools/mcp.test-echo/state"
    response = client.post(
        path, json={"enabled": False, "expected_digest": tool["digest"]}, headers=owner_headers()
    )
    assert response.status_code == 200, response.text
    disabled = response.json()["tool"]
    assert disabled["version"] == 2 and disabled["status"] == "disabled"
    assert invoke(api).status_code == 403
    with cp._conn() as conn, pytest.raises(publications.PublicationInvalid):
        publications.for_execution(conn, "tool", tool["id"], 1)
    assert (
        client.post(
            path, json={"enabled": True, "expected_digest": tool["digest"]}, headers=owner_headers()
        ).status_code
        == 409
    )
    response = client.post(
        path, json={"enabled": True, "expected_digest": disabled["digest"]}, headers=owner_headers()
    )
    assert response.status_code == 200, response.text
    assert response.json()["tool"]["version"] == 3


def test_invalid_definition_cannot_relax_owner_confirmation(api):
    client, _, _ = api
    tool = {
        "id": "mcp.bad",
        "name": "Bad",
        "description": "Bad",
        "inputs": [{"name": "arguments", "type": "object", "required": True}],
        "authorization": "auto",
        "execution": execution(),
    }
    response = client.post("/v2/tools", json=tool, headers={"X-ToolGate-Key": ADMIN})
    assert response.status_code == 422
    assert "owner_confirmation" in response.text


def test_import_model_rejects_reserved_non_mcp_ids():
    with pytest.raises(ValueError):
        mcp_imports.Import.model_validate({**import_body(), "id": "system.inventory"})


def test_selected_tool_becoming_unsupported_blocks_import_and_execution(api, peer):
    peer.schema["properties"]["text"]["format"] = "uri"
    result = mcp.execute(execution(), {"arguments": {"text": "hello"}})
    assert result["error_code"] == "unsupported_schema"
    client, _, _ = api
    response = client.post("/v2/owner/mcp/import", json=import_body(), headers=owner_headers())
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "unsupported_schema"
    assert not peer.tool_calls


def test_imported_schema_description_preserves_unicode_without_ascii_expansion(api, peer):
    for i in range(4):
        peer.schema["properties"][f"value{i}"] = {"type": "string", "description": "界" * 2000}
    body = {
        **import_body(),
        "input_schema": peer.schema,
        "schema_hash": mcp.schema_hash(peer.schema),
    }
    client, _, _ = api
    response = client.post("/v2/owner/mcp/import", json=body, headers=owner_headers())
    assert response.status_code == 200, response.text
    published = publications.get("tool", body["id"], 1, published=True)
    description = published["definition"]["inputs"][0]["description"]
    assert "界" in description and "\\u754c" not in description
    assert len(description.encode("utf-8")) < 32768
    assert json.loads(description.split(": ", 1)[1]) == peer.schema
