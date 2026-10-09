import copy
import hashlib
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import mcp_imports, publications
from toolgate.executors import mcp_http as mcp

SCHEMA = {
    "type": "object",
    "properties": {"text": {"type": "string", "maxLength": 30}},
    "required": ["text"],
    "additionalProperties": False,
}
URL = "https://mcp.example.test/api/mcp"
OWNER = "owner-mcp-credential-" + "x" * 32
ADMIN = "admin-mcp-credential-" + "a" * 32
SECRET = "private-bearer-" + "s" * 32


class Peer:
    def __init__(self):
        self.schema = copy.deepcopy(SCHEMA)
        self.calls = []
        self.sse = False
        self.bad_identity = False
        self.unknown = False
        self.error = False
        self.extra_tools = []
        self.pages = None
        self.result = None
        self.session = "external-session-id"
        self.modern = False
        self.modern_error = None

    def handle(self, request):
        if request.method == "DELETE":
            assert not self.modern
            assert request.headers["mcp-session-id"] == self.session
            return httpx.Response(405)
        value = json.loads(request.content)
        self.calls.append((value, dict(request.headers)))
        method = value["method"]
        assert request.url == URL
        assert request.headers["accept"] == "application/json, text/event-stream"
        if method == "server/discover" and self.modern_error:
            return httpx.Response(
                400,
                json={
                    "jsonrpc": "2.0",
                    "id": value["id"],
                    "error": {"code": self.modern_error, "message": "Modern error"},
                },
            )
        if method == "server/discover" and not self.modern:
            return httpx.Response(400, json={"detail": "A session must first be initialized"})
        if self.modern:
            assert "mcp-session-id" not in request.headers
            assert request.headers["mcp-method"] == method
            assert request.headers["mcp-protocol-version"] == mcp.MODERN_VERSION
            assert value["params"]["_meta"] == {
                "io.modelcontextprotocol/protocolVersion": mcp.MODERN_VERSION,
                "io.modelcontextprotocol/clientInfo": {"name": "Conker ToolGate", "version": "1"},
                "io.modelcontextprotocol/clientCapabilities": {},
            }
            assert method not in {"initialize", "notifications/initialized"}
        elif method != "initialize":
            assert request.headers["mcp-session-id"] == self.session
            assert request.headers["mcp-protocol-version"] == mcp.VERSION
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "server/discover":
            result = {
                "resultType": "complete",
                "supportedVersions": [mcp.MODERN_VERSION],
                "capabilities": {"tools": {}},
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {"name": "Fixture MCP", "version": "1.0"}
                },
            }
        elif method == "initialize":
            result = {
                "protocolVersion": mcp.VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "Fixture MCP", "version": "1.0"},
                "instructions": "Ignored server instructions",
            }
        elif method == "tools/list":
            result = {
                "tools": [
                    {"name": "echo", "description": "Echo text", "inputSchema": self.schema},
                    *self.extra_tools,
                ]
            }
            if self.pages is not None:
                result = self.pages.pop(0)
        elif method == "tools/call":
            if self.unknown:
                raise httpx.ReadError("remote operation may already have completed")
            assert {key: item for key, item in value["params"].items() if key != "_meta"} == {
                "name": "echo",
                "arguments": {"text": "hello"},
            }
            if self.modern:
                assert request.headers["mcp-name"] == "echo"
            result = self.result or {
                "content": [{"type": "text", "text": "hello"}],
                "isError": self.error,
            }
        else:
            pytest.fail("Unexpected MCP method")
        response = {
            "jsonrpc": "2.0",
            "id": "wrong" if self.bad_identity else value["id"],
            "result": result,
        }
        headers = {"Mcp-Session-Id": self.session} if method == "initialize" else {}
        if self.sse:
            notice = json.dumps(
                {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}
            )
            return httpx.Response(
                200,
                headers={**headers, "Content-Type": "text/event-stream"},
                content=f"data: {notice}\n\ndata: {json.dumps(response)}\n\n".encode(),
            )
        return httpx.Response(200, headers=headers, json=response)

    @property
    def tool_calls(self):
        return [value for value, _ in self.calls if value["method"] == "tools/call"]


@pytest.fixture
def peer(monkeypatch):
    peer = Peer()
    monkeypatch.setattr(mcp, "public_url", lambda _: True)
    monkeypatch.setattr(
        mcp,
        "public_client",
        lambda **kwargs: httpx.Client(
            transport=httpx.MockTransport(peer.handle),
            trust_env=False,
            follow_redirects=False,
            **kwargs,
        ),
    )
    monkeypatch.setattr(mcp.vault, "get_key", lambda _: SECRET)
    return peer


def execution():
    return {
        "type": "mcp_http",
        "url": URL,
        "tool_name": "echo",
        "input_schema": SCHEMA,
        "schema_hash": mcp.schema_hash(SCHEMA),
        "secret_ref": None,
    }


@pytest.mark.parametrize("sse", [False, True])
def test_discovery_and_call_keep_protocol_identity_and_credentials_private(peer, sse):
    peer.sse = sse
    result = mcp.discover(URL, "MCP_BEARER")
    assert result == {
        "schemaVersion": 1,
        "server": {"url": URL, "name": "Fixture MCP", "version": "1.0"},
        "tools": [
            {
                "name": "echo",
                "description": "Echo text",
                "inputSchema": SCHEMA,
                "schemaHash": mcp.schema_hash(SCHEMA),
            }
        ],
    }
    assert SECRET not in json.dumps(result)
    assert all(headers.get("authorization") == "Bearer " + SECRET for _, headers in peer.calls)
    assert mcp.execute(execution(), {"arguments": {"text": "hello"}}) == {
        "ok": True,
        "result": {"content": [{"type": "text", "text": "hello"}], "isError": False},
    }
    assert len(peer.tool_calls) == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/mcp",
        "https://example.com:9443/mcp",
        "https://user:pass@example.com/mcp",
        "https://example.com/mcp?key=secret",
        "https://example.com/mcp#fragment",
    ],
)
def test_nonfixed_destinations_are_rejected_before_network(peer, url):
    with pytest.raises(mcp.MCPError, match="HTTPS"):
        mcp.discover(url)
    assert not peer.calls


def test_private_dns_is_denied_before_transport(peer, monkeypatch):
    monkeypatch.setattr(mcp, "public_url", lambda _: False)
    with pytest.raises(mcp.MCPError) as exc:
        mcp.discover(URL)
    assert exc.value.code == "destination_denied"
    assert not peer.calls


def test_control_credentials_cannot_be_selected_as_external_secrets(peer):
    with pytest.raises(mcp.MCPError) as exc:
        mcp.discover(URL, "TOOLGATE_ADMIN_KEY")
    assert exc.value.code == "invalid_secret_reference"
    assert not peer.calls


def test_missing_secret_uses_fixed_error(peer, monkeypatch):
    def missing(_):
        raise KeyError("private vault location")

    monkeypatch.setattr(mcp.vault, "get_key", missing)
    with pytest.raises(mcp.MCPError) as exc:
        mcp.discover(URL, "MCP_BEARER")
    assert str(exc.value) == "The referenced MCP credential is not available."


@pytest.mark.parametrize(
    "change",
    [
        lambda schema: schema.update({"$ref": "https://metadata.internal/schema"}),
        lambda schema: schema.update({"allOf": [{"type": "object"}]}),
        lambda schema: schema["properties"]["text"].update({"pattern": "(a+)+$"}),
        lambda schema: schema.update({"additionalProperties": {"type": "string"}}),
    ],
)
def test_unsupported_constraints_are_not_silently_weakened(peer, change):
    change(peer.schema)
    catalogue = mcp.discover(URL)
    assert catalogue["tools"] == []
    assert len(catalogue["unsupportedTools"]) == 1
    assert catalogue["unsupportedTools"][0]["name"] == "echo"
    with pytest.raises(mcp.MCPError) as exc:
        mcp.validate_schema(peer.schema)
    assert exc.value.code == "unsupported_schema"
    assert catalogue["unsupportedTools"][0]["reason"] == str(exc.value)


@pytest.mark.parametrize(
    "arguments", [{}, {"text": 8}, {"text": "x" * 31}, {"text": "hello", "extra": True}, []]
)
def test_arguments_are_validated_before_connection(peer, arguments):
    result = mcp.execute(execution(), {"arguments": arguments})
    assert result["ok"] is False
    assert result["error_code"] == "invalid_arguments"
    assert not peer.calls


def test_schema_drift_stops_before_tools_call(peer):
    peer.schema["properties"]["text"]["maxLength"] = 31
    result = mcp.execute(execution(), {"arguments": {"text": "hello"}})
    assert result["error_code"] == "schema_changed"
    assert not peer.tool_calls


def test_is_error_is_an_affirmative_tool_failure(peer):
    peer.error = True
    result = mcp.execute(execution(), {"arguments": {"text": "hello"}})
    assert result["ok"] is False
    assert result["result"]["isError"] is True


def test_lost_reply_after_call_remains_unknown(peer):
    peer.unknown = True
    with pytest.raises(mcp.CallOutcomeUnknown):
        mcp.execute(execution(), {"arguments": {"text": "hello"}})
    assert len(peer.tool_calls) == 1


def test_rpc_identity_mismatch_is_rejected(peer):
    peer.bad_identity = True
    with pytest.raises(mcp.MCPError) as exc:
        mcp.discover(URL)
    assert exc.value.code == "invalid_response"


def test_echoed_auth_secret_is_not_returned(peer):
    peer.result = {"content": [{"type": "text", "text": SECRET}]}
    with pytest.raises(mcp.CallOutcomeUnknown) as exc:
        mcp.execute({**execution(), "secret_ref": "MCP_BEARER"}, {"arguments": {"text": "hello"}})
    assert SECRET not in str(exc.value)


def test_pagination_is_bounded_and_duplicate_names_rejected(peer):
    tool = {"name": "echo", "inputSchema": SCHEMA}
    peer.pages = [{"tools": [tool], "nextCursor": "more"}, {"tools": [tool]}]
    with pytest.raises(mcp.MCPError) as exc:
        mcp.discover(URL)
    assert exc.value.code == "invalid_catalogue"
    peer.pages = [{"tools": [], "nextCursor": "loop"}] * 2
    with pytest.raises(mcp.MCPError) as exc:
        mcp.discover(URL)
    assert exc.value.code == "invalid_catalogue"


def test_response_byte_limit_is_enforced(peer, monkeypatch):
    monkeypatch.setattr(mcp, "MAX_BYTES", 20)
    with pytest.raises(mcp.MCPError) as exc:
        mcp.discover(URL)
    assert exc.value.code == "response_limit"


def test_nested_schema_constraints_are_enforced():
    schema = {
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {"type": "integer", "minimum": 1},
                "maxItems": 3,
                "uniqueItems": True,
            }
        },
        "required": ["items"],
        "additionalProperties": False,
    }
    mcp.validate_arguments(schema, {"items": [1, 2]})
    for value in ([1, 1], [0], [True], [1, 2, 3, 4]):
        with pytest.raises(mcp.MCPError):
            mcp.validate_arguments(schema, {"items": value})


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


@pytest.mark.parametrize("sse", [False, True])
def test_modern_protocol_uses_stateless_per_request_metadata(peer, sse):
    peer.modern, peer.sse = True, sse
    discovery = mcp.discover(URL)
    assert discovery["server"]["name"] == "Fixture MCP"
    assert mcp.execute(execution(), {"arguments": {"text": "hello"}})["ok"] is True
    assert {value["method"] for value, _ in peer.calls} == {
        "server/discover",
        "tools/list",
        "tools/call",
    }
    assert len(peer.tool_calls) == 1


@pytest.mark.parametrize("code", [-32020, -32021, -32022])
def test_modern_protocol_errors_never_fall_back_or_retry(peer, code):
    peer.modern_error = code
    with pytest.raises(mcp.MCPError) as exc:
        mcp.discover(URL)
    assert exc.value.code == "modern_protocol_error"
    assert [value["method"] for value, _ in peer.calls] == ["server/discover"]


def test_modern_input_requests_are_not_silently_completed_or_replayed(peer):
    peer.modern = True
    peer.result = {
        "resultType": "input_required",
        "inputRequests": [{"method": "sampling/createMessage"}],
        "content": [{"type": "text", "text": "not actually finished"}],
    }
    with pytest.raises(mcp.CallOutcomeUnknown):
        mcp.execute(execution(), {"arguments": {"text": "hello"}})
    assert len(peer.tool_calls) == 1


def test_modern_lost_call_result_is_not_retried(peer):
    peer.modern, peer.unknown = True, True
    with pytest.raises(mcp.CallOutcomeUnknown):
        mcp.execute(execution(), {"arguments": {"text": "hello"}})
    assert len(peer.tool_calls) == 1


def test_mcp_parameter_headers_encode_unicode_and_avoid_header_injection():
    schema = {
        "type": "object",
        "properties": {
            "settings": {
                "type": "object",
                "properties": {
                    "region": {"type": "string", "x-mcp-header": "Region"},
                    "count": {"type": "integer", "x-mcp-header": "Count"},
                    "enabled": {"type": "boolean", "x-mcp-header": "Enabled"},
                },
            }
        },
    }
    value = {
        "settings": {"region": "line1\n\u05e9\u05dc\u05d5\u05dd", "count": 42, "enabled": True}
    }
    mcp.validate_arguments(schema, value)
    headers = mcp.parameter_headers(schema, value)
    assert headers["Mcp-Param-Region"].startswith("=?base64?")
    assert "\n" not in headers["Mcp-Param-Region"]
    assert headers["Mcp-Param-Count"] == "42"
    assert headers["Mcp-Param-Enabled"] == "true"
    assert mcp._header_value("=?base64?literal?=") != "=?base64?literal?="
    value["settings"]["count"] = 2**53
    with pytest.raises(mcp.MCPError):
        mcp.validate_arguments(schema, value)


def test_mcp_parameter_headers_reach_modern_calls(peer):
    peer.modern = True
    peer.schema["properties"]["text"]["x-mcp-header"] = "Text"
    definition = {
        **execution(),
        "input_schema": peer.schema,
        "schema_hash": mcp.schema_hash(peer.schema),
    }
    assert mcp.execute(definition, {"arguments": {"text": "hello"}})["ok"] is True
    call = next(headers for value, headers in peer.calls if value["method"] == "tools/call")
    assert call["mcp-param-text"] == "hello"


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "object", "properties": {"a": {"type": "string", "x-mcp-header": "Host\r\nBad"}}},
        {"type": "object", "properties": {"a": {"type": "number", "x-mcp-header": "Amount"}}},
        {
            "type": "object",
            "properties": {
                "a": {"type": "array", "items": {"type": "string", "x-mcp-header": "Item"}}
            },
        },
        {
            "type": "object",
            "properties": {
                "a": {"type": "string", "x-mcp-header": "Same"},
                "b": {"type": "string", "x-mcp-header": "SAME"},
            },
        },
        {"type": "object", "$schema": "https://unknown.example/schema"},
    ],
)
def test_unsupported_or_ambiguous_header_schemas_are_rejected(schema):
    with pytest.raises(mcp.MCPError) as exc:
        mcp.validate_schema(schema)
    assert exc.value.code == "unsupported_schema"


@pytest.mark.parametrize("status", [301, 302, 307, 401, 403, 429, 500])
def test_discovery_does_not_follow_redirects_or_retry_auth_and_server_failures(
    peer, monkeypatch, status
):
    calls = []

    def failure(request):
        calls.append(request)
        return httpx.Response(status, headers={"Location": "https://other.example/mcp"})

    monkeypatch.setattr(
        mcp,
        "public_client",
        lambda **kwargs: httpx.Client(
            transport=httpx.MockTransport(failure),
            follow_redirects=False,
            trust_env=False,
            **kwargs,
        ),
    )
    with pytest.raises(mcp.MCPError):
        mcp.discover(URL, "MCP_BEARER")
    assert len(calls) == 1


def test_schema_hash_failure_and_malformed_numbers_are_bounded():
    with pytest.raises(mcp.MCPError) as exc:
        mcp.validate_execution({**execution(), "schema_hash": "0" * 64})
    assert exc.value.code == "schema_hash_mismatch"
    schema = {"type": "object", "properties": {"big": {"type": "number", "minimum": 10**400}}}
    mcp.validate_schema(schema)
    with pytest.raises(mcp.MCPError):
        mcp.validate_arguments(schema, {"big": float("inf")})


def test_duplicate_json_keys_are_rejected(peer, monkeypatch):
    def duplicate(request):
        identity = json.loads(request.content)["id"]
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=f'{{"jsonrpc":"2.0","id":"{identity}","result":{{}},"result":{{}}}}'.encode(),
        )

    monkeypatch.setattr(
        mcp,
        "public_client",
        lambda **kwargs: httpx.Client(
            transport=httpx.MockTransport(duplicate), trust_env=False, **kwargs
        ),
    )
    with pytest.raises(mcp.MCPError) as exc:
        mcp.discover(URL)
    assert exc.value.code == "invalid_response"


def test_nullable_types_and_const_match_microsoft_catalogue_shape():
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": ["string", "null"], "default": None},
            "SessionId": {
                "type": ["string", "null"],
                "default": "opaque-session",
                "const": "opaque-session",
            },
        },
    }
    mcp.validate_schema(schema)
    mcp.validate_arguments(schema, {"query": None})
    mcp.validate_arguments(schema, {"query": "Azure", "SessionId": "opaque-session"})
    for value in (False, 4, {}):
        with pytest.raises(mcp.MCPError):
            mcp.validate_arguments(schema, {"query": value})
    for value in (None, "other-session"):
        with pytest.raises(mcp.MCPError):
            mcp.validate_arguments(schema, {"SessionId": value})


def test_type_unions_apply_only_constraints_for_the_actual_value_type():
    schema = {
        "type": "object",
        "properties": {
            "value": {
                "type": ["object", "array", "string", "number", "null"],
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
                "additionalProperties": False,
                "items": {"type": "integer"},
                "minLength": 2,
                "minimum": 1,
                "maxItems": 2,
            }
        },
    }
    for value in (None, "ab", 2, {"name": "A"}, [1, 2]):
        mcp.validate_arguments(schema, {"value": value})
    for value in (False, "a", 0, {}, [1, 2, 3], [None]):
        with pytest.raises(mcp.MCPError):
            mcp.validate_arguments(schema, {"value": value})


@pytest.mark.parametrize("types", [[], ["string", "string"], ["string", {}], ["string", "unknown"]])
def test_invalid_type_unions_are_rejected(types):
    with pytest.raises(mcp.MCPError) as exc:
        mcp.validate_schema({"type": "object", "properties": {"value": {"type": types}}})
    assert exc.value.code == "unsupported_schema"


def test_const_and_enum_distinguish_boolean_but_equate_json_numbers():
    schema = {
        "type": "object",
        "properties": {"n": {"type": ["integer", "boolean"], "const": 1, "enum": [1.0]}},
    }
    mcp.validate_arguments(schema, {"n": 1.0})
    with pytest.raises(mcp.MCPError):
        mcp.validate_arguments(schema, {"n": True})
    array = {
        "type": "object",
        "properties": {"list": {"type": "array", "items": {"type": "number"}, "uniqueItems": True}},
    }
    with pytest.raises(mcp.MCPError):
        mcp.validate_arguments(array, {"list": [1, 1.0]})


def test_dynamic_const_changes_still_stop_exact_schema_pinning(peer):
    peer.schema["properties"]["SessionId"] = {
        "type": ["string", "null"],
        "default": "session-a",
        "const": "session-a",
    }
    pinned = copy.deepcopy(peer.schema)
    definition = {**execution(), "input_schema": pinned, "schema_hash": mcp.schema_hash(pinned)}
    peer.schema["properties"]["SessionId"].update(default="session-b", const="session-b")
    result = mcp.execute(definition, {"arguments": {"text": "hello"}})
    assert result["error_code"] == "schema_changed"
    assert not peer.tool_calls


def test_nullable_header_is_omitted_for_null():
    schema = {
        "type": "object",
        "properties": {"name": {"type": ["string", "null"], "x-mcp-header": "Name"}},
    }
    mcp.validate_arguments(schema, {"name": None})
    assert mcp.parameter_headers(schema, {"name": None}) == {}


def test_deepwiki_anyof_catalogue_can_be_discovered_and_validated(peer):
    schema = {
        "type": "object",
        "properties": {
            "repoName": {
                "anyOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}},
                ]
            },
            "question": {"type": "string"},
        },
        "required": ["repoName", "question"],
    }
    peer.schema = schema
    catalogue = mcp.discover(URL)
    assert catalogue["tools"][0]["inputSchema"] == schema
    for repo in ("owner/repo", ["owner/first", "owner/second"]):
        mcp.validate_arguments(schema, {"repoName": repo, "question": "How does it work?"})
    for repo in (None, 7, ["owner/repo", False], {"name": "owner/repo"}):
        with pytest.raises(mcp.MCPError) as exc:
            mcp.validate_arguments(schema, {"repoName": repo, "question": "Question"})
        assert exc.value.code == "invalid_arguments"


def test_anyof_and_oneof_preserve_overlapping_branch_semantics():
    alternatives = [{"type": "integer"}, {"type": "number", "minimum": 0}]
    for keyword in ("anyOf", "oneOf"):
        schema = {"type": "object", "properties": {"value": {keyword: alternatives}}}
        mcp.validate_arguments(schema, {"value": -1})
        mcp.validate_arguments(schema, {"value": 0.5})
        if keyword == "anyOf":
            mcp.validate_arguments(schema, {"value": 1})
        else:
            with pytest.raises(mcp.MCPError):
                mcp.validate_arguments(schema, {"value": 1})
        with pytest.raises(mcp.MCPError):
            mcp.validate_arguments(schema, {"value": False})


def test_alternatives_apply_sibling_constraints_and_validate_every_branch():
    value_schema = {
        "type": "string",
        "maxLength": 4,
        "anyOf": [{"type": "string", "const": "hello"}, {"type": "string", "const": "hi"}],
    }
    schema = {"type": "object", "properties": {"value": value_schema}}
    mcp.validate_arguments(schema, {"value": "hi"})
    for value in ("hello", "no", 4):
        with pytest.raises(mcp.MCPError):
            mcp.validate_arguments(schema, {"value": value})
    value_schema["anyOf"].append({"$ref": "https://schema.example/ref"})
    with pytest.raises(mcp.MCPError) as exc:
        mcp.validate_schema(schema)
    assert exc.value.code == "unsupported_schema"


@pytest.mark.parametrize(
    "alternatives",
    [[], {}, [True], [{"type": "string"}] * 9, [{"type": "string", "x-mcp-header": "Branch"}]],
)
def test_schema_alternatives_are_bounded_and_cannot_add_conditional_headers(alternatives):
    schema = {"type": "object", "properties": {"value": {"anyOf": alternatives}}}
    with pytest.raises(mcp.MCPError) as exc:
        mcp.validate_schema(schema)
    assert exc.value.code == "unsupported_schema"


def test_schema_alternative_work_is_bounded():
    schema = {
        "type": "object",
        "properties": {
            "values": {
                "type": "array",
                "items": {"oneOf": [{"type": "number"}] * 7 + [{"type": "string"}]},
            }
        },
    }
    mcp.validate_arguments(schema, {"values": ["x"] * 100})
    with pytest.raises(mcp.MCPError) as exc:
        mcp.validate_arguments(schema, {"values": ["x"] * 2300})
    assert exc.value.code == "value_too_complex"


def test_alternative_schema_drift_is_not_normalized(peer):
    peer.schema["properties"]["text"] = {
        "anyOf": [{"type": "string", "maxLength": 30}, {"type": "null"}]
    }
    pinned = copy.deepcopy(peer.schema)
    definition = {**execution(), "input_schema": pinned, "schema_hash": mcp.schema_hash(pinned)}
    peer.schema["properties"]["text"]["anyOf"][0]["maxLength"] = 31
    result = mcp.execute(definition, {"arguments": {"text": "hello"}})
    assert result["error_code"] == "schema_changed"
    assert not peer.tool_calls


def unsupported_tool(name="formatted"):
    return {
        "name": name,
        "description": "Requires a schema keyword this client does not support",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string", "format": "uri"}},
        },
    }


def test_unsupported_catalogue_entries_do_not_block_supported_discovery_or_execution(peer):
    peer.extra_tools = [unsupported_tool()]
    result = mcp.discover(URL)
    assert [tool["name"] for tool in result["tools"]] == ["echo"]
    assert [tool["name"] for tool in result["unsupportedTools"]] == ["formatted"]
    assert "unsupported constraints" in result["unsupportedTools"][0]["reason"]
    assert set(result["unsupportedTools"][0]) == {"name", "reason"}
    assert mcp.execute(execution(), {"arguments": {"text": "hello"}})["ok"] is True
    assert len(peer.tool_calls) == 1


def test_selected_tool_becoming_unsupported_blocks_import_and_execution(api, peer):
    peer.schema["properties"]["text"]["format"] = "uri"
    result = mcp.execute(execution(), {"arguments": {"text": "hello"}})
    assert result["error_code"] == "unsupported_schema"
    client, _, _ = api
    response = client.post("/v2/owner/mcp/import", json=import_body(), headers=owner_headers())
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "unsupported_schema"
    assert not peer.tool_calls


def test_unsupported_entries_cannot_bypass_duplicate_or_catalogue_bounds(peer):
    peer.pages = [
        {"tools": [unsupported_tool()], "nextCursor": "more"},
        {"tools": [unsupported_tool()]},
    ]
    with pytest.raises(mcp.MCPError) as exc:
        mcp.discover(URL)
    assert exc.value.code == "invalid_catalogue"
    peer.pages = [
        {"tools": [unsupported_tool(f"first-{i}") for i in range(33)], "nextCursor": "more"},
        {"tools": [unsupported_tool(f"second-{i}") for i in range(32)]},
    ]
    with pytest.raises(mcp.MCPError) as exc:
        mcp.discover(URL)
    assert exc.value.code == "catalogue_limit"


@pytest.mark.parametrize("sse", [False, True])
@pytest.mark.parametrize("in_key", [False, True])
def test_json_escaped_bearer_echo_in_decoded_keys_or_values_is_withheld(
    peer, monkeypatch, sse, in_key
):
    secret = 'dummy-bearer-"quote"-\\backslash'
    monkeypatch.setattr(mcp.vault, "get_key", lambda _: secret)
    peer.sse = sse
    peer.result = {"content": [{"type": "text", "text": "Public result"}]}
    peer.result["structuredContent"] = (
        {f"prefix:{secret}:suffix": "value"}
        if in_key
        else {"nested": [{"value": f"prefix:{secret}:suffix"}]}
    )
    with pytest.raises(mcp.CallOutcomeUnknown) as exc:
        mcp.execute({**execution(), "secret_ref": "MCP_BEARER"}, {"arguments": {"text": "hello"}})
    assert len(peer.tool_calls) == 1
    assert secret not in str(exc.value)
    assert exc.value.__cause__.code == "credential_echo"
    assert (
        str(exc.value.__cause__)
        == "The MCP server echoed its credential; the response was withheld."
    )


def test_json_escaped_bearer_in_catalogue_is_withheld_before_discovery(peer, monkeypatch):
    secret = 'dummy-bearer-"quote"'
    monkeypatch.setattr(mcp.vault, "get_key", lambda _: secret)
    peer.schema["properties"]["text"]["default"] = secret
    with pytest.raises(mcp.MCPError) as exc:
        mcp.discover(URL, "MCP_BEARER")
    assert exc.value.code == "credential_echo"
    assert secret not in str(exc.value)
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
