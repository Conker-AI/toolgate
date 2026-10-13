import copy
import json

import httpx
import pytest

from toolgate.executors import mcp_http as mcp
from toolgate.tests.mcp_peer import (
    SCHEMA,
    SECRET,
    URL,
    execution,
    peer,  # noqa: F401 - pytest fixture used by name
    unsupported_tool,
)


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


def test_unsupported_catalogue_entries_do_not_block_supported_discovery_or_execution(peer):
    peer.extra_tools = [unsupported_tool()]
    result = mcp.discover(URL)
    assert [tool["name"] for tool in result["tools"]] == ["echo"]
    assert [tool["name"] for tool in result["unsupportedTools"]] == ["formatted"]
    assert "unsupported constraints" in result["unsupportedTools"][0]["reason"]
    assert set(result["unsupportedTools"][0]) == {"name", "reason"}
    assert mcp.execute(execution(), {"arguments": {"text": "hello"}})["ok"] is True
    assert len(peer.tool_calls) == 1


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


