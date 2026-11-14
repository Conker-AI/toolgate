"""MCP over HTTP against a server that answers wrongly: malformed envelopes, server-initiated
requests, bad session headers, compressed or non-JSON bodies, hostile catalogues and tool
results. Each answer ends in a fixed refusal; nothing the server sent is trusted, and a call that
was already sent is reported as unknown rather than retried. Uses the scripted peer."""

from __future__ import annotations

import json

import httpx
import pytest

from toolgate.executors import mcp_http as mcp
from toolgate.executors.mcp_http import CallOutcomeUnknown, MCPError
from toolgate.tests.mcp_peer import (
    SCHEMA,
    SECRET,
    URL,
    execution,
    peer,  # noqa: F401 - pytest fixture used by name
)


def tamper(monkeypatch, peer, method, change):
    """Let the peer answer `method`, then hand its JSON answer to `change` (which returns a
    new answer, an `httpx.Response`, or raises)."""
    original = peer.handle

    def handle(request):
        response = original(request)
        if request.method != "POST":
            return change("DELETE", request, response) if method == "DELETE" else response
        sent = json.loads(request.content)
        if sent["method"] != method:
            return response
        outcome = change(sent, request, response)
        return outcome if isinstance(outcome, httpx.Response) else httpx.Response(200, json=outcome)

    monkeypatch.setattr(
        mcp,
        "public_client",
        lambda **kwargs: httpx.Client(
            transport=httpx.MockTransport(handle), trust_env=False, follow_redirects=False, **kwargs
        ),
    )


def answered(response):
    return json.loads(response.content)


def refused_code(callable_):
    with pytest.raises(MCPError) as error:
        callable_()
    return error.value.code


# Destinations and definitions


@pytest.mark.parametrize(
    "url",
    [
        None,
        7,
        "",
        "https://example.com/" + "a" * 2100,
        "https://exa mple.com/mcp",
        "https://example.com/mcp\n",
    ],
)
def test_a_destination_that_is_not_a_plain_bounded_string_is_refused(peer, url):
    assert refused_code(lambda: mcp.destination(url)) == "invalid_destination"
    assert not peer.calls


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com:notaport/mcp",
        "https://example.com\\@evil.test/mcp",
        "https:///mcp",
        "ftp://example.com/mcp",
    ],
)
def test_a_destination_that_does_not_parse_as_a_fixed_https_endpoint_is_refused(peer, url):
    assert refused_code(lambda: mcp.destination(url)) == "invalid_destination"


@pytest.mark.parametrize("name", ["", "has space", "x" * 200, 5, None])
def test_a_definition_with_an_unusable_tool_name_is_refused(peer, name):
    definition = {**execution(), "tool_name": name}
    result = mcp.execute(definition, {"arguments": {"text": "hello"}})
    assert result["ok"] is False and result["error_code"] == "invalid_definition"
    assert not peer.calls


def test_a_definition_of_another_type_is_refused(peer):
    result = mcp.execute({**execution(), "type": "http"}, {"arguments": {"text": "hello"}})
    assert result["error_code"] == "invalid_definition"


@pytest.mark.parametrize(
    "arguments", [None, [], {}, {"arguments": {"text": "hello"}, "extra": 1}, "text"]
)
def test_a_call_must_carry_only_the_arguments_object(peer, arguments):
    result = mcp.execute(execution(), arguments)
    assert result == {
        "ok": False,
        "error": "Provide only the arguments object.",
        "error_code": "invalid_arguments",
    }
    assert not peer.calls


@pytest.mark.parametrize(
    "secret", ["short", "x" * 9000, "has space in it ok", "non-ascii-é-credential"]
)
def test_a_bearer_credential_that_is_not_bounded_ascii_is_never_sent(peer, monkeypatch, secret):
    monkeypatch.setattr(mcp.vault, "get_key", lambda _: secret)
    assert refused_code(lambda: mcp.discover(URL, "MCP_BEARER")) == "invalid_secret"
    assert not peer.calls


# Handshake answers


def test_a_modern_server_that_does_not_list_the_supported_version_is_refused(peer, monkeypatch):
    peer.modern = True

    def change(sent, request, response):
        body = answered(response)
        body["result"]["supportedVersions"] = ["1999-01-01"]
        return body

    tamper(monkeypatch, peer, "server/discover", change)
    assert refused_code(lambda: mcp.discover(URL)) == "unsupported_server"


def test_a_modern_server_with_malformed_metadata_is_refused(peer, monkeypatch):
    peer.modern = True

    def change(sent, request, response):
        body = answered(response)
        body["result"]["_meta"] = ["not", "a", "mapping"]
        return body

    tamper(monkeypatch, peer, "server/discover", change)
    assert refused_code(lambda: mcp.discover(URL)) == "invalid_server"


@pytest.mark.parametrize("capabilities", [None, [], {}, {"tools": []}, {"resources": {}}])
@pytest.mark.parametrize("modern", [False, True])
def test_a_server_that_does_not_advertise_tools_is_refused(peer, monkeypatch, capabilities, modern):
    peer.modern = modern

    def change(sent, request, response):
        body = answered(response)
        body["result"]["capabilities"] = capabilities
        return body

    tamper(monkeypatch, peer, "server/discover" if modern else "initialize", change)
    assert refused_code(lambda: mcp.discover(URL)) == "unsupported_server"


@pytest.mark.parametrize(
    "info",
    [
        None,
        "text",
        {},
        {"name": "x"},
        {"name": "", "version": "1"},
        {"name": "x" * 201, "version": "1"},
        {"name": "x", "version": 3},
    ],
)
def test_a_server_that_names_itself_badly_is_refused(peer, monkeypatch, info):
    def change(sent, request, response):
        body = answered(response)
        body["result"]["serverInfo"] = info
        return body

    tamper(monkeypatch, peer, "initialize", change)
    assert refused_code(lambda: mcp.discover(URL)) == "invalid_server"


def test_a_session_that_cannot_be_closed_still_returns_the_catalogue(peer, monkeypatch):
    def change(sent, request, response):
        raise httpx.ConnectError("closed early")

    tamper(monkeypatch, peer, "DELETE", change)
    assert [tool["name"] for tool in mcp.discover(URL)["tools"]] == ["echo"]


# Envelopes


def envelope(**fields):
    def change(sent, request, response):
        return {"jsonrpc": "2.0", "id": sent["id"], **fields}

    return change


@pytest.mark.parametrize(
    "answer",
    [
        ["not", "an", "object"],
        {"jsonrpc": "1.0", "id": 1, "result": {}},
        {"id": 1, "result": {}},
    ],
)
def test_an_answer_that_is_not_a_json_rpc_envelope_is_refused(peer, monkeypatch, answer):
    tamper(monkeypatch, peer, "tools/list", lambda *_: answer)
    assert refused_code(lambda: mcp.discover(URL)) == "invalid_response"


def test_a_server_request_in_place_of_an_answer_is_refused(peer, monkeypatch):
    def change(sent, request, response):
        return {"jsonrpc": "2.0", "id": 99, "method": "sampling/createMessage", "params": {}}

    tamper(monkeypatch, peer, "tools/list", change)
    assert refused_code(lambda: mcp.discover(URL)) == "unsupported_server_request"


def test_a_notification_alone_never_completes_a_request(peer, monkeypatch):
    def change(sent, request, response):
        return {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}

    tamper(monkeypatch, peer, "tools/list", change)
    assert refused_code(lambda: mcp.discover(URL)) == "incomplete_response"


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"result": {}, "error": {"code": 1, "message": "both"}},
    ],
)
def test_an_answer_with_neither_or_both_of_result_and_error_is_refused(peer, monkeypatch, fields):
    tamper(monkeypatch, peer, "tools/list", envelope(**fields))
    assert refused_code(lambda: mcp.discover(URL)) == "invalid_response"


def test_an_rpc_error_is_reported_without_the_servers_wording(peer, monkeypatch):
    tamper(
        monkeypatch,
        peer,
        "tools/list",
        envelope(error={"code": -32000, "message": "internal path /srv/x"}),
    )
    with pytest.raises(MCPError) as error:
        mcp.discover(URL)
    assert error.value.code == "rpc_error" and "/srv/x" not in str(error.value)


@pytest.mark.parametrize("result", ["text", ["list"], 5, None])
def test_a_result_that_is_not_an_object_is_refused(peer, monkeypatch, result):
    tamper(monkeypatch, peer, "tools/list", envelope(result=result))
    assert refused_code(lambda: mcp.discover(URL)) == "invalid_response"


def test_a_deferred_result_is_refused_and_no_follow_up_is_sent(peer, monkeypatch):
    tamper(
        monkeypatch,
        peer,
        "tools/list",
        envelope(result={"resultType": "input_required", "tools": []}),
    )
    assert refused_code(lambda: mcp.discover(URL)) == "unsupported_input_request"
    assert [call[0]["method"] for call in peer.calls].count("tools/list") == 1


# Transport details


def test_a_compressed_body_is_refused(peer, monkeypatch):
    def change(sent, request, response):
        return httpx.Response(
            200,
            headers={"content-encoding": "gzip", "content-type": "application/json"},
            content=b"{}",
        )

    tamper(monkeypatch, peer, "tools/list", change)
    assert refused_code(lambda: mcp.discover(URL)) in {"unsupported_encoding", "transport_error"}


@pytest.mark.parametrize("content_type", ["text/html", "text/plain", "application/xml", ""])
def test_a_body_that_is_neither_json_nor_an_event_stream_is_refused(
    peer, monkeypatch, content_type
):
    def change(sent, request, response):
        return httpx.Response(
            200,
            headers={"content-type": content_type} if content_type else {},
            content=b"<html>login</html>",
        )

    tamper(monkeypatch, peer, "tools/list", change)
    assert refused_code(lambda: mcp.discover(URL)) == "invalid_response"


@pytest.mark.parametrize("session", ["has a space", "x" * 300])
def test_a_session_id_with_unsafe_characters_or_length_is_refused(peer, monkeypatch, session):
    original = peer.session
    peer.session = session

    def change(sent, request, response):
        return response

    tamper(monkeypatch, peer, "initialize", change)
    assert refused_code(lambda: mcp.discover(URL)) == "invalid_session"
    peer.session = original


def test_a_session_id_that_changes_midway_is_refused(peer, monkeypatch):
    def change(sent, request, response):
        reply = httpx.Response(
            200, json=answered(response), headers={"Mcp-Session-Id": "another-session"}
        )
        return reply

    tamper(monkeypatch, peer, "tools/list", change)
    assert refused_code(lambda: mcp.discover(URL)) == "invalid_session"


def test_an_unreachable_server_is_reported_without_a_retry(peer, monkeypatch):
    def change(sent, request, response):
        raise httpx.ConnectTimeout("no route")

    tamper(monkeypatch, peer, "initialize", change)
    assert refused_code(lambda: mcp.discover(URL)) == "transport_error"
    assert [call[0]["method"] for call in peer.calls].count("initialize") == 1


# Catalogues


@pytest.mark.parametrize(
    "tool",
    [
        "not-a-mapping",
        {"description": "no name"},
        {"name": "has space", "description": "x", "inputSchema": SCHEMA},
        {"name": 7, "inputSchema": SCHEMA},
        {"name": "echo", "description": "duplicate of the peer's own tool", "inputSchema": SCHEMA},
        {"name": "other", "description": 5, "inputSchema": SCHEMA},
        {"name": "other", "description": "x" * 4001, "inputSchema": SCHEMA},
    ],
)
def test_a_catalogue_entry_without_a_supported_name_or_description_is_refused(peer, tool):
    peer.extra_tools = [tool]
    assert refused_code(lambda: mcp.discover(URL)) == "invalid_catalogue"


def test_a_catalogue_that_is_not_a_list_is_refused(peer):
    peer.pages = [{"tools": {"echo": {}}}]
    assert refused_code(lambda: mcp.discover(URL)) == "catalogue_limit"


@pytest.mark.parametrize("cursor", [5, "", "x" * 1100])
def test_a_page_cursor_that_is_not_a_bounded_string_is_refused(peer, cursor):
    peer.pages = [{"tools": [], "nextCursor": cursor}]
    assert refused_code(lambda: mcp.discover(URL)) == "invalid_catalogue"


def test_a_repeated_page_cursor_is_refused(peer):
    peer.pages = [{"tools": [], "nextCursor": "same"}, {"tools": [], "nextCursor": "same"}]
    assert refused_code(lambda: mcp.discover(URL)) == "invalid_catalogue"


def test_a_catalogue_that_never_ends_stops_after_four_pages(peer):
    peer.pages = [{"tools": [], "nextCursor": f"page-{index}"} for index in range(6)]
    assert refused_code(lambda: mcp.discover(URL)) == "catalogue_limit"
    assert [call[0]["method"] for call in peer.calls].count("tools/list") == mcp.MAX_PAGES


# Tool results (the call is already sent, so a bad answer is an unknown outcome, never a retry)


def call_with(peer, result):
    peer.result = result
    return mcp.execute(execution(), {"arguments": {"text": "hello"}})


@pytest.mark.parametrize(
    "result",
    [
        {"content": "text"},
        {"content": [{"text": "no type"}]},
        {"content": ["bare string"]},
        {"content": [{"type": "text", "text": "x"}] * 65},
        {"content": [{"type": "text", "text": "x"}], "isError": "no"},
        {"content": [{"type": "text", "text": "x"}], "structuredContent": ["not", "an", "object"]},
    ],
)
def test_a_malformed_tool_result_leaves_the_outcome_unknown(peer, result):
    with pytest.raises(CallOutcomeUnknown):
        call_with(peer, result)
    assert len(peer.tool_calls) == 1


def test_structured_content_is_kept_apart_from_text_and_cleaned(peer):
    result = call_with(
        peer, {"content": [{"type": "text", "text": "ok"}], "structuredContent": {"value": "a​b"}}
    )
    assert result["ok"] is True
    assert result["result"]["structuredContent"] == {"value": "ab"}


def test_a_tool_that_reports_an_error_is_a_failure_with_the_content_fenced(peer):
    result = call_with(peer, {"content": [{"type": "text", "text": "nope"}], "isError": True})
    assert result["ok"] is False and result["error_code"] == "mcp_tool_error"
    assert "UNTRUSTED_MCP_CONTENT" in result["result"]["content"][0]["text"]


def test_embedded_resource_text_is_fenced_like_plain_text(peer):
    result = call_with(
        peer, {"content": [{"type": "resource", "resource": {"uri": "file:///x", "text": "body"}}]}
    )
    assert "UNTRUSTED_MCP_CONTENT" in result["result"]["content"][0]["resource"]["text"]


def test_the_credential_never_appears_in_a_refusal(peer, monkeypatch):
    monkeypatch.setattr(mcp.vault, "get_key", lambda _: SECRET)
    peer.extra_tools = ["not-a-mapping"]
    with pytest.raises(MCPError) as error:
        mcp.discover(URL, "MCP_BEARER")
    assert SECRET not in str(error.value)
