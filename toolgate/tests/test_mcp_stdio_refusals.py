"""The stdio MCP bridge refuses what it must: no key, unsafe origins, redirects, malformed
messages, and it never claims a result it did not receive."""

import io
import json

import httpx
import pytest

from toolgate.mcp import toolgate_mcp as bridge

TOOL = {
    "id": "notes.add",
    "description": "Add a note.",
    "inputs": [
        {"name": "text", "type": "string", "required": True, "min_length": 1, "max_length": 9,
         "pattern": "^[a-z]+$", "description": "Words", "default": "hi", "allowed_values": ["hi"]},
        {"name": "count", "type": "integer", "minimum": 1, "maximum": 3},
        {"name": "tags", "type": "array", "item_type": "string", "item_pattern": "^#",
         "min_items": 1, "max_items": 2, "unique_items": True},
        {"name": "odd", "type": "mystery"},
        {"type": "string"},
    ],
}


@pytest.fixture
def server(monkeypatch):
    """A fake ToolGate behind the bridge; `routes` maps (method, path) to a response."""
    monkeypatch.setenv("TOOLGATE_EXECUTION_KEY", "agent-key")
    monkeypatch.setenv("TOOLGATE_URL", "http://127.0.0.1:8010")
    routes: dict = {
        ("GET", "/v2/agent/status"): httpx.Response(200, json={"ok": True}),
        ("GET", "/v2/agent/tools"): httpx.Response(200, json=[TOOL]),
    }
    seen: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path.decode()
        seen.append((request.method, path, request.headers.get("X-ToolGate-Execution-Key")))
        answer = routes.get((request.method, path))
        if isinstance(answer, Exception):
            raise answer
        return answer or httpx.Response(404, json={"detail": "not found"})

    real = httpx.Client
    monkeypatch.setattr(bridge.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    return routes, seen


def test_it_refuses_to_start_without_a_key(monkeypatch):
    monkeypatch.delenv("TOOLGATE_EXECUTION_KEY", raising=False)
    with pytest.raises(RuntimeError, match="TOOLGATE_EXECUTION_KEY"):
        bridge._request("GET", "/v2/agent/status")


@pytest.mark.parametrize("origin", [
    "http://toolgate.example", "ftp://127.0.0.1", "https://user:pw@toolgate.example",
    "https://toolgate.example/sub", "https://toolgate.example?x=1", "https://toolgate.example#f",
    "https://",
])
def test_only_https_or_loopback_http_origins_get_the_key(monkeypatch, origin):
    monkeypatch.setenv("TOOLGATE_EXECUTION_KEY", "agent-key")
    monkeypatch.setenv("TOOLGATE_URL", origin)
    with pytest.raises(RuntimeError, match="TOOLGATE_URL"):
        bridge._request("GET", "/v2/agent/status")


def test_a_redirect_is_refused_instead_of_followed(server):
    routes, seen = server
    routes[("GET", "/v2/agent/tools")] = httpx.Response(302, headers={"Location": "https://elsewhere/"})
    with pytest.raises(RuntimeError, match="redirected"):
        bridge._request("GET", "/v2/agent/tools")
    assert len(seen) == 1


def test_a_refusal_names_its_status_and_detail(server):
    routes, _ = server
    routes[("GET", "/v2/agent/tools")] = httpx.Response(403, json={"detail": {"code": "POLICY_DENIED"}})
    with pytest.raises(RuntimeError) as caught:
        bridge._request("GET", "/v2/agent/tools")
    assert json.loads(str(caught.value))["status"] == 403
    assert json.loads(str(caught.value))["detail"] == {"code": "POLICY_DENIED"}
    routes[("GET", "/v2/agent/tools")] = httpx.Response(500, text="not json")
    with pytest.raises(RuntimeError) as caught:
        bridge._request("GET", "/v2/agent/tools")
    assert json.loads(str(caught.value))["detail"] is None


@pytest.mark.parametrize("failure", [httpx.ReadTimeout("slow"), httpx.Response(200, text="{broken")])
def test_a_lost_or_unreadable_answer_is_never_called_a_result(server, failure):
    routes, _ = server
    routes[("POST", "/v2/tools/notes.add/invoke")] = failure
    with pytest.raises(RuntimeError, match="outcome may be unknown"):
        bridge._request("POST", "/v2/tools/notes.add/invoke", {"args": {}})


def test_the_input_schema_carries_every_typed_limit():
    schema = bridge._tool_input_schema(TOOL)["properties"]["args"]
    text, count, tags, odd = (schema["properties"][name] for name in ("text", "count", "tags", "odd"))
    assert text == {"type": "string", "description": "Words", "default": "hi", "enum": ["hi"],
                    "minLength": 1, "maxLength": 9, "pattern": "^[a-z]+$"}
    assert count == {"type": "integer", "minimum": 1, "maximum": 3}
    assert tags == {"type": "array", "items": {"type": "string", "pattern": "^#"},
                    "minItems": 1, "maxItems": 2, "uniqueItems": True}
    assert odd == {"type": "string"}
    assert schema["required"] == ["text"] and schema["additionalProperties"] is False
    assert set(schema["properties"]) == {"text", "count", "tags", "odd"}


@pytest.mark.parametrize("tool_id", ["9lives", "...", "a" * 80])
def test_tool_names_are_safe_and_distinct(tool_id):
    name = bridge._mcp_tool_name(tool_id)
    assert name[0].isalpha() or name[0] == "_"
    assert len(name) <= 64 and name != bridge._mcp_tool_name(tool_id + "x")


def test_calls_go_only_to_tools_this_key_sees_with_the_documented_shape(server):
    routes, seen = server
    name = bridge._mcp_tool_name("notes.add")
    routes[("POST", "/v2/tools/notes.add/invoke")] = httpx.Response(200, json={"status": "completed"})
    routes[("GET", "/v2/agent/requests/a%2Fb")] = httpx.Response(200, json={"status": "pending"})
    assert bridge._invoke(name, {"args": {"text": "hi"}, "action_id": "a1"}) == {"status": "completed"}
    assert seen[-1] == ("POST", "/v2/tools/notes.add/invoke", "agent-key")
    assert bridge._invoke("toolgate_request_status", {"request_id": "a/b"}) == {"status": "pending"}
    with pytest.raises(RuntimeError, match="unavailable"):
        bridge._invoke("someone_elses_tool", {"args": {}})
    with pytest.raises(RuntimeError, match="inside args"):
        bridge._invoke(name, {"text": "hi"})
    with pytest.raises(RuntimeError, match="inside args"):
        bridge._invoke(name, {"args": "hi"})
    with pytest.raises(TypeError):
        bridge._invoke(name, ["hi"])  # type: ignore[arg-type]


def run(monkeypatch, capsys, *lines):
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO("".join(line + "\n" for line in lines)))
    code = bridge.main()
    return code, [json.loads(line) for line in capsys.readouterr().out.splitlines()]


def test_the_stdio_loop_answers_every_method_and_survives_bad_lines(server, monkeypatch, capsys):
    name = bridge._mcp_tool_name("notes.add")
    code, out = run(
        monkeypatch, capsys,
        json.dumps({"id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}),
        json.dumps({"id": 2, "method": "tools/list"}),
        json.dumps({"id": 3, "method": "tools/call", "params": {"name": name, "arguments": {"args": {}}}}),
        json.dumps({"id": 4, "method": "ping"}),
        json.dumps({"id": 5, "method": "resources/list"}),
        json.dumps({"method": "notifications/initialized"}),
        "not json",
        json.dumps([1, 2]),
        json.dumps({"id": 6, "method": "tools/list", "params": []}),
    )
    assert code == 0
    by_id = {message["id"]: message for message in out}
    assert by_id[1]["result"]["protocolVersion"] == "2025-03-26"
    assert by_id[1]["result"]["serverInfo"]["name"] == "toolgate"
    assert [tool["name"] for tool in by_id[2]["result"]["tools"]] == [name, "toolgate_request_status"]
    # The fake ToolGate has no invoke route: a refusal comes back as a tool error, not a crash.
    assert by_id[3]["result"]["isError"] is True and "404" in by_id[3]["result"]["content"][0]["text"]
    assert by_id[4]["result"] == {}
    assert by_id[5]["error"]["message"] == "Unsupported MCP method"
    assert by_id[6]["error"]["message"] == "MCP params must be an object"
    assert [message["id"] for message in out if message["id"] is None] == [None, None]
    assert len(out) == 8  # the notification gets no answer


def test_it_will_not_serve_when_toolgate_refuses_the_key(server, monkeypatch, capsys):
    routes, _ = server
    routes[("GET", "/v2/agent/status")] = httpx.Response(401, json={"detail": "bad key"})
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO(""))
    assert bridge.main() == 2
    assert "401" in capsys.readouterr().err
