"""A scripted fake MCP server (Streamable HTTP and SSE) and the fixtures the MCP tests share."""

import copy
import json

import httpx
import pytest

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


def unsupported_tool(name="formatted"):
    return {
        "name": name,
        "description": "Requires a schema keyword this client does not support",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string", "format": "uri"}},
        },
    }
