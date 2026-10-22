"""Drive stdio and its real HTTP action path against SQLite, not mocked authority."""

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from toolgate.api import server
from toolgate.core import approvals, control_plane, vault
from toolgate.mcp import toolgate_mcp as bridge


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(control_plane, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(vault, "ENV_PATH", tmp_path / "vault.env")
    monkeypatch.setenv("TOOLGATE_ADMIN_KEY", "owner-test-key")
    for tool_id in ("allowed.echo", "secret.echo"):
        control_plane.create_tool(
            {
                "id": tool_id,
                "name": tool_id,
                "status": "active",
                "authorization": "auto",
                "inputs": [{"name": "value", "type": "string", "required": True}],
                "execution": {"type": "echo"},
                "policy": {
                    "usage_limits": {
                        "max_per_minute": 1000,
                        "max_per_hour": 1000,
                        "cooldown_seconds": 0,
                    }
                },
            }
        )
    agent, key = control_plane.issue_agent_key("scoped caller", ["tool:allowed.echo"])
    other, other_key = control_plane.issue_agent_key("other caller", ["tool:*"])
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    url = f"http://127.0.0.1:{sock.getsockname()[1]}"
    api = uvicorn.Server(uvicorn.Config(server.app, lifespan="off", log_level="error"))
    thread = threading.Thread(target=api.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not api.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert api.started, "local ToolGate HTTP server did not start"
    monkeypatch.setenv("TOOLGATE_URL", url)
    monkeypatch.setenv("TOOLGATE_EXECUTION_KEY", key)
    yield {
        "url": url,
        "key": key,
        "agent": agent,
        "other_key": other_key,
        "other": other,
    }
    api.should_exit = True
    thread.join(timeout=10)
    sock.close()
    assert not thread.is_alive()


def call(tool_id="allowed.echo", value="hello", approval=None):
    body = {"args": {"value": value}}
    if approval:
        body["approval_request_id"] = approval
    return bridge._invoke(bridge._mcp_tool_name(tool_id), body)


def test_scoped_catalogue_and_direct_call_cannot_escape(boundary):
    names = {tool["name"] for tool in bridge.list_tools()}
    assert bridge._mcp_tool_name("allowed.echo") in names
    assert bridge._mcp_tool_name("secret.echo") not in names
    assert call()["code"] == "OK"
    with pytest.raises(RuntimeError, match="unavailable"):
        call("secret.echo")
    # A client skipping discovery still meets the same server-side scope check.
    with pytest.raises(RuntimeError, match="403"):
        bridge._request(
            "POST", "/v2/tools/secret.echo/invoke", {"args": {"value": "hello"}}
        )
    assert not any(
        event["subject_id"] == "secret.echo"
        for event in control_plane.events(100)
        if event["event_type"] == "tool_executed"
    )


def test_revocation_and_scope_changes_take_effect_without_restart(boundary):
    assert call()["code"] == "OK"
    control_plane.update_agent_key_scopes(boundary["agent"]["id"], [])
    with pytest.raises(RuntimeError, match="unavailable"):
        call()
    control_plane.revoke_agent_key(boundary["agent"]["id"])
    with pytest.raises(RuntimeError, match="401"):
        bridge.list_tools()


def test_approvals_keep_identity_arguments_and_single_consumption(
    boundary, monkeypatch
):
    tool = control_plane.get("tool", "allowed.echo")
    control_plane.create_tool({**tool, "authorization": "owner_confirmation"})
    pending = call()
    assert pending["code"] == "CONFIRMATION_REQUIRED"
    request_id = pending["request_id"]
    record = control_plane.get("request", request_id)
    assert record["payload"]["created_by_agent_key"] == boundary["agent"]["id"]
    assert (
        bridge._invoke("toolgate_request_status", {"request_id": request_id})["status"]
        == "pending"
    )
    approvals.decide_request(request_id, "approved", "admin")
    monkeypatch.setenv("TOOLGATE_EXECUTION_KEY", boundary["other_key"])
    with pytest.raises(RuntimeError, match="404"):
        bridge._invoke("toolgate_request_status", {"request_id": request_id})
    with pytest.raises(RuntimeError, match="409"):
        call(approval=request_id)
    monkeypatch.setenv("TOOLGATE_EXECUTION_KEY", boundary["key"])
    with pytest.raises(RuntimeError, match="409"):
        call(value="changed", approval=request_id)
    assert call(approval=request_id)["code"] == "OK"
    with pytest.raises(RuntimeError, match="409"):
        call(approval=request_id)
    executed = [
        e for e in control_plane.events(100) if e["event_type"] == "tool_executed"
    ]
    assert len(executed) == 1
    assert executed[0]["actor"] == "scoped caller"


def test_lockdown_and_limits_apply_to_mcp(boundary):
    tool = control_plane.get("tool", "allowed.echo")
    control_plane.create_tool(
        {**tool, "policy": {"usage_limits": {"max_per_minute": 1}}}
    )
    assert call()["code"] == "OK"
    with pytest.raises(RuntimeError, match="429"):
        call()
    control_plane.set_lockdown(True, "admin", "drill")
    with pytest.raises(RuntimeError, match="423"):
        call()


def run_stdio(messages, env=None):
    return subprocess.run(
        [sys.executable, str(Path(bridge.__file__).resolve())],
        input="".join(json.dumps(message) + "\n" for message in messages),
        text=True,
        capture_output=True,
        env=env,
        timeout=15,
        check=False,
    )


def test_stdio_requires_execution_key_even_when_admin_key_exists(monkeypatch):
    monkeypatch.delenv("TOOLGATE_EXECUTION_KEY", raising=False)
    monkeypatch.setenv("TOOLGATE_ADMIN_KEY", "not-an-execution-key")
    result = run_stdio([])
    assert result.returncode == 2
    assert "Set TOOLGATE_EXECUTION_KEY" in result.stderr
    assert not result.stdout


def test_stdio_lists_and_executes_through_http_without_local_state(boundary):
    env = dict(
        os.environ,
        TOOLGATE_DATA_DIR="Z:/unavailable-state",
        TOOLGATE_ENV_PATH="Z:/no-vault",
    )
    result = run_stdio(
        [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": bridge._mcp_tool_name("allowed.echo"),
                    "arguments": {"args": {"value": "from stdio"}},
                },
            },
        ],
        env,
    )
    assert result.returncode == 0, result.stderr
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert [r["id"] for r in responses] == [1, 2, 3]
    assert len(responses[1]["result"]["tools"]) == 2
    assert json.loads(responses[2]["result"]["content"][0]["text"])["code"] == "OK"


def test_invalid_and_admin_keys_are_not_execution_credentials(boundary, monkeypatch):
    for key in ("invalid", "owner-test-key"):
        monkeypatch.setenv("TOOLGATE_EXECUTION_KEY", key)
        with pytest.raises(RuntimeError, match="401"):
            bridge.list_tools()


def test_input_envelope_preserves_a_tool_argument_named_approval_request_id():
    schema = bridge._tool_input_schema(
        {
            "inputs": [
                {"name": "approval_request_id", "type": "string", "required": True}
            ]
        }
    )
    assert "approval_request_id" in schema["properties"]["args"]["properties"]
    assert schema["properties"]["args"]["required"] == ["approval_request_id"]


def test_names_do_not_alias_when_scope_changes():
    ids = ["a.b", "a_b", "1abc", "tool_1abc", "toolgate_request_status", "x" * 100]
    ids.append(bridge._mcp_tool_name("a.b"))
    names = [bridge._mcp_tool_name(i) for i in ids]
    assert len(set(names)) == len(ids)
    assert "toolgate_request_status" not in names
    assert all(len(name) <= 64 for name in names)


@pytest.mark.parametrize("status", [302, 503])
def test_transport_never_follows_redirects_or_retries(status, monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    received = []

    class Upstream(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(self.path)
            self.send_response(status if self.path == "/v2/agent/status" else 200)
            if status == 302:
                self.send_header("Location", "/credential-sink")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args):
            pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("TOOLGATE_URL", f"http://127.0.0.1:{upstream.server_port}")
    monkeypatch.setenv("TOOLGATE_EXECUTION_KEY", "scoped-test-key")
    try:
        with pytest.raises(RuntimeError):
            bridge._request("GET", "/v2/agent/status")
        assert received == ["/v2/agent/status"]
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)
