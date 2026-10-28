"""The sandbox tools inside ToolGate: registration, identity decides the workspace, scoping, the
guard before approval, result shaping, uncertain outcomes and reserved definitions. The runner is
replaced by a recorder; tests/test_sandbox_runner.py and sandbox/verify cover the real one."""

import hashlib
import json
import os
import socket
import socketserver
import threading

import pytest
from fastapi.testclient import TestClient

from toolgate.api import definitions, dispatch, server
from toolgate.core import control_plane as cp
from toolgate.core import identities
from toolgate.executors import sandbox
from toolgate.sandbox.tools import ensure_builtin_sandbox_capabilities

ADMIN = "sandbox-admin-key"
OWNER = "sandbox-owner-key-" + "o" * 32
DEPLOYMENT = "tgx_sandbox_deployment_key_0123456789"
ANSWER = {
    "ok": True,
    "exit_code": 0,
    "timed_out": False,
    "oom_killed": False,
    "workspace_exceeded": False,
    "duration_ms": 5,
    "stdout": "hi\n",
    "stderr": "",
    "stdout_truncated": False,
    "stderr_truncated": False,
    "workspace_bytes": 10,
}


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(server.vault, "get_control_key", lambda _: ADMIN)
    monkeypatch.setenv("TOOLGATE_OWNER_KEY_SHA256", hashlib.sha256(OWNER.encode()).hexdigest())
    monkeypatch.setenv("TOOLGATE_SANDBOX_SOCKET", "/nonexistent/runner.sock")
    monkeypatch.setenv("TOOLGATE_BOOTSTRAP_EXECUTION_KEY", DEPLOYMENT)
    key = cp.ensure_bootstrap_agent_key(DEPLOYMENT, ["sandbox.run", "sandbox.install", "notes.read"])
    ensure_builtin_sandbox_capabilities()
    calls = []
    answer = dict(ANSWER)

    def send(request, timeout):
        calls.append(request)
        if isinstance(answer.get("raise"), Exception):
            raise answer["raise"]
        return answer

    monkeypatch.setattr(sandbox, "_send", send)
    client = TestClient(server.app)
    yield client, key, calls, answer
    client.close()


def auto(tool_id):
    cp.update_tool(tool_id, {**cp.get("tool", tool_id), "authorization": "auto"})


def headers(raw=DEPLOYMENT, agent=None):
    return {"X-ToolGate-Execution-Key": raw, **({"X-ToolGate-Agent": agent} if agent else {})}


def invoke(client, args, tool="sandbox.run", raw=DEPLOYMENT, agent=None, action="a1"):
    return client.post(
        f"/v2/tools/{tool}/invoke",
        json={"args": args, "action_id": action},
        headers=headers(raw, agent),
    )


def define(client, agent, scopes, raw=DEPLOYMENT):
    response = client.put(
        f"/v2/agent/identities/{agent}", json={"scopes": scopes}, headers=headers(raw)
    )
    assert response.status_code == 200, response.text


def test_registered_only_with_a_runner_and_owner_choices_survive(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.delenv("TOOLGATE_SANDBOX_SOCKET", raising=False)
    ensure_builtin_sandbox_capabilities()
    assert cp.get("tool", "sandbox.run") is None and cp.get("tool", "sandbox.install") is None
    monkeypatch.setenv("TOOLGATE_SANDBOX_SOCKET", "/run/x.sock")
    ensure_builtin_sandbox_capabilities()
    assert cp.get("tool", "sandbox.run")["authorization"] == "ai_review"
    assert cp.get("tool", "sandbox.install")["authorization"] == "ai_review"
    auto("sandbox.run")
    ensure_builtin_sandbox_capabilities()
    assert cp.get("tool", "sandbox.run")["authorization"] == "auto"


@pytest.mark.parametrize("old_index", [0, 1])
def test_the_old_terminal_text_is_refreshed_and_an_owner_edit_is_kept(tmp_path, monkeypatch, old_index):
    """Small local models broke the JSON on nested double quotes; the new text says how to quote.
    Only ToolGate's own earlier wording is replaced, and nothing but the description changes."""
    from toolgate.sandbox import tools as sandbox_tools

    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setenv("TOOLGATE_SANDBOX_SOCKET", "/run/x.sock")
    ensure_builtin_sandbox_capabilities()
    old = sandbox_tools.PREVIOUS_TERMINAL_DESCRIPTIONS[old_index]
    cp.update_tool("sandbox.run", {**cp.get("tool", "sandbox.run"), "description": old, "authorization": "auto"})
    ensure_builtin_sandbox_capabilities()
    refreshed = cp.get("tool", "sandbox.run")
    assert refreshed["description"] == sandbox_tools.TERMINAL_DESCRIPTION
    assert "never wrapped in quotes" in refreshed["description"]
    assert refreshed["authorization"] == "auto"
    cp.update_tool("sandbox.run", {**refreshed, "description": "The owner's own words."})
    ensure_builtin_sandbox_capabilities()
    assert cp.get("tool", "sandbox.run")["description"] == "The owner's own words."


def test_the_callers_identity_picks_the_workspace(gate):
    client, key, calls, _ = gate
    auto("sandbox.run")
    define(client, "researcher", ["sandbox.run"])
    assert invoke(client, {"command": "ls"}, agent="researcher", action="r").status_code == 200
    assert invoke(client, {"command": "ls"}, action="c").status_code == 200
    _, bound = identities.mint(key, "coder")
    define(client, "coder", ["sandbox.run"])
    assert invoke(client, {"command": "ls"}, raw=bound, action="b").status_code == 200
    assert [call["agent"] for call in calls] == ["researcher", "companion", "coder"]
    # A bound key cannot present another agent; nothing reaches the runner.
    assert invoke(client, {"command": "ls"}, raw=bound, agent="researcher", action="x").status_code == 403
    assert len(calls) == 3


def test_another_key_never_shares_the_deployments_folders(gate):
    client, _, calls, _ = gate
    auto("sandbox.run")
    record, other = cp.issue_agent_key("Other client", ["sandbox.run"])
    assert invoke(client, {"command": "ls"}, raw=other).status_code == 200
    assert calls[-1]["agent"] == identities.workspace_for(record["id"])
    assert calls[-1]["agent"].startswith("k") and calls[-1]["agent"].endswith("_companion")


def test_an_argument_cannot_name_the_agent(gate):
    client, _, calls, _ = gate
    auto("sandbox.run")
    response = invoke(client, {"command": "ls", "agent": "other"})
    assert response.status_code == 422 and calls == []


def test_an_agent_outside_whose_toolkit_the_terminal_is_never_sees_it(gate):
    client, _, calls, _ = gate
    auto("sandbox.run")
    define(client, "writer", ["notes.read"])
    listed = client.get("/v2/agent/tools", headers=headers(agent="writer")).json()
    assert "sandbox.run" not in [tool["id"] for tool in listed]
    assert invoke(client, {"command": "ls"}, agent="writer").status_code == 404
    assert calls == []


def test_the_guard_refuses_before_any_approval_is_asked(gate):
    client, _, calls, _ = gate
    # Default access is AI decides: a fine command is queued for review...
    queued = invoke(client, {"command": "ls"}, action="q")
    assert queued.json()["code"] == "CONFIRMATION_REQUIRED"
    # ...a sandbox-breaking one is refused outright, with no request to approve.
    refused = invoke(client, {"command": "rm -rf /"}, action="g")
    assert refused.status_code == 422
    assert refused.json()["detail"]["code"] == "VALIDATION_ERROR"
    assert "Refused" in refused.json()["detail"]["message"]
    assert calls == []


def test_results_are_shaped_cleaned_and_bounded(gate):
    client, _, _, answer = gate
    auto("sandbox.run")
    body = invoke(client, {"command": "ls"}, action="s1").json()
    run = body["result"]["run"]
    assert body["code"] == "OK"
    assert (run["exitCode"], run["stdout"], run["timedOut"], run["truncated"]) == (0, "hi\n", False, False)
    answer["stdout"] = "\x1b[31mred\x1b[0m done"
    assert invoke(client, {"command": "ls"}, action="s2").json()["result"]["run"]["stdout"] == "red done"
    answer["stdout"] = "x" * 19999 + "!"
    run = invoke(client, {"command": "ls"}, action="s3").json()["result"]["run"]
    assert len(run["stdout"]) == 16000 and run["stdout"].endswith("!") and run["truncated"] is True


def test_small_model_arguments_run_in_the_workspace_with_the_default_time(gate):
    client, _, calls, _ = gate
    auto("sandbox.run")
    args = {"command": "ls", "cwd": "/", "timeout_seconds": None}
    body = invoke(client, args, action="n1").json()
    assert body["code"] == "OK"
    assert (calls[-1]["cwd"], calls[-1]["timeout"]) == ("", 30)


def test_a_bad_time_limit_is_refused_before_any_approval(gate):
    client, _, calls, _ = gate
    refused = invoke(client, {"command": "ls", "timeout_seconds": 500}, action="t1")
    assert refused.status_code == 422
    assert "timeout_seconds is 1 to 100" in refused.json()["detail"]["message"]
    assert calls == []


def test_a_lost_answer_is_unknown_and_never_sent_twice(gate):
    client, _, calls, answer = gate
    auto("sandbox.run")
    answer["raise"] = sandbox.OutcomeUnknown()
    first = invoke(client, {"command": "touch x"}, action="u1").json()
    assert first["code"] == "OUTCOME_UNKNOWN"
    second = invoke(client, {"command": "touch x"}, action="u1").json()
    assert second["code"] == "OUTCOME_UNKNOWN" and len(calls) == 1


def test_a_runner_refusal_is_a_failed_result(gate):
    client, _, _, answer = gate
    auto("sandbox.run")
    answer["raise"] = sandbox.SandboxError("busy", "The sandbox is busy.")
    body = invoke(client, {"command": "ls"}).json()
    assert body["code"] == "TOOL_UNAVAILABLE" and body["result"]["error_code"] == "busy"


def test_install_sends_validated_packages_only(gate):
    client, _, calls, _ = gate
    auto("sandbox.install")
    ok = invoke(client, {"manager": "pip", "packages": ["six"]}, tool="sandbox.install", action="i1")
    assert ok.json()["code"] == "OK"
    assert calls[-1] == {**calls[-1], "op": "install", "manager": "pip", "packages": ["six"], "timeout": 100}
    for bad in (["git+https://x"], ["x.whl"], ["-r", "reqs.txt"]):
        response = invoke(client, {"manager": "pip", "packages": bad}, tool="sandbox.install", action="i2")
        assert response.status_code == 422
    assert len(calls) == 1


def test_sandbox_executors_are_reserved():
    base = {
        "name": "x",
        "description": "x",
        "category": "controlled",
        "authorization": "auto",
        "status": "active",
        "inputs": [{"name": "command", "type": "string", "required": True}],
        "outputs": [{"name": "run", "type": "object"}],
        "policy": {"usage_limits": {"max_per_minute": 1, "max_per_hour": 1}},
    }
    assert definitions.tool_definition_errors({**base, "id": "my.shell", "execution": {"type": "sandbox_run"}})
    assert definitions.tool_definition_errors({**base, "id": "sandbox.run", "execution": {"type": "local_echo"}})
    assert not [
        error
        for error in definitions.tool_definition_errors(
            {**base, "id": "sandbox.run", "execution": {"type": "sandbox_run"}}
        )
        if "reserved" in error
    ]
    refused = dispatch._dispatch_tool({**base, "id": "sandbox.run", "execution": {"type": "sandbox_run"}}, {})
    assert refused["error_code"] == "invalid_sandbox_dispatch"


# --- the client against a real Unix socket -----------------------------------------------------


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX") or os.name == "nt", reason="POSIX only")
@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        (b'{"ok": true, "exit_code": 0}\n', "answer"),
        (None, "unknown"),
        (b'{"ok": false, "code": "outcome_unknown"}\n', "unknown"),
        (b'{"ok": false, "code": "busy", "message": "later"}\n', "busy"),
    ],
)
def test_send_over_a_real_socket(tmp_path, monkeypatch, reply, expected):
    path = str(tmp_path / "runner.sock")
    received = []

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            received.append(json.loads(self.rfile.readline()))
            if reply is not None:
                self.wfile.write(reply)

    with socketserver.UnixStreamServer(path, Handler) as fake:
        threading.Thread(target=fake.handle_request, daemon=True).start()
        monkeypatch.setenv("TOOLGATE_SANDBOX_SOCKET", path)
        request = {"v": 1, "op": "run", "agent": "companion", "command": "ls"}
        if expected == "answer":
            assert sandbox._send(request, 5) == {"ok": True, "exit_code": 0}
        elif expected == "unknown":
            with pytest.raises(sandbox.OutcomeUnknown):
                sandbox._send(request, 5)
        else:
            with pytest.raises(sandbox.SandboxError) as refused:
                sandbox._send(request, 5)
            assert refused.value.code == "busy"
    assert received == [request]


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX") or os.name == "nt", reason="POSIX only")
def test_no_runner_is_unavailable_not_unknown(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOLGATE_SANDBOX_SOCKET", str(tmp_path / "missing.sock"))
    with pytest.raises(sandbox.SandboxError) as refused:
        sandbox._send({"v": 1}, 5)
    assert refused.value.code == "unavailable"
