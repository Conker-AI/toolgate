"""Per-agent scoping: each agent reaches only its own workspace, through the runner and through
ToolGate itself (in-process here, talking to the real runner), and an agent outside whose toolkit
the terminal is never reaches it."""

import os
import uuid
from pathlib import Path

import pytest
from conftest import run, unique_agent
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import identities
from toolgate.sandbox.tools import ensure_builtin_sandbox_capabilities

WORKSPACES = Path("/workspaces")


def test_an_agent_cannot_see_another_agents_files():
    first, second = unique_agent("a"), unique_agent("b")
    wrote = run(first, "echo 'secret data' > secret.txt; cat secret.txt")
    assert wrote["exit_code"] == 0 and wrote["stdout"].strip() == "secret data", wrote

    listing = run(second, "ls -A /workspace")
    assert "secret.txt" not in listing["stdout"], listing
    assert run(second, "cat /workspace/secret.txt")["exit_code"] != 0
    assert run(second, "find / -name secret.txt 2>/dev/null")["stdout"].strip() == ""

    # From outside: the file is in the first agent's folder only.
    assert (WORKSPACES / first / "secret.txt").read_text() == "secret data\n"
    assert not (WORKSPACES / second / "secret.txt").exists()


def test_the_working_folder_cannot_leave_the_workspace():
    first, second = unique_agent("a"), unique_agent("b")
    run(second, "true")
    escape = run(first, "echo test", cwd=f"../{second}")
    assert escape == {**escape, "ok": False, "code": "invalid_cwd"}, escape
    parent = run(first, "ls -A /workspace/..")
    assert parent["exit_code"] == 0, parent
    assert second not in parent["stdout"] and first not in parent["stdout"], parent


# --- through ToolGate --------------------------------------------------------------------------


@pytest.fixture
def gate(tmp_path, monkeypatch):
    """ToolGate with its own database, the deployment key (as Pi's) and the Terminal on auto."""
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    raw = "tgx_verify_" + uuid.uuid4().hex
    monkeypatch.setenv("TOOLGATE_BOOTSTRAP_EXECUTION_KEY", raw)
    key = cp.ensure_bootstrap_agent_key(raw, ["sandbox.run", "notes.read"])
    ensure_builtin_sandbox_capabilities()
    cp.update_tool("sandbox.run", {**cp.get("tool", "sandbox.run"), "authorization": "auto"})
    client = TestClient(server.app)
    yield client, key, raw
    client.close()


def invoke(client, raw_key, command, agent=None):
    headers = {"X-ToolGate-Execution-Key": raw_key}
    if agent:
        headers["X-ToolGate-Agent"] = agent
    return client.post(
        "/v2/tools/sandbox.run/invoke",
        json={"args": {"command": command}, "action_id": "verify-" + uuid.uuid4().hex},
        headers=headers,
    )


def define(client, raw_key, agent, scopes):
    response = client.put(
        f"/v2/agent/identities/{agent}",
        json={"scopes": scopes},
        headers={"X-ToolGate-Execution-Key": raw_key},
    )
    assert response.status_code == 200, response.text


def ran(response) -> dict:
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["code"] == "OK", body
    return body["result"]["run"]


def test_an_agent_runs_in_its_own_folder_through_toolgate(gate):
    client, _, raw = gate
    researcher = unique_agent("researcher")
    define(client, raw, researcher, ["sandbox.run"])
    marker = uuid.uuid4().hex
    result = ran(invoke(client, raw, f"echo {marker} > r.txt; pwd", researcher))
    assert result["exitCode"] == 0 and result["stdout"].strip() == "/workspace", result
    assert (WORKSPACES / researcher / "r.txt").read_text().strip() == marker


def test_an_agent_without_the_terminal_in_its_toolkit_cannot_reach_it(gate):
    client, _, raw = gate
    writer = unique_agent("writer")
    define(client, raw, writer, ["notes.read"])
    listed = client.get(
        "/v2/agent/tools",
        headers={"X-ToolGate-Execution-Key": raw, "X-ToolGate-Agent": writer},
    )
    assert "sandbox.run" not in [tool["id"] for tool in listed.json()]
    response = invoke(client, raw, "echo w > w.txt", writer)
    assert response.status_code == 404, response.text
    assert not (WORKSPACES / writer).exists()


def test_the_key_acting_as_itself_is_the_companion(gate):
    client, _, raw = gate
    marker = "companion-" + uuid.uuid4().hex
    result = ran(invoke(client, raw, f"touch {marker}"))
    assert result["exitCode"] == 0, result
    assert (WORKSPACES / "companion" / marker).exists()
    os.remove(WORKSPACES / "companion" / marker)


def test_a_key_bound_to_an_agent_runs_in_that_agents_folder(gate):
    client, key, raw = gate
    agent = unique_agent("bound")
    define(client, raw, agent, ["sandbox.run"])
    _, bound_raw = identities.mint(key, agent)
    marker = uuid.uuid4().hex
    assert ran(invoke(client, bound_raw, f"echo {marker} > b.txt"))["exitCode"] == 0
    assert (WORKSPACES / agent / "b.txt").read_text().strip() == marker
    # A bound key cannot present another agent.
    other = unique_agent("other")
    assert invoke(client, bound_raw, "true", other).status_code == 403


def test_another_keys_agents_never_share_the_deployments_folders(gate):
    client, _, _ = gate
    record, other_raw = cp.issue_agent_key("Other client", ["sandbox.run"])
    marker = "other-" + uuid.uuid4().hex
    assert ran(invoke(client, other_raw, f"touch {marker}"))["exitCode"] == 0
    folder = identities.workspace_for(record["id"])
    assert folder.startswith("k") and folder.endswith("_companion"), folder
    assert (WORKSPACES / folder / marker).exists()
    assert not (WORKSPACES / "companion" / marker).exists()


def test_a_guarded_command_never_reaches_the_runner(gate):
    client, _, raw = gate
    response = invoke(client, raw, "rm -rf /")
    assert response.status_code == 422, response.text
    assert "Refused" in response.json()["detail"]["message"]
