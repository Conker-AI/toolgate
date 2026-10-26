"""Per-agent scoping tests: workspace isolation, escape attempts, ToolGate authorization."""

import os
import tempfile

import pytest
from conftest import run, unique_agent
from fastapi.testclient import TestClient

from toolgate.api.server import app
from toolgate.core import control_plane
from toolgate.sandbox.tools import ensure_builtin_sandbox_capabilities


def test_workspace_isolation():
    agent_a = unique_agent("a")
    agent_b = unique_agent("b")

    # Agent A writes a secret
    result_a = run(agent_a, "echo 'secret data' > secret.txt; cat secret.txt")
    assert result_a["ok"] and result_a["exit_code"] == 0
    assert result_a["stdout"].strip() == "secret data"

    # Agent B should not see it
    result_b_list = run(agent_b, "ls -A /workspace")
    assert "secret.txt" not in result_b_list["stdout"], "Agent B should not see A's file"

    result_b_cat = run(agent_b, "cat /workspace/secret.txt")
    assert result_b_cat["exit_code"] != 0, "Agent B should not be able to cat A's file"

    result_b_find = run(agent_b, "find / -name secret.txt 2>/dev/null")
    assert result_b_find["stdout"].strip() == "", "Agent B should not find A's file"

    # Verifier should see it in workspaces/<A>/ but not in workspaces/<B>/
    verifier_a = run(agent_a, "pwd")
    assert "/workspace" in verifier_a["stdout"]

    # Check from host perspective (verifier can see workspaces volume)
    # This would be checked by examining /workspaces/<agent>/ directly
    # For now, we trust the volume isolation


def test_escape_attempts():
    agent_a = unique_agent("a")
    agent_b = unique_agent("b")

    # Try to escape via cwd to B's workspace
    escape_result = run(agent_a, "echo test", cwd=f"../{agent_b}")
    assert not escape_result["ok"], "Should fail to escape to another agent's workspace"
    assert escape_result.get("code") == "invalid_cwd", f"Expected invalid_cwd, got {escape_result}"

    # Try to list parent directory from inside A
    parent_result = run(agent_a, "ls /workspace/..")
    # Should not show B's folder name
    assert agent_b not in parent_result["stdout"], f"Should not see {agent_b} in parent listing"


@pytest.mark.xfail(strict=True, reason="ToolGate integration needs control plane setup")
def test_toolgate_authorization_scopes():
    # Set up control plane
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".db") as f:
        db_path = f.name

    try:
        os.environ["TOOLGATE_SANDBOX_SOCKET"] = "/run/conker-sandbox/runner.sock"
        original_db = control_plane.DB_PATH
        control_plane.DB_PATH = db_path

        # Ensure builtin capabilities are loaded
        ensure_builtin_sandbox_capabilities()

        # Issue a key with sandbox.run scope
        control_plane.issue_agent_key("test-key", scopes=["sandbox.run", "notes.read"])

        # Define identities
        client = TestClient(app)

        # researcher identity with sandbox.run
        client.put(
            "/v2/agent/identities/researcher",
            json={"description": "Research user", "capabilities": ["sandbox.run"]},
        )

        # writer identity with notes.read only
        client.put(
            "/v2/agent/identities/writer",
            json={"description": "Write user", "capabilities": ["notes.read"]},
        )

        # Test researcher can run sandbox
        researcher_result = run("researcher", "echo r > r.txt; cat r.txt")
        assert researcher_result["ok"] and researcher_result["exit_code"] == 0
        assert researcher_result["stdout"].strip() == "r"

        # Verify file exists in correct workspace
        # (This would be checked by examining /workspaces/researcher/r.txt)

        # Test writer cannot run sandbox
        writer_result = run("writer", "echo w > w.txt")
        assert not writer_result["ok"] or writer_result.get("code") == "not_found"

        # Test companion (no header) goes to /workspaces/companion
        companion_result = run("", "echo companion > companion.txt")
        if companion_result.get("ok"):
            # File should be in /workspaces/companion/ if it succeeded
            pass

        # Test minted key for researcher runs in /workspaces/researcher
        control_plane.issue_agent_key("researcher-minted", scopes=["sandbox.run"])
        # Use minted key to authenticate and run...
        # (Implementation depends on auth mechanism)

    finally:
        # Cleanup
        control_plane.DB_PATH = original_db
        if os.path.exists(db_path):
            os.unlink(db_path)
        if "TOOLGATE_SANDBOX_SOCKET" in os.environ:
            del os.environ["TOOLGATE_SANDBOX_SOCKET"]
