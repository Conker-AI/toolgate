"""Invocation metadata must survive both CLI and MCP envelopes."""

import importlib.machinery
import importlib.util
from pathlib import Path

import pytest

from toolgate.mcp import toolgate_mcp as bridge


@pytest.mark.parametrize("command", [["tool", "example"], ["automation", "example", "run"]])
def test_cli_preserves_action_job_and_arguments(tmp_path, monkeypatch, command):
    monkeypatch.setenv("TOOLGATE_CONFIG", str(tmp_path / "missing"))
    path = Path(__file__).parents[1] / "cli" / "toolgate"
    loader = importlib.machinery.SourceFileLoader("toolgate_cli_test", str(path))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    calls = []
    monkeypatch.setattr(module, "_request", lambda *args, **kw: calls.append((args, kw)) or 0)
    monkeypatch.setattr(
        module.sys,
        "argv",
        [
            "toolgate",
            *command,
            "--value",
            "hello",
            "--action-id",
            "123",
            "--job-id",
            "job-one",
            "--approval-request-id",
            "approval-one",
        ],
    )
    assert module.main() == 0
    assert calls[0][0][2] == {
        "args": {"value": "hello"},
        "action_id": "123",
        "job_id": "job-one",
        "approval_request_id": "approval-one",
    }


def test_mcp_preserves_action_job_and_arguments(monkeypatch):
    monkeypatch.setattr(bridge, "_visible_tools", lambda: [{"id": "example"}])
    calls = []
    monkeypatch.setattr(bridge, "_request", lambda *args, **kw: calls.append((args, kw)) or {})
    body = {"args": {"value": "hello"}, "action_id": "stable", "job_id": "job-one"}
    bridge._invoke(bridge._mcp_tool_name("example"), body)
    assert calls[0][0] == ("POST", "/v2/tools/example/invoke", body)
