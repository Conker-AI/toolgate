"""Covers the mutation drill's handling of a test run outliving its 180 s limit.

A timed-out run used to escape as a raw subprocess.TimeoutExpired traceback instead of a
one-line verdict. The drill itself is never run here: the tests load the real module, replace
`stale_anchors` and `run_tests` with fakes, and shrink MUTANTS to one entry whose anchor
occurs exactly once in a real file, so the drill's own anchor check still passes.
"""

import importlib.util
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "mutation_check.py"

# A real anchor, present exactly once, so the drill's in-loop count check passes.
ANCHOR = ('MCP = "toolgate/tests/test_mcp_adapter.py::"', "toolgate/scripts/mutation_check.py")


@pytest.fixture()
def drill(monkeypatch):
    spec = importlib.util.spec_from_file_location("mutation_check_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "stale_anchors", lambda: [])
    return module


def test_baseline_timeout_prints_the_verdict_and_fails(drill, monkeypatch, capsys):
    calls = []

    def fake_run_tests(root, tests, name):
        calls.append(name)
        raise subprocess.TimeoutExpired(cmd=["pytest", *tests], timeout=180)

    monkeypatch.setattr(drill, "run_tests", fake_run_tests)
    assert drill.main() == 1
    assert calls == ["baseline"]
    assert (
        "Baseline timed out; fix the behavior before testing mutations." in capsys.readouterr().out
    )


def test_mutant_timeout_prints_the_label_and_fails_with_the_file_restored(
    drill, monkeypatch, capsys
):
    calls = []

    def fake_run_tests(root, tests, name):
        calls.append(name)
        if name == "baseline":
            return subprocess.CompletedProcess([], 0, stdout="", stderr="")
        assert name == "mutant-0"
        raise subprocess.TimeoutExpired(cmd=["pytest", *tests], timeout=180)

    monkeypatch.setattr(drill, "run_tests", fake_run_tests)
    monkeypatch.setattr(
        drill,
        "MUTANTS",
        [
            ("drill anchor mutated", ANCHOR[1], ANCHOR[0], ANCHOR[0] + "  # mutated", "some/test"),
        ],
    )
    assert drill.main() == 1
    assert calls == ["baseline", "mutant-0"]
    assert "TIMED OUT: drill anchor mutated" in capsys.readouterr().out
