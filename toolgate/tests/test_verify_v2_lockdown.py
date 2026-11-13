"""The live verifier never lifts a lockdown it did not set (hunt toolgate-5 F2).

Runs the real script's main() against a fake ToolGate (httpx.MockTransport); no stack runs.
"""

import importlib.util
from pathlib import Path

import httpx
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_v2.py"


@pytest.fixture()
def verifier(monkeypatch):
    spec = importlib.util.spec_from_file_location("verify_v2_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.vault, "get_control_key", lambda name: "owner-key")
    monkeypatch.setattr(module.vault, "get_key", lambda name: f"value-of-{name}")
    monkeypatch.setattr(module, "dotenv_values", lambda path: {"TOOLGATE_EXECUTION_KEY": "agent"})
    return module


def fake_toolgate(monkeypatch, module, lockdown: bool) -> list[str]:
    seen: list[str] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.method} {request.url.path}?{request.url.query.decode()}")
        if request.url.path == "/v2/status":
            return httpx.Response(200, json={"lockdown": lockdown})
        if request.method == "DELETE":
            return httpx.Response(404)
        return httpx.Response(500, text="fake ToolGate refuses the rest")

    real = httpx.Client
    monkeypatch.setattr(module.httpx, "Client", lambda **kwargs: real(
        transport=httpx.MockTransport(answer), base_url=kwargs["base_url"]))
    return seen


def test_an_owner_lockdown_stops_the_run_and_is_never_lifted(verifier, monkeypatch):
    seen = fake_toolgate(monkeypatch, verifier, lockdown=True)
    with pytest.raises(AssertionError, match="lockdown"):
        verifier.main()
    assert seen == ["GET /v2/status?"]


def test_a_failed_run_without_its_own_lockdown_does_not_touch_lockdown(verifier, monkeypatch):
    seen = fake_toolgate(monkeypatch, verifier, lockdown=False)
    with pytest.raises(AssertionError, match="could not create verification tool"):
        verifier.main()
    assert not [line for line in seen if "/v2/settings/lockdown" in line]
