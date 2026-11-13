"""A tool call ToolGate refuses before anything leaves it is a known failure: it names its reason,
releases its spending hold and is never reported as an unknown outcome. A refusal after the
request was sent stays unknown, because the upstream may have acted."""

import httpx
import pytest

from toolgate.api import dispatch, invocation, server
from toolgate.core import control_plane, spending
from toolgate.core import execution_journal as journal
from toolgate.tests.test_spending import invoke, setup_budget
from toolgate.tests.test_spending import paid as paid


def test_a_paid_call_without_its_credential_is_a_known_failure_with_no_hold(paid, monkeypatch):
    job = setup_budget()

    def never_sent(*args, **kwargs):
        raise AssertionError("nothing may be sent")

    def missing(name):
        raise KeyError(name)

    monkeypatch.setattr(httpx, "post", never_sent)
    monkeypatch.setattr(server.vault, "get_key", missing)
    first = invoke(paid, job)
    assert first["status"] == "completed"
    assert first["code"] == "SECRET_UNAVAILABLE"
    assert first["result"] == {
        "ok": False, "error": "Hosted AI credential is not configured",
        "error_code": "SECRET_UNAVAILABLE",
    }
    assert "Nothing was sent" in first["next_action"]
    status = spending.status()
    assert status["held_microusd"] == 0
    assert status["accounted_and_reserved_microusd"] == 0
    assert invoke(paid, job) == first


@pytest.fixture
def http_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(control_plane, "DB_PATH", tmp_path / "gate.db")
    return {"id": "http", "name": "HTTP", "version": 1, "authorization": "auto", "status": "active",
            "inputs": [{"name": "place", "type": "string", "required": False}],
            "outputs": [], "execution": {
                "type": "http_json", "billing": {"mode": "free"},
                "url": "https://api.example.com/{place}", "allowed_hosts": ["api.example.com"]}}


def call(tool, action, args):
    return invocation.invoke_tool(tool, args, "Actor", actor_id="agent", action_id=action)


def test_a_missing_template_argument_is_refused_by_name(http_tool):
    result = call(http_tool, "missing-arg", {})
    assert (result["status"], result["code"]) == ("completed", "VALIDATION_ERROR")
    assert result["message"] == "Missing template argument 'place'"


def test_a_destination_outside_the_allowlist_is_refused_before_any_request(http_tool):
    execution = {**http_tool["execution"], "url": "https://elsewhere.example.com/x"}
    result = call({**http_tool, "execution": execution}, "elsewhere", {})
    assert (result["status"], result["code"]) == ("completed", "DESTINATION_DENIED")


def test_a_refusal_after_the_request_was_sent_stays_unknown(http_tool, monkeypatch):
    sent = []

    def upstream(request):
        sent.append(str(request.url))
        return httpx.Response(500)

    monkeypatch.setattr(dispatch, "public_url", lambda url: True)
    monkeypatch.setattr(dispatch, "public_client", lambda timeout, headers: httpx.Client(
        transport=httpx.MockTransport(upstream), headers=headers))
    result = call(http_tool, "sent", {"place": "home"})
    assert sent == ["https://api.example.com/home"]
    assert result["code"] == "OUTCOME_UNKNOWN"
    assert journal.get("sent")["status"] == "outcome_unknown"
