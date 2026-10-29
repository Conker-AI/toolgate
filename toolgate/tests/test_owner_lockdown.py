"""The owner's lockdown switch (`GET`/`POST /v2/owner/lockdown`): the same lockdown the operator's
`/v2/settings/lockdown` sets, reached with the owner key. On, no tool or workflow runs and no agent
can file a request; off, they work again. Only the owner key reaches it; Pi's gateway asks the
owner's password for turning it off (turning it on only takes power away)."""

import pytest

from toolgate.core import control_plane as cp
from toolgate.tests.test_approval_boundary import TOOL, TOOL_ID
from toolgate.tests.test_owner_channel import ADMIN, HEADERS, gate  # noqa: F401

OFF = {"lockdown": False, "reason": "", "changed_by": None}


@pytest.fixture
def caller(gate):
    """A key that may run one tool that needs no approval."""
    cp.create_tool({**TOOL, "authorization": "auto"})
    _, key = cp.issue_agent_key("lockdown caller", [f"tool:{TOOL_ID}"])
    return gate[0], key


def switch(client, enabled, headers=None):
    return client.post(
        "/v2/owner/lockdown", headers=HEADERS if headers is None else headers,
        json={"enabled": enabled},
    )  # fmt: skip


def invoke(client, key):
    return client.post(
        f"/v2/tools/{TOOL_ID}/invoke",
        headers={"X-ToolGate-Execution-Key": key},
        json={"args": {"value": "hello"}},
    )


def test_only_the_owner_key_reads_or_turns_it(gate):
    client, _, execution = gate
    for headers in (
        {},
        {"X-ToolGate-Key": ADMIN},
        {"X-ToolGate-Execution-Key": execution},
        {"X-ToolGate-Owner-Key": ADMIN},
        {"X-ToolGate-Owner-Key": execution},
        {"X-ToolGate-Owner-Key": "wrong"},
    ):
        assert client.get("/v2/owner/lockdown", headers=headers).status_code == 401
        assert switch(client, True, headers).status_code == 401
    assert not cp.settings().get("lockdown")
    cp.set_lockdown(True, "owner")
    for headers in ({"X-ToolGate-Key": ADMIN}, {"X-ToolGate-Owner-Key": execution}):
        assert switch(client, False, headers).status_code == 401
    assert cp.settings()["lockdown"] is True


def test_before_any_lockdown_it_reads_off(gate):
    response = gate[0].get("/v2/owner/lockdown", headers=HEADERS)
    assert response.status_code == 200
    assert response.json() == OFF
    assert response.headers["Cache-Control"] == "no-store"


def test_on_stops_every_tool_and_off_lets_them_run_again(caller):
    client, key = caller
    assert invoke(client, key).json()["code"] == "OK"
    on = switch(client, True)
    assert on.status_code == 200, on.text
    assert on.json() == {"lockdown": True, "reason": "", "changed_by": "owner"}
    assert on.headers["Cache-Control"] == "no-store"
    locked = invoke(client, key)
    assert locked.status_code == 423
    assert locked.json()["detail"]["code"] == "LOCKED_DOWN"
    assert client.get("/v2/owner/lockdown", headers=HEADERS).json()["lockdown"] is True
    off = switch(client, False)
    assert off.status_code == 200
    assert off.json() == {"lockdown": False, "reason": "", "changed_by": "owner"}
    assert invoke(client, key).json()["code"] == "OK"
    events = [e["event_type"] for e in cp.events() if e["subject_id"] == "control-plane"]
    assert events[:2] == ["lockdown_disabled", "lockdown_enabled"]
    assert {e["actor"] for e in cp.events() if e["subject_id"] == "control-plane"} == {"owner"}


def test_the_owner_sees_why_toolgate_locked_itself_and_can_release_it(gate):
    client = gate[0]
    cp.set_lockdown(True, "system", "repeated invalid verification callbacks")
    view = client.get("/v2/owner/lockdown", headers=HEADERS).json()
    assert view == {
        "lockdown": True,
        "reason": "repeated invalid verification callbacks",
        "changed_by": "system",
    }
    assert switch(client, False).json()["lockdown"] is False


def test_turning_it_on_again_is_harmless(gate):
    client = gate[0]
    assert switch(client, True).json()["lockdown"] is True
    assert switch(client, True).json()["lockdown"] is True
    assert cp.settings()["lockdown"] is True


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"enabled": "false"},
        {"enabled": 0},
        {"enabled": None},
        {"enabled": False, "reason": "x"},
    ],
    ids=["empty", "text", "number", "null", "extra"],
)
def test_only_enabled_true_or_false_is_accepted(gate, body):
    client = gate[0]
    cp.set_lockdown(True, "owner")
    response = client.post("/v2/owner/lockdown", headers=HEADERS, json=body)
    assert response.status_code == 422
    assert cp.settings()["lockdown"] is True


def test_the_operator_route_still_works_and_the_owner_sees_it(gate):
    client = gate[0]
    response = client.post(
        "/v2/settings/lockdown?enabled=true&reason=drill", headers={"X-ToolGate-Key": ADMIN}
    )
    assert response.status_code == 200
    view = client.get("/v2/owner/lockdown", headers=HEADERS).json()
    assert view == {"lockdown": True, "reason": "drill", "changed_by": "admin"}
