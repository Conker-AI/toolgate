"""The run window after an approval (`run_window_minutes`): once the owner approves a request that
waited for them, the exact action has this long to start, and it still runs once. The owner may
only shorten today's 15 minutes, and each approval keeps the window in force when it was
decided, so a later change never moves it."""

import hashlib
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import approvals, owner_channel, tool_settings, vault
from toolgate.core import control_plane as cp
from toolgate.tests.test_approval_boundary import TOOL, TOOL_ID
from toolgate.tests.test_owner_channel import ADMIN, HEADERS, KEY

ARGS = {"value": "real action"}
EXPIRED = "Approval request has expired"
INVALID = "Approval request has an invalid expiry"


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(vault, "ENV_PATH", tmp_path / "vault.env")
    monkeypatch.setenv("TOOLGATE_ADMIN_KEY", ADMIN)
    monkeypatch.setenv(owner_channel.OWNER_HASH, hashlib.sha256(KEY.encode()).hexdigest())
    limits = {"max_per_minute": 1000, "max_per_hour": 1000, "cooldown_seconds": 0}
    cp.create_tool({**TOOL, "policy": {"usage_limits": limits}})
    agent, key = cp.issue_agent_key("window caller", [f"tool:{TOOL_ID}"])
    client = TestClient(server.app)  # No startup, listeners or external services.
    yield client, agent, key
    client.close()


def choose(client, minutes, revision=None):
    """The owner saves a run window through the owner route."""
    revision = tool_settings.load()["revision"] if revision is None else revision
    return client.put(
        "/v2/owner/settings",
        headers=HEADERS,
        json={"expected_revision": revision, "settings": {"run_window_minutes": minutes}},
    )


def invoke(gate, request_id=None):
    client, _, key = gate
    return client.post(
        f"/v2/tools/{TOOL_ID}/invoke",
        headers={"X-ToolGate-Execution-Key": key},
        json={"args": ARGS, "approval_request_id": request_id},
    )


def ask(gate):
    """Conker asks; with no expiry set the request waits until the owner answers."""
    response = invoke(gate)
    assert response.json()["code"] == "CONFIRMATION_REQUIRED", response.text
    return response.json()["request_id"]


def approve(gate, request_id):
    """The owner approves in the Inbox (the gateway's owner route) and the window is recorded."""
    response = gate[0].post(
        f"/v2/owner/requests/{request_id}/decision",
        headers=HEADERS,
        json={"status": "approved", "note": ""},
    )
    assert response.status_code == 200, response.text
    return cp.get("request", request_id)["decision"].get("run_window_minutes")


def age(request_id, minutes, **decision):
    """Move the recorded decision back, as if the owner approved `minutes` ago; `decision`
    replaces recorded fields."""
    record = cp.get("request", request_id)
    decided = datetime.fromisoformat(record["decision"]["at"]) - timedelta(minutes=minutes)
    record["decision"] = {**record["decision"], "at": decided.isoformat(), **decision}
    with cp._conn() as conn:
        approvals._save_request(conn, record)


def run(gate, request_id):
    """Start the approved action: (True, "approved") or (False, why not)."""
    _, agent, _ = gate
    return approvals.consume_verification(
        request_id, "tool", TOOL_ID, ARGS, TOOL["version"], agent["name"], agent["id"]
    )


# --- the setting ---------------------------------------------------------------------------------


def test_before_a_choice_the_window_is_todays_fifteen_minutes(gate):
    assert tool_settings.load()["settings"]["run_window_minutes"] is None
    assert tool_settings.RUN_WINDOW_MINUTES == 15
    assert timedelta(minutes=tool_settings.RUN_WINDOW_MINUTES) == approvals.EXECUTION_WINDOW
    early, late = ask(gate), ask(gate)
    assert approve(gate, early) == approve(gate, late) == 15
    age(early, 14)
    age(late, 16)
    assert run(gate, early) == (True, "approved")
    assert run(gate, late) == (False, EXPIRED)


@pytest.mark.parametrize("minutes", [1, 15])
def test_one_to_fifteen_minutes_are_accepted(gate, minutes):
    response = choose(gate[0], minutes)
    assert response.status_code == 200, response.text
    assert response.json()["settings"]["run_window_minutes"] == minutes


@pytest.mark.parametrize("minutes", [16, 60, 1440])
def test_a_window_longer_than_fifteen_minutes_is_refused(gate, minutes):
    """Only shorter than today: the setting can never widen an approval."""
    assert choose(gate[0], minutes).status_code == 422
    assert tool_settings.load()["revision"] == 0


@pytest.mark.parametrize("minutes", [0, -1, True, "5", 5.0])
def test_a_window_of_the_wrong_kind_is_refused(gate, minutes):
    assert choose(gate[0], minutes).status_code == 422
    assert tool_settings.load()["revision"] == 0


def test_a_stale_save_cannot_change_the_window(gate):
    client = gate[0]
    assert choose(client, 5, revision=0).status_code == 200
    stale = choose(client, 10, revision=0)
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "settings_revision_conflict"
    assert tool_settings.load()["settings"]["run_window_minutes"] == 5
    assert approve(gate, ask(gate)) == 5


def test_a_stored_window_past_the_ceiling_reads_as_today(gate):
    cp._put("settings", "tools", {"settings": {"run_window_minutes": 60}, "revision": 2})
    assert tool_settings.load()["settings"]["run_window_minutes"] is None
    assert approve(gate, ask(gate)) == 15


# --- what an approval gets -----------------------------------------------------------------------


def test_a_shorter_window_runs_out_sooner(gate):
    assert choose(gate[0], 5).status_code == 200
    inside, outside = ask(gate), ask(gate)
    assert approve(gate, inside) == approve(gate, outside) == 5
    age(inside, 4)
    age(outside, 6)
    assert run(gate, inside) == (True, "approved")
    assert run(gate, outside) == (False, EXPIRED)
    # Through the invoke path too: the spent window is refused before anything runs.
    refused = invoke(gate, outside)
    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "APPROVAL_INVALID"
    assert not [e for e in cp.events(event_type="tool_executed") if e["subject_id"] == TOOL_ID]


def test_an_approval_keeps_the_window_it_was_decided_under(gate):
    client = gate[0]
    before = ask(gate)
    assert approve(gate, before) == 15
    assert choose(client, 1).status_code == 200
    shortened = ask(gate)
    assert approve(gate, shortened) == 1
    # Back to today's limit; neither approval moves.
    assert choose(client, None).status_code == 200
    age(before, 10)
    age(shortened, 2)
    assert run(gate, before) == (True, "approved")
    assert run(gate, shortened) == (False, EXPIRED)


def test_a_request_waiting_when_the_window_changes_gets_the_new_one_when_decided(gate):
    waiting = ask(gate)
    assert choose(gate[0], 3).status_code == 200
    assert approve(gate, waiting) == 3
    age(waiting, 4)
    assert run(gate, waiting) == (False, EXPIRED)


def test_an_approval_decided_before_the_window_was_a_setting_has_fifteen_minutes(gate):
    assert choose(gate[0], 1).status_code == 200
    earlier, older = ask(gate), ask(gate)
    for request_id in (earlier, older):
        approve(gate, request_id)
        record = cp.get("request", request_id)
        del record["decision"]["run_window_minutes"]
        with cp._conn() as conn:
            approvals._save_request(conn, record)
    age(earlier, 14)
    age(older, 16)
    assert run(gate, earlier) == (True, "approved")
    assert run(gate, older) == (False, EXPIRED)


@pytest.mark.parametrize(
    "minutes", [60, 16, 0, True, "15", None], ids=["60", "16", "0", "bool", "text", "null"]
)
def test_a_recorded_window_past_its_ceiling_or_malformed_never_runs(gate, minutes):
    """The ceiling holds where the window is used, whatever the record says."""
    request_id = ask(gate)
    approve(gate, request_id)
    age(request_id, 16, run_window_minutes=minutes)
    assert run(gate, request_id) == (False, INVALID)


def test_a_bounded_request_keeps_its_own_expiry(gate):
    """A request that waits a bounded time ends at its own expiry; the run window is not used."""
    _, agent, _ = gate
    assert choose(gate[0], 1).status_code == 200
    record = approvals.create_verification_request(
        "Run", "Bounded.", "Pi", "tool", TOOL_ID, ARGS, TOOL["version"],
        expiry_seconds=900, actor_id=agent["id"],
    )  # fmt: skip
    assert record["payload"]["binding"]["expires_at"] is not None
    assert approve(gate, record["id"]) is None
    age(record["id"], 5)
    assert run(gate, record["id"]) == (True, "approved")


def test_an_approval_still_runs_once(gate):
    assert choose(gate[0], 5).status_code == 200
    request_id = ask(gate)
    approve(gate, request_id)
    assert invoke(gate, request_id).json()["code"] == "OK"
    again = invoke(gate, request_id)
    assert again.status_code == 409
    assert run(gate, request_id) == (False, "Approval request has already been consumed")
