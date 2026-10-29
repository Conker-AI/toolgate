"""The agent that asked may withdraw its waiting approval request; nothing else may, and a
withdrawn request leaves the owner's view and can never be approved or run."""

import hashlib

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import approvals
from toolgate.core import control_plane as cp

ADMIN = "withdraw-admin-key-" + "a" * 32
OWNER = "withdraw-owner-key-" + "o" * 32


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(server.vault, "get_control_key", lambda _: ADMIN)
    monkeypatch.setenv("TOOLGATE_OWNER_KEY_SHA256", hashlib.sha256(OWNER.encode()).hexdigest())
    cp.create_tool(
        {
            "id": "echo.ask",
            "name": "echo.ask",
            "description": "Local echo that asks the owner.",
            "category": "safe",
            "inputs": [{"name": "value", "type": "string", "required": True}],
            "outputs": [{"name": "proof", "type": "object"}],
            "execution": {"type": "local_echo"},
            "policy": {"usage_limits": {"max_per_minute": 60, "max_per_hour": 600}},
            "authorization": "owner_confirmation",
            "version": 1,
            "status": "active",
        }
    )
    _, pi_key = cp.issue_agent_key("Pi", ["echo.ask"])
    _, other_key = cp.issue_agent_key("Other agent", ["echo.ask"])
    client = TestClient(server.app)
    yield client, pi_key, other_key
    client.close()


def agent(key, identity=None):
    return {"X-ToolGate-Execution-Key": key, **({"X-ToolGate-Agent": identity} if identity else {})}


OWNER_HEADERS = {"X-ToolGate-Owner-Key": OWNER}


def invoke(client, key, value="hi", approval=None):
    body = {"args": {"value": value}, "action_id": f"withdraw-{value}"}
    if approval:
        body["approval_request_id"] = approval
    return client.post("/v2/tools/echo.ask/invoke", json=body, headers=agent(key))


def park(client, key, value="hi"):
    response = invoke(client, key, value)
    assert response.status_code == 200, response.text
    assert response.json()["code"] == "CONFIRMATION_REQUIRED"
    return response.json()["request_id"]


def withdraw(client, key, request_id, identity=None):
    return client.post(f"/v2/agent/requests/{request_id}/withdraw", headers=agent(key, identity))


def owner_list(client, **query):
    response = client.get("/v2/owner/requests", params=query, headers=OWNER_HEADERS)
    assert response.status_code == 200, response.text
    return response.json()


def test_the_asking_key_withdraws_its_waiting_request_and_the_owner_no_longer_sees_it(api):
    client, pi_key, _ = api
    kept = park(client, pi_key, "kept")
    taken = park(client, pi_key, "taken")
    response = withdraw(client, pi_key, taken)
    assert response.status_code == 200, response.text
    view = response.json()
    assert view["id"] == taken and view["status"] == "withdrawn"
    assert view["decision"]["actor"] == "Pi" and view["decision"]["at"]
    status = client.get(f"/v2/agent/requests/{taken}", headers=agent(pi_key)).json()
    assert status["status"] == "withdrawn"
    assert [row["id"] for row in owner_list(client)["results"]] == [kept]
    detail = client.get(f"/v2/owner/requests/{taken}", headers=OWNER_HEADERS)
    assert detail.status_code == 404
    events = cp.events(event_type="request_withdrawn")
    assert [(event["subject_id"], event["actor"]) for event in events] == [(taken, "Pi")]
    assert events[0]["payload"] == {"subject_type": "tool", "subject_id": "echo.ask"}


def test_withdrawing_again_is_the_same_answer_and_records_nothing_new(api):
    client, pi_key, _ = api
    request_id = park(client, pi_key)
    first = withdraw(client, pi_key, request_id)
    second = withdraw(client, pi_key, request_id)
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert len(cp.events(event_type="request_withdrawn")) == 1


def test_another_key_another_agent_or_an_unknown_id_cannot_withdraw(api):
    client, pi_key, other_key = api
    request_id = park(client, pi_key)
    refusals = [
        withdraw(client, other_key, request_id),
        # The same key acting as another agent is not the one that asked.
        withdraw(client, pi_key, request_id, identity="helper"),
        withdraw(client, pi_key, "no-such-request"),
    ]
    assert [response.status_code for response in refusals] == [404, 404, 404]
    assert len({response.text for response in refusals}) == 1
    assert cp.get("request", request_id)["status"] == "pending"
    assert not cp.events(event_type="request_withdrawn")
    # A message to the owner is not an approval request; it is not withdrawn here.
    note = client.post(
        "/v2/requests",
        json={"kind": "info", "title": "Note", "details": "Just so you know"},
        headers=agent(pi_key),
    )
    assert note.status_code == 200, note.text
    assert withdraw(client, pi_key, note.json()["id"]).status_code == 404


@pytest.mark.parametrize("answer", ["approved", "rejected"])
def test_a_request_the_owner_answered_cannot_be_withdrawn(api, answer):
    client, pi_key, _ = api
    request_id = park(client, pi_key)
    decided = client.post(
        f"/v2/owner/requests/{request_id}/decision",
        json={"status": answer, "note": ""},
        headers=OWNER_HEADERS,
    )
    assert decided.status_code == 200, decided.text
    response = withdraw(client, pi_key, request_id)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "REQUEST_NOT_PENDING"
    assert cp.get("request", request_id)["status"] == answer
    assert not cp.events(event_type="request_withdrawn")


def test_a_withdrawn_request_can_never_be_approved_or_run(api):
    client, pi_key, _ = api
    request_id = park(client, pi_key)
    assert withdraw(client, pi_key, request_id).status_code == 200
    owner = client.post(
        f"/v2/owner/requests/{request_id}/decision",
        json={"status": "approved", "note": ""},
        headers=OWNER_HEADERS,
    )
    assert owner.status_code == 404
    admin = client.post(
        f"/v2/requests/{request_id}/decision",
        json={"status": "approved"},
        headers={"X-ToolGate-Key": ADMIN},
    )
    assert admin.status_code == 409
    with pytest.raises(ValueError, match="already withdrawn"):
        approvals.decide_request(request_id, "approved", "owner")
    ran = invoke(client, pi_key, approval=request_id)
    assert ran.status_code == 409
    assert ran.json()["detail"]["code"] == "APPROVAL_INVALID"
    assert cp.get("request", request_id)["status"] == "withdrawn"
    assert not cp.events(event_type="tool_executed")


def test_withdrawing_works_in_lockdown_because_it_only_removes_authority(api):
    client, pi_key, _ = api
    request_id = park(client, pi_key)
    cp.set_lockdown(True, "owner", "test")
    assert withdraw(client, pi_key, request_id).json()["status"] == "withdrawn"


def test_owner_paging_continues_past_a_request_withdrawn_between_pages(api):
    client, pi_key, _ = api
    park(client, pi_key, "one")
    park(client, pi_key, "two")
    order = [row["id"] for row in owner_list(client)["results"]]
    first = owner_list(client, limit=1)
    cursor = first["next_cursor"]
    assert cursor == first["results"][0]["id"] == order[0]
    assert withdraw(client, pi_key, cursor).status_code == 200
    rest = owner_list(client, limit=1, cursor=cursor)
    assert [row["id"] for row in rest["results"]] == [order[1]]
