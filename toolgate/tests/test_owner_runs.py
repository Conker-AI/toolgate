"""The owner runs a tool by hand (`/v2/owner/tools/{id}/runs`): the owner key with the chat's own key,
the same asking as an agent's invoke, and a bounded read of the tool's journal."""

import uuid

from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import owner_channel
from toolgate.tests.test_access_policy import api, delegate, invoke, owner, tool  # noqa: F401


def action():
    return "owner_" + uuid.uuid4().hex


def run(client, key, tool_id, body=None, headers=None):
    body = {"action_id": action(), "args": {"value": "hi"}} if body is None else body
    return client.post(
        f"/v2/owner/tools/{tool_id}/runs",
        json=body,
        headers=owner(key) if headers is None else headers,
    )


def runs(client, tool_id, limit=None, headers=None):
    query = "" if limit is None else f"?limit={limit}"
    return client.get(
        f"/v2/owner/tools/{tool_id}/runs{query}", headers=owner() if headers is None else headers
    )


def code(response):
    body = response.json()
    return body.get("code") or body["detail"]["code"]


def test_only_the_owner_key_with_the_chat_key_runs(api):
    client, _, pi_key, _ = api
    for headers in (
        {},
        owner(),
        {"X-ToolGate-Execution-Key": pi_key},
        {"X-ToolGate-Owner-Key": pi_key, "X-ToolGate-Execution-Key": pi_key},
    ):
        assert run(client, pi_key, "echo.auto", headers=headers).status_code == 401
        assert run(client, pi_key, "echo.ask", headers=headers).status_code == 401
    assert journal.list_actions() == [] and cp.list_objects("request") == []
    for headers in ({}, {"X-ToolGate-Execution-Key": pi_key}):
        assert runs(client, "echo.auto", headers=headers).status_code == 401


def test_a_tool_that_runs_alone_runs_once_and_replays_its_receipt(api):
    client, pi, pi_key, _ = api
    body = {"action_id": action(), "args": {"value": "hi"}}
    first = run(client, pi_key, "echo.auto", body)
    assert first.status_code == 200 and first.json()["code"] == "OK", first.text
    assert run(client, pi_key, "echo.auto", body).json() == first.json()
    changed = run(client, pi_key, "echo.auto", {**body, "args": {"value": "other"}})
    assert changed.status_code == 409 and code(changed) == "ACTION_CONFLICT"
    [record] = journal.list_actions()
    assert record["actor_id"] == pi["id"] and record["subject_id"] == "echo.auto"
    assert cp.events(event_type="tool_executed")[0]["actor"] == "owner"


def test_he_runs_any_active_tool_but_never_a_blocked_missing_or_turned_off_one(api):
    client, _, pi_key, _ = api
    # Conker's key may not use this one; the owner still may.
    cp.create_tool(tool("echo.mine", "auto"))
    assert code(run(client, pi_key, "echo.mine")) == "OK"
    assert invoke(client, pi_key, "echo.mine").status_code == 404
    blocked = run(client, pi_key, "echo.blocked")
    assert blocked.status_code == 403 and code(blocked) == "POLICY_DENIED"
    cp.create_tool({**tool("echo.off", "auto"), "status": "disabled"})
    for tool_id in ("echo.off", "echo.nowhere"):
        missing = run(client, pi_key, tool_id)
        assert missing.status_code == 404 and code(missing) == "TOOL_UNAVAILABLE"
    bad = run(client, pi_key, "echo.auto", {"action_id": "a1", "args": {}})
    assert bad.status_code == 422
    decided = run(
        client,
        pi_key,
        "echo.ask",
        {
            "action_id": action(),
            "args": {"value": "hi"},
            "decision": {"outcome": "run", "decided_by": "chat"},
        },
    )
    assert decided.status_code == 422
    assert len(journal.list_actions()) == 1


def test_a_tool_that_asks_waits_for_his_approval_and_the_same_run_resumes(api):
    client, _, pi_key, _ = api
    body = {"action_id": action(), "args": {"value": "hi"}}
    waiting = run(client, pi_key, "echo.ask", body).json()
    assert waiting["code"] == "CONFIRMATION_REQUIRED", waiting
    request = owner_channel.get(waiting["request_id"])
    assert request["actor"] == "owner" and request["action"]["args"] == {"value": "hi"}
    assert journal.list_actions() == []
    resume = {**body, "approval_request_id": waiting["request_id"]}
    early = run(client, pi_key, "echo.ask", resume)
    assert early.status_code == 409 and code(early) == "APPROVAL_INVALID"
    assert journal.list_actions() == []
    owner_channel.decide(waiting["request_id"], "approved", "Owner checked this exact run.")
    done = run(client, pi_key, "echo.ask", resume)
    assert done.status_code == 200 and done.json()["code"] == "OK", done.text
    assert run(client, pi_key, "echo.ask", resume).json() == done.json()
    assert len(journal.list_actions()) == 1
    # An approval binds the exact action: other arguments under it never run.
    other = run(
        client, pi_key, "echo.ask", {**resume, "action_id": action(), "args": {"value": "other"}}
    )
    assert other.status_code == 409 and code(other) == "APPROVAL_INVALID"


def test_the_floor_still_asks_when_he_presses_run(api):
    client, _, pi_key, _ = api
    delegate(client, pi_key)
    marked = client.post(
        "/v2/owner/tools/echo.auto/sensitive", json={"sensitive": True}, headers=owner()
    )
    assert marked.status_code == 200
    waiting = run(client, pi_key, "echo.auto")
    assert waiting.status_code == 200 and code(waiting) == "CONFIRMATION_REQUIRED"
    assert journal.list_actions() == []
    # A fixed system control is on the floor whatever its own setting says.
    cp.create_tool(tool("system.x", "auto", execution={"type": "container_control"}))
    assert code(run(client, pi_key, "system.x")) == "CONFIRMATION_REQUIRED"
    assert journal.list_actions() == []
    assert len(cp.list_objects("request")) == 2


def test_lockdown_and_agent_identities_stop_a_run(api):
    client, _, pi_key, _ = api
    helper = client.put(
        "/v2/agent/identities/helper",
        json={"scopes": ["echo.auto"]},
        headers={"X-ToolGate-Execution-Key": pi_key},
    )
    assert helper.status_code == 200, helper.text
    suited = run(
        client, pi_key, "echo.auto", headers={**owner(pi_key), "X-ToolGate-Agent": "helper"}
    )
    assert suited.status_code == 403 and code(suited) == "execution_unavailable"
    locked = client.post("/v2/owner/lockdown", json={"enabled": True}, headers=owner())
    assert locked.status_code == 200, locked.text
    assert run(client, pi_key, "echo.auto").status_code == 423
    assert journal.list_actions() == []


def test_recent_runs_are_this_tools_own_newest_first_and_bounded(api):
    client, pi, pi_key, other_key = api
    made = [run(client, pi_key, "echo.auto").json() for _ in range(3)]
    assert invoke(client, other_key, "echo.auto", action="agent").json()["code"] == "OK"
    cp.create_tool(tool("echo.mine", "auto"))
    assert code(run(client, pi_key, "echo.mine")) == "OK"
    items = runs(client, "echo.auto").json()["items"]
    assert len(items) == 4
    assert [item["created_at"] for item in items] == sorted(
        (item["created_at"] for item in items), reverse=True
    )
    newest = runs(client, "echo.auto", limit=2)
    assert newest.status_code == 200 and newest.headers["Cache-Control"] == "no-store"
    assert len(newest.json()["items"]) == 2
    mine = {item["action_id"]: item for item in items}
    for result in made:
        item = mine[result["action_id"]]
        assert set(item) == {
            "action_id",
            "actor_id",
            "parent_action_id",
            "version",
            "status",
            "created_at",
            "args",
            "response",
        }
        assert item["actor_id"] == pi["id"] and item["args"] == {"value": "hi"}
        assert item["status"] == "completed" and item["response"] == result
    for limit in (0, 51, "x"):
        assert runs(client, "echo.auto", limit=limit).status_code == 422
    assert runs(client, "echo.nowhere").json() == {"items": []}
    assert runs(client, "bad id!").status_code == 404
