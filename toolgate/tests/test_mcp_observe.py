"""Observe or Act outward for imported MCP tools (core/mcp_observe.py): what each class asks, what
can never be Observe, and what still applies to an Observe call."""

import copy

import pytest

from toolgate.api import invocation
from toolgate.core import (
    access_policy,
    approval_levels,
    approvals,
    mcp_imports,
    owner_channel,
    spending,
)
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import mcp_observe as observe
from toolgate.executors import mcp_http as mcp
from toolgate.tests.mcp_observe_support import (
    READ_NAME,
    TOOL,
    api,  # noqa: F401 - pytest fixture used by name
    confirmed,
    import_body,
    imported,
    inject,
    invoke,
    listed_class,
    observe_execution,
    owner,
    requests,
    set_class,
)
from toolgate.tests.mcp_peer import (
    ADMIN,
    SCHEMA,
    URL,
    peer,  # noqa: F401 - pytest fixture used by name
)


def test_a_new_import_is_act_outward_and_asks_for_the_exact_call_at_level_two(api, peer):
    client, _, _ = api
    response = client.post(
        "/v2/owner/mcp/import", json=import_body(read_class="observe"), headers=owner()
    )
    assert response.status_code == 422  # Observe is never granted at import
    tool = imported(api)
    assert tool["read_class"] == "act_outward"
    assert "read_class" not in cp.get("tool", TOOL)
    response = invoke(api)
    assert response.status_code == 200, response.text
    assert response.json()["code"] == "CONFIRMATION_REQUIRED"
    identity = response.json()["request_id"]
    assert owner_channel.get(identity)["approval_level"] == approval_levels.OUTWARD
    approvals.decide_request(identity, "approved", "owner")
    # The approval is bound to the exact arguments: other text with it is refused, nothing is sent.
    other = invoke(api, action="mcp.observe-other", text="other", approval_request_id=identity)
    assert other.status_code == 409 and other.json()["detail"]["code"] == "APPROVAL_INVALID"
    assert not peer.tool_calls
    response = invoke(api, approval_request_id=identity)
    assert response.status_code == 200 and response.json()["code"] == "OK", response.text
    assert len(peer.tool_calls) == 1


def test_an_observe_tool_runs_without_a_card_once_per_action(api, peer):
    imported(api)
    response = set_class(api, "observe")
    assert response.status_code == 200, response.text
    assert response.json()["tool"]["read_class"] == "observe"
    assert response.json()["tool"]["version"] == 2
    assert cp.get("tool", TOOL)["authorization"] == "owner_confirmation"  # stored as before
    assert [event["payload"] for event in cp.events(event_type="mcp_class_changed")] == [
        {"read_class": "observe", "version": 2}
    ]
    response = invoke(api)
    assert response.status_code == 200 and response.json()["code"] == "OK", response.text
    assert len(peer.tool_calls) == 1 and not requests()
    # A retry of the same action returns its record; it never runs twice.
    assert invoke(api).json() == response.json()
    assert len(peer.tool_calls) == 1


def test_observe_keeps_scope_lockdown_limits_audit_and_spending(api, peer, monkeypatch):
    client, _, _ = api
    imported(api)
    tool = cp.get("tool", TOOL)
    inject(TOOL, policy={**tool["policy"], "usage_limits": {"max_per_minute": 1}})
    assert set_class(api, "observe").status_code == 200
    held, settled = [], []
    monkeypatch.setattr(invocation, "_spending_preflight", lambda *_: {"model": "fixture"})
    monkeypatch.setattr(spending, "reserve", lambda _conn, action, *_: held.append(action))
    monkeypatch.setattr(spending, "reconcile", lambda _conn, action, _usage: settled.append(action))
    assert invoke(api).json()["code"] == "OK"
    assert held == settled == ["mcp.observe-1"]
    # Audit: the journal holds the action and the event log says it ran as Observe.
    assert journal.get("mcp.observe-1")["status"] == "completed"
    executed = cp.events(event_type="tool_executed")
    assert [event["payload"] for event in executed] == [
        {"ok": True, "action_id": "mcp.observe-1", "read_class": "observe"}
    ]
    # Usage limit: the second call in the same minute is refused before anything is sent.
    limited = invoke(api, action="mcp.observe-2")
    assert limited.status_code == 429 and limited.json()["detail"]["code"] == "RATE_LIMITED"

    def no_budget(*_):
        raise spending.BudgetDenied("No budget left")

    monkeypatch.setattr(invocation, "_spending_preflight", no_budget)
    denied = invoke(api, action="mcp.observe-3")
    assert denied.status_code == 403 and denied.json()["detail"]["code"] == "BUDGET_DENIED"
    cp.set_lockdown(True, "owner")
    assert invoke(api, action="mcp.observe-4").status_code == 423
    cp.set_lockdown(False, "owner")
    # Scope: a key without the grant sees no such tool.
    _, other = cp.issue_agent_key("Other", [])
    response = client.post(
        f"/v2/tools/{TOOL}/invoke",
        json={"args": {"arguments": {"text": "hello"}}, "action_id": "mcp.observe-5"},
        headers={"X-ToolGate-Execution-Key": other},
    )
    assert response.status_code == 404
    assert len(peer.tool_calls) == 1 and not requests()


@pytest.mark.parametrize(
    "changes",
    [
        {"id": "mcp.chat-send", "tool_name": "send_message"},
        {"id": "mcp.get-echo-delete"},
        {"name": "Post a reply"},
    ],
)
def test_a_name_that_acts_can_never_be_marked_observe(api, peer, changes, monkeypatch):
    peer.extra_tools = [{"name": "send_message", "description": "Send", "inputSchema": SCHEMA}]
    tool = imported(api, **changes)

    def never_asked(*_):
        raise AssertionError("a name that acts with any hint is refused before the server")

    monkeypatch.setattr(mcp_imports.mcp_http, "discover", never_asked)
    response = set_class(api, "observe", tool_id=tool["id"])
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == "act_outward_name"
    assert cp.get("tool", tool["id"])["version"] == 1
    assert listed_class(api, tool["id"]) == "act_outward"


def test_a_stored_observe_on_a_name_that_acts_still_asks(api, peer):
    peer.extra_tools = [{"name": "send_message", "description": "Send", "inputSchema": SCHEMA}]
    tool = imported(api, id="mcp.chat", name="Chat", tool_name="send_message")
    stored = cp.get("tool", tool["id"])
    inject(tool["id"], read_class=confirmed(stored["execution"], "Send"))
    assert listed_class(api, tool["id"]) == "act_outward"
    assert invoke(api, tool_id=tool["id"]).json()["code"] == "CONFIRMATION_REQUIRED"


def test_only_the_owner_channel_marks_observe_for_the_version_it_saw(api, peer):
    client, _, key = api
    imported(api)
    body = {"read_class": "observe", "expected_version": 1}
    path = f"/v2/owner/mcp/tools/{TOOL}/class"
    for headers in ({}, {"X-ToolGate-Key": ADMIN}, {"X-ToolGate-Execution-Key": key}):
        assert client.post(path, json=body, headers=headers).status_code == 401
    for bad in (
        {"read_class": "observe"},
        {"read_class": "always", "expected_version": 1},
        {"read_class": "observe", "expected_version": True},
        {**body, "approved": True},
    ):
        assert client.post(path, json=bad, headers=owner()).status_code == 422
    stale = set_class(api, "observe", version=7)
    assert stale.status_code == 409 and stale.json()["detail"]["code"] == "definition_conflict"
    assert listed_class(api) == "act_outward" and cp.get("tool", TOOL)["version"] == 1
    assert set_class(api, "observe").status_code == 200
    stale = set_class(api, "act_outward", version=1)
    assert stale.status_code == 409 and stale.json()["detail"]["code"] == "definition_conflict"
    assert listed_class(api) == "observe" and cp.get("tool", TOOL)["version"] == 2
    # The admin catalogue cannot keep or grant it: a legacy upsert drops the class (fail closed).
    tool = cp.get("tool", TOOL)
    upsert = {key: tool[key] for key in ("name", "description", "inputs", "execution", "policy")}
    upsert.update(id=TOOL, authorization="owner_confirmation", read_class=tool["read_class"])
    response = client.put(f"/v2/tools/{TOOL}", json=upsert, headers={"X-ToolGate-Key": ADMIN})
    assert response.status_code == 200, response.text
    assert "read_class" not in cp.get("tool", TOOL) and listed_class(api) == "act_outward"
    assert invoke(api).json()["code"] == "CONFIRMATION_REQUIRED"


def test_act_outward_again_asks_at_once_and_no_op_keeps_the_version(api, peer):
    imported(api)
    assert set_class(api, "act_outward").json()["tool"]["version"] == 1  # already Act outward
    assert set_class(api, "observe").status_code == 200
    assert invoke(api).json()["code"] == "OK"
    # Act outward only tightens, so it never waits on the server: nothing is listed for it.
    listed = len(peer.calls)
    response = set_class(api, "act_outward")
    assert len(peer.calls) == listed
    assert response.status_code == 200 and response.json()["tool"]["read_class"] == "act_outward"
    assert invoke(api, action="mcp.observe-2").json()["code"] == "CONFIRMATION_REQUIRED"
    assert len(peer.tool_calls) == 1


def test_a_changed_schema_at_a_call_reverts_to_act_outward_until_he_confirms_again(api, peer):
    imported(api)
    assert set_class(api, "observe").status_code == 200
    original = copy.deepcopy(peer.schema)
    peer.schema["properties"]["text"]["maxLength"] = 31
    response = invoke(api)
    assert response.json()["result"]["error_code"] == "schema_changed", response.text
    assert not peer.tool_calls
    assert listed_class(api) == "act_outward"
    assert [event["payload"]["reason"] for event in cp.events(event_type="mcp_class_reverted")] == [
        "schema_changed"
    ]
    assert invoke(api, action="mcp.observe-2").json()["code"] == "CONFIRMATION_REQUIRED"
    peer.schema = original
    assert set_class(api, "observe").status_code == 200
    assert invoke(api, action="mcp.observe-3").json()["code"] == "OK"
    assert len(peer.tool_calls) == 1


def test_his_discovery_of_a_renamed_or_changed_tool_reverts_it(api, peer):
    client, _, _ = api
    imported(api)
    assert set_class(api, "observe").status_code == 200
    renamed = {"name": "echo2", "description": "Echo text", "inputSchema": SCHEMA}
    peer.pages = [{"tools": [renamed]}]
    response = client.post("/v2/owner/mcp/discover", json={"url": URL}, headers=owner())
    assert response.status_code == 200, response.text
    assert listed_class(api) == "act_outward"
    assert invoke(api).json()["code"] == "CONFIRMATION_REQUIRED"
    assert not peer.tool_calls


def test_a_stored_observe_for_another_schema_does_not_apply(api, peer):
    imported(api)
    assert set_class(api, "observe").status_code == 200
    stored = cp.get("tool", TOOL)["read_class"]
    inject(TOOL, read_class={**stored, "schema_hash": "0" * 64})
    assert listed_class(api) == "act_outward"
    assert invoke(api).json()["code"] == "CONFIRMATION_REQUIRED"


def test_observe_never_applies_outside_imported_mcp_tools(api, peer):
    _, _, key = api
    local = {"type": "local_echo", "url": URL, "tool_name": READ_NAME, "secret_ref": None}
    local["schema_hash"] = mcp.schema_hash(SCHEMA)
    for identity, execution in (("mcp.get-local", local), ("ext.get-echo", observe_execution())):
        cp.create_tool(
            {
                "id": identity,
                "name": "Get echo",
                "description": "Echo",
                "inputs": [{"name": "arguments", "type": "object", "required": True}],
                "execution": execution,
                "authorization": "owner_confirmation",
            }
        )
        read_class = {"class": "observe", **{key: execution[key] for key in observe.BOUND}}
        inject(
            identity, read_class={**read_class, "advert_hash": mcp.advert_hash("Echo text", None)}
        )
        cp.update_agent_key_scopes(cp.authenticate_agent(key)["id"], [identity])
        response = invoke(api, action=f"{identity}-1", tool_id=identity)
        assert response.json()["code"] == "CONFIRMATION_REQUIRED", response.text
        assert set_class(api, "observe", tool_id=identity).status_code == 404
    assert not peer.tool_calls


def test_an_ask_or_his_sensitive_mark_still_asks(api, peer):
    client, _, key = api
    imported(api)
    assert set_class(api, "observe").status_code == 200
    ask = {"outcome": "ask", "decided_by": "chat", "reason": "Ask me"}
    assert invoke(api, decision=ask).json()["code"] == "CONFIRMATION_REQUIRED"
    listed = client.get("/v2/agent/tools", headers={"X-ToolGate-Execution-Key": key}).json()
    row = {item["id"]: item for item in listed}[TOOL]
    assert (row["authorization"], row["sensitive"]) == ("auto", False)
    access_policy.set_sensitive(TOOL, True)
    assert invoke(api, action="mcp.observe-2").json()["code"] == "CONFIRMATION_REQUIRED"
    listed = client.get("/v2/agent/tools", headers={"X-ToolGate-Execution-Key": key}).json()
    row = {item["id"]: item for item in listed}[TOOL]
    assert (row["authorization"], row["sensitive"]) == ("owner_confirmation", True)
    assert not peer.tool_calls


def test_a_delegate_run_on_an_observe_tool_runs_and_pinned_versions_follow_his_class(api, peer):
    client, _, key = api
    imported(api)
    assert set_class(api, "observe").status_code == 200
    client.post("/v2/owner/access/delegate", json={"enabled": True}, headers=owner(key))
    run = {"outcome": "run", "decided_by": "chat", "reason": "Full access"}
    assert invoke(api, decision=run).json()["code"] == "OK"
    # Version 1 was published at import, before Observe: running it follows his current class.
    pinned = {"published_version": 1}
    assert invoke(api, action="mcp.observe-2", **pinned).json()["code"] == "OK"
    assert set_class(api, "act_outward").status_code == 200
    response = invoke(api, action="mcp.observe-3", **pinned)
    assert response.json()["code"] == "CONFIRMATION_REQUIRED", response.text
    assert len(peer.tool_calls) == 2


def test_a_class_change_during_a_call_is_caught_before_dispatch(api, peer, monkeypatch):
    imported(api)
    assert set_class(api, "observe").status_code == 200
    begin = journal.begin

    def changed_meanwhile(*args, **kwargs):
        assert set_class(api, "act_outward").status_code == 200
        return begin(*args, **kwargs)

    monkeypatch.setattr(invocation.journal, "begin", changed_meanwhile)
    response = invoke(api)
    assert response.status_code == 409 and response.json()["detail"]["code"] == "POLICY_DENIED"
    assert not peer.tool_calls and journal.get("mcp.observe-1") is None
