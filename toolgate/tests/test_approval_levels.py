"""What approving a request must prove, worked out by ToolGate when the request is made."""

import json

import pytest

from toolgate.api import definitions
from toolgate.core import approval_levels as levels
from toolgate.core import approvals, ask_cards
from toolgate.core import control_plane as cp
from toolgate.core import publications as pub
from toolgate.tests.test_access_policy import api, asked, invoke, owner, tool  # noqa: F401
from toolgate.tests.test_ask_cards import card
from toolgate.tests.test_editor_execution import linear
from toolgate.tests.test_editor_publication import registry, save  # noqa: F401


def level_of(client, response):
    assert asked(response), response.text
    view = client.get(f"/v2/owner/requests/{response.json()['request_id']}", headers=owner())
    assert view.status_code == 200, view.text
    return view.json()["approval_level"]


@pytest.mark.parametrize("template,expected", [
    ("do", 1), ("run", 1), ("save", 1), ("send", 2), ("publish", 2), ("ship", 2),
    ("delete", 3), ("pay", 3),
])
def test_his_card_for_the_tool_sets_the_level(api, template, expected):
    client, _, pi_key, _ = api
    assert card(client, "echo.ask", template).status_code == 200
    assert level_of(client, invoke(client, pi_key, "echo.ask", action=template)) == expected


def test_a_tool_he_never_labelled_is_judged_by_its_name(api):
    client = api[0]
    cp.create_tool(tool("files.deleteFolder"))
    cp.create_tool(tool("mail.send_reply"))
    _, key = cp.issue_agent_key("Namer", ["files.deleteFolder", "mail.send_reply"])
    assert level_of(client, invoke(client, key, "files.deleteFolder")) == 3
    assert level_of(client, invoke(client, key, "mail.send_reply")) == 2
    # A milder card he picks cannot lower what the name says.
    assert card(client, "files.deleteFolder", "save").status_code == 200
    assert level_of(client, invoke(client, key, "files.deleteFolder", action="again")) == 3


def test_the_level_is_fixed_when_the_request_is_made(api):
    client, _, pi_key, _ = api
    first = invoke(client, pi_key, "echo.ask", action="first")
    assert card(client, "echo.ask", "pay").status_code == 200
    assert level_of(client, first) == 1
    assert level_of(client, invoke(client, pi_key, "echo.ask", action="second")) == 3


def test_what_a_tool_runs_raises_its_level():
    assert levels.for_tool(tool("x.a"), {}) == 1
    for kind in ("port_control", "container_control", "process_control"):
        assert levels.for_tool(tool("x.a", execution={"type": kind}), {"x.a": "save"}) == 3
    assert levels.for_tool(tool("x.a", execution={"type": "mcp_http"}), {}) == 2
    assert levels.for_tool(tool("x.a", execution={"type": "http_json", "method": "post"}), {}) == 2
    assert levels.for_tool(tool("x.a", execution={"type": "http_json", "method": "GET"}), {}) == 1
    assert levels.for_tool(tool("x.a", execution={"type": "http_json"}), {}) == 1
    assert levels.for_tool(tool("x.a", execution={"type": "mcp_http"}), {"x.a": "pay"}) == 3
    assert levels.for_tool(tool("x.a"), {"x.a": "not-a-card"}) == 3


@pytest.mark.parametrize("value", [None, "pay", [], {"id": 3}, {"name": "no id"}])
def test_an_unreadable_tool_is_serious(value):
    assert levels.for_tool(value, {}) == 3


@pytest.mark.parametrize("value,expected", [(1, 1), (2, 2), (3, 3), (None, 3), (0, 3), (4, 3),
                                            (True, 3), ("1", 3), (1.0, 3)])
def test_a_missing_or_odd_stored_level_is_serious(value, expected):
    assert levels.stored(value) == expected


def test_a_tool_it_cannot_find_asks_for_the_password(api):
    request = approvals.create_verification_request("Run", "exact", "Pi", "tool", "not.registered", {}, 1)
    assert request["payload"]["level"] == 3


@pytest.mark.parametrize("shown,expected", [("do", 1), ("send", 2), ("pay", 3), ("odd", 3)])
def test_the_level_is_never_below_the_card_the_inbox_shows(api, shown, expected):
    # The card is copied from the caller; whatever buttons it shows, the level is at least as strong.
    request = approvals.create_verification_request("Run", "exact", "Pi", "tool", "echo.ask", {}, 1,
                                                    card=shown)
    assert request["payload"]["level"] == expected


def publish_workflow(identity, *tool_ids):
    steps = [(f"call{i}", "tool_call", {"tool": tool_id, "args": {}}) for i, tool_id in enumerate(tool_ids)]
    save(identity, linear(*steps, ("result", "return", {"value": "$last"})))
    return pub.publish("automation", identity, 1, validate=definitions.require_valid_automation_definition)


def workflow_request(publication):
    payload = approvals.create_verification_request(
        "Run", "exact", "Pi", "automation", publication["id"], {}, 1,
        publication_digest=publication["digest"])["payload"]
    return payload["level"], payload["card"]


def echo_tool(identity, name):
    cp.create_tool({"id": identity, "name": name, "description": "Test", "execution": {"type": "echo"}})


def test_a_workflow_takes_the_strongest_tool_it_runs(registry):
    echo_tool("notes.save", "Save note")
    plain = publish_workflow("graph", "echo", "notes.save")
    assert workflow_request(plain) == (1, "do")
    ask_cards.set_card("echo", "send")
    assert workflow_request(plain) == (2, "send")
    ask_cards.set_card("notes.save", "pay")
    assert workflow_request(plain) == (3, "pay")


def test_a_workflow_that_runs_a_delete_named_tool_is_serious(registry):
    echo_tool("files.remove", "Remove file")
    assert workflow_request(publish_workflow("child", "echo", "files.remove")) == (3, "do")


def test_a_workflow_named_for_a_payment_is_serious(registry):
    assert workflow_request(publish_workflow("graph", "echo"))[0] == 1
    assert workflow_request(publish_workflow("monthly-payout", "echo"))[0] == 3


def unpublished(identity, tool_id):
    cp.create_automation({"id": identity, "name": identity, "description": "x", "status": "active",
                          "workflow": [{"type": "tool_call", "tool_id": tool_id}]})
    return approvals.create_verification_request(
        "Run", "exact", "Pi", "automation", identity, {}, 1)["payload"]["level"]


def test_an_unpublished_workflow_counts_its_tools(registry):
    echo_tool("files.wipe", "Files")
    assert unpublished("tidy", "echo") == 1
    assert unpublished("tidy-two", "files.wipe") == 3
    assert unpublished("purge-old", "echo") == 3


def test_a_lowered_level_breaks_the_requests_origin(api):
    client, _, pi_key, _ = api
    assert card(client, "echo.ask", "delete").status_code == 200
    identity = invoke(client, pi_key, "echo.ask").json()["request_id"]
    record = cp.get("request", identity)
    assert record["payload"]["level"] == 3
    record["payload"]["level"] = 1
    with cp._conn() as db:
        db.execute("UPDATE v2_objects SET body=? WHERE kind='request' AND id=?",
                   (json.dumps(record), identity))
    view = client.get(f"/v2/owner/requests/{identity}", headers=owner()).json()
    assert view["unavailable_reason"] == "invalid_origin" and not view["reviewable"]
    decided = client.post(f"/v2/owner/requests/{identity}/decision", headers=owner(),
                          json={"status": "approved"})
    assert decided.status_code == 409
