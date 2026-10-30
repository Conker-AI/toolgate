"""The buttons his Inbox card shows for a tool: a fixed template he picks, copied into each request."""

from toolgate.api import definitions
from toolgate.core import ask_cards, editor_catalogue
from toolgate.core import control_plane as cp
from toolgate.core import publications as pub
from toolgate.tests.test_access_policy import api, asked, invoke, owner  # noqa: F401
from toolgate.tests.test_editor_execution import linear
from toolgate.tests.test_editor_publication import registry, save  # noqa: F401


def card(client, tool_id, template, headers=None):
    return client.post(
        f"/v2/owner/tools/{tool_id}/card",
        json={"template": template},
        headers=owner() if headers is None else headers,
    )


def request_card(client, response):
    assert asked(response), response.text
    view = client.get(f"/v2/owner/requests/{response.json()['request_id']}", headers=owner())
    assert view.status_code == 200, view.text
    return view.json()["card"]


def test_a_request_shows_the_buttons_chosen_when_it_was_made(api):
    client, _, pi_key, _ = api
    first = invoke(client, pi_key, "echo.ask", action="c1")
    assert request_card(client, first) == "do"

    changed = card(client, "echo.ask", "send")
    assert changed.status_code == 200 and changed.json() == {"id": "echo.ask", "template": "send"}
    assert request_card(client, invoke(client, pi_key, "echo.ask", action="c2")) == "send"
    # A request already waiting keeps the buttons it was made with.
    assert request_card(client, first) == "do"


def test_choosing_buttons_changes_nothing_about_the_tool(api):
    client, _, pi_key, _ = api
    before = cp.get("tool", "echo.ask")
    assert card(client, "echo.ask", "publish").status_code == 200
    assert cp.get("tool", "echo.ask") == before
    state = client.get("/v2/owner/access", headers=owner(pi_key)).json()
    assert state["cards"] == {"echo.ask": "publish", "sandbox.run": "run"}
    assert card(client, "echo.ask", "do").status_code == 200
    assert client.get("/v2/owner/access", headers=owner(pi_key)).json()["cards"] == {
        "sandbox.run": "run"
    }


def test_only_the_owner_picks_and_only_from_the_list(api):
    client, _, pi_key, _ = api
    assert card(client, "echo.ask", "send", {"X-ToolGate-Execution-Key": pi_key}).status_code in (
        401,
        403,
    )
    assert card(client, "echo.ask", "send", {}).status_code in (401, 403)
    # Free text could label the approve button "Cancel"; only the fixed templates exist.
    assert card(client, "echo.ask", "Cancel").status_code == 422
    assert card(client, "echo.nowhere", "send").status_code == 404
    assert ask_cards.card_for("echo.ask") == "do"


def test_a_missing_or_unknown_stored_template_shows_the_default():
    assert ask_cards.valid(None) == "do"
    assert ask_cards.valid("Cancel") == "do"
    assert ask_cards.valid("pay") == "pay"


def listed_cards(client, key):
    rows = client.get("/v2/agent/tools", headers={"X-ToolGate-Execution-Key": key}).json()
    return {row["id"]: row["card"] for row in rows}


def test_the_agent_tool_list_carries_the_card_he_picked(api):
    client, _, pi_key, _ = api
    # Pi's reviewer reads `card` here: send, publish, ship, delete and pay always ask him.
    assert listed_cards(client, pi_key) == {
        "echo.ask": "do",
        "echo.auto": "do",
        "echo.blocked": "do",
    }
    assert card(client, "echo.auto", "send").status_code == 200
    assert card(client, "echo.ask", "pay").status_code == 200
    cards = client.get("/v2/owner/access", headers=owner(pi_key)).json()["cards"]
    listed = listed_cards(client, pi_key)
    # The same value his Inbox card settings hold, tool by tool.
    assert listed == {tool_id: cards.get(tool_id, "do") for tool_id in listed}
    assert listed == {"echo.ask": "pay", "echo.auto": "send", "echo.blocked": "do"}
    assert card(client, "echo.auto", "do").status_code == 200
    assert listed_cards(client, pi_key)["echo.auto"] == "do"


def test_a_published_workflow_shows_the_strongest_card_of_the_tools_it_runs(registry):
    _, agent = registry
    document = linear(
        ("call", "tool_call", {"tool": "echo", "args": {}}),
        ("result", "return", {"value": "$last"}),
    )
    save("graph", document)
    pub.publish("automation", "graph", 1, validate=definitions.require_valid_automation_definition)
    rows = editor_catalogue.agent_workflows(agent)
    assert [row["card"] for row in rows] == ["do"]
    ask_cards.set_card("echo", "send")
    assert [row["card"] for row in editor_catalogue.agent_workflows(agent)] == ["send"]


def test_the_strongest_template_wins_and_none_is_the_default():
    assert ask_cards.for_workflow(["a", "b", "c"], {"a": "run", "b": "pay", "c": "send"}) == "pay"
    assert ask_cards.for_workflow(["a", "b"], {"a": "run", "b": "save"}) == "save"
    assert ask_cards.for_workflow(["a"], {"b": "pay"}) == "do"
    assert ask_cards.for_workflow([], {}) == "do"
    assert set(ask_cards.STRONGEST) == set(ask_cards.TEMPLATES) - {ask_cards.DEFAULT}
