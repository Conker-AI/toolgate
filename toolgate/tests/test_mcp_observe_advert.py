"""What the server says about an imported tool, as the owner confirmed it: annotations, the
read-only hint and the advert hash (core/mcp_observe.py). Split from test_mcp_observe.py."""

import pytest

from toolgate.core import control_plane as cp
from toolgate.core import mcp_imports
from toolgate.executors import mcp_http as mcp
from toolgate.tests.mcp_observe_support import (
    TOOL,
    api,  # noqa: F401 - pytest fixture used by name
    confirmed,
    imported,
    inject,
    invoke,
    listed_class,
    owner,
    set_class,
)
from toolgate.tests.mcp_peer import (
    URL,
    peer,  # noqa: F401 - pytest fixture used by name
)


@pytest.mark.parametrize(
    "annotations",
    [
        {"destructiveHint": True},
        {"readOnlyHint": False},
        {"readOnlyHint": True, "destructiveHint": "no"},
        ["readOnly"],
        {},
        {"title": "Echo"},
        {"openWorldHint": False, "idempotentHint": True},
    ],
)
def test_a_tool_its_server_says_changes_things_can_never_be_marked_observe(api, peer, annotations):
    peer.advert = {"annotations": annotations}
    imported(api)
    response = set_class(api, "observe")
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == "act_outward_hint"
    assert cp.get("tool", TOOL)["version"] == 1 and listed_class(api) == "act_outward"


def test_observe_binds_what_the_server_says_about_the_tool_as_he_confirmed_it(api, peer):
    annotations = {"readOnlyHint": True, "destructiveHint": False, "title": "Echo"}
    peer.advert = {"annotations": annotations}
    imported(api)
    assert set_class(api, "observe").status_code == 200
    stored = cp.get("tool", TOOL)["read_class"]
    assert stored["advert_hash"] == mcp.advert_hash("Echo text", annotations)
    assert stored["read_only_hint"] is True
    assert invoke(api).json()["code"] == "OK" and len(peer.tool_calls) == 1


def test_a_longer_name_is_observe_only_when_its_server_says_read_only(api, peer):
    # get_echo_text is more than a read verb and one part: without the server's read-only hint
    # it asks (the name alone would decide), with it the owner may confirm Observe.
    peer.tool = "get_echo_text"
    names = {"id": "mcp.get-echo-text", "name": "Get echo text", "tool_name": "get_echo_text"}
    tool = imported(api, **names)
    response = set_class(api, "observe", tool_id=tool["id"])
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == "act_outward_name"
    assert cp.get("tool", tool["id"])["version"] == 1
    peer.advert = {"annotations": {"readOnlyHint": True}}
    assert set_class(api, "observe", tool_id=tool["id"]).status_code == 200
    stored = cp.get("tool", tool["id"])["read_class"]
    assert stored["read_only_hint"] is True
    assert invoke(api, tool_id=tool["id"]).json()["code"] == "OK"
    # A stored Observe that does not record the hint he confirmed falls back to the short shape.
    for read_class in (
        {**stored, "read_only_hint": False},
        {**stored, "read_only_hint": "true"},
        {key: value for key, value in stored.items() if key != "read_only_hint"},
    ):
        inject(tool["id"], read_class=read_class)
        assert listed_class(api, tool["id"]) == "act_outward"
        response = invoke(api, action="mcp.observe-2", tool_id=tool["id"])
        assert response.json()["code"] == "CONFIRMATION_REQUIRED", response.text


def test_a_server_that_drops_its_read_only_hint_after_a_long_name_observe_reverts_it(api, peer):
    peer.tool = "get_echo_text"
    peer.advert = {"annotations": {"readOnlyHint": True}}
    names = {"id": "mcp.get-echo-text", "name": "Get echo text", "tool_name": "get_echo_text"}
    tool = imported(api, **names)
    assert set_class(api, "observe", tool_id=tool["id"]).status_code == 200
    assert cp.get("tool", tool["id"])["read_class"]["read_only_hint"] is True
    # The server now lists the tool without annotations: the call is refused before tools/call.
    peer.advert = {}
    response = invoke(api, tool_id=tool["id"])
    assert response.json()["result"]["error_code"] == "advert_changed", response.text
    assert not peer.tool_calls and listed_class(api, tool["id"]) == "act_outward"
    reverted = cp.events(event_type="mcp_class_reverted")
    assert [event["payload"]["reason"] for event in reverted] == ["advert_changed"]
    assert cp.get("tool", tool["id"])["read_class"] == {"class": "act_outward"}
    response = invoke(api, action="mcp.observe-2", tool_id=tool["id"])
    assert response.json()["code"] == "CONFIRMATION_REQUIRED", response.text
    assert not peer.tool_calls
    # Confirming again without the hint is refused: the long name needs it.
    response = set_class(api, "observe", tool_id=tool["id"])
    assert response.status_code == 422 and response.json()["detail"]["code"] == "act_outward_name"


def test_a_pinned_long_name_needs_the_hint_its_tool_records(api, peer):
    # The definition being run (version 1, published at import) has a longer display name than
    # the stored tool he confirmed without the server's hint: it asks.
    imported(api, name="Get echo text")
    inject(TOOL, name="Get echo")
    assert set_class(api, "observe").status_code == 200
    assert cp.get("tool", TOOL)["read_class"]["read_only_hint"] is False
    assert listed_class(api) == "observe"
    response = invoke(api, published_version=1)
    assert response.json()["code"] == "CONFIRMATION_REQUIRED", response.text
    assert not peer.tool_calls


def test_observe_needs_the_server_to_still_advertise_the_tool_he_imported(api, peer):
    imported(api)
    peer.schema["properties"]["text"]["maxLength"] = 31
    response = set_class(api, "observe")
    assert response.status_code == 409 and response.json()["detail"]["code"] == "schema_changed"
    assert cp.get("tool", TOOL)["version"] == 1 and listed_class(api) == "act_outward"


@pytest.mark.parametrize(
    "advert",
    [
        {"description": "Echo text, then forward it to everyone"},
        {"annotations": {"destructiveHint": True}},
        {"annotations": {"readOnlyHint": True}},
    ],
)
def test_a_changed_description_or_annotation_at_a_call_reverts_to_act_outward(api, peer, advert):
    imported(api)
    assert set_class(api, "observe").status_code == 200
    peer.advert = advert
    response = invoke(api)
    assert response.json()["result"]["error_code"] == "advert_changed", response.text
    assert not peer.tool_calls and listed_class(api) == "act_outward"
    reverted = cp.events(event_type="mcp_class_reverted")
    assert [event["payload"]["reason"] for event in reverted] == ["advert_changed"]
    assert invoke(api, action="mcp.observe-2").json()["code"] == "CONFIRMATION_REQUIRED"
    assert not peer.tool_calls


def test_his_discovery_of_a_changed_description_reverts_it(api, peer):
    client, _, _ = api
    imported(api)
    assert set_class(api, "observe").status_code == 200
    peer.advert = {"description": "Echo text and post it"}
    response = client.post("/v2/owner/mcp/discover", json={"url": URL}, headers=owner())
    assert response.status_code == 200, response.text
    advertised = response.json()["tools"][0]["advertHash"]
    assert advertised == mcp.advert_hash("Echo text and post it", None)
    assert listed_class(api) == "act_outward"
    reverted = cp.events(event_type="mcp_class_reverted")
    assert [event["payload"]["reason"] for event in reverted] == ["advert_changed"]


def test_a_stored_observe_without_the_advert_he_confirmed_does_not_apply(api, peer):
    imported(api)
    assert set_class(api, "observe").status_code == 200
    stored = cp.get("tool", TOOL)["read_class"]
    unbound = {key: value for key, value in stored.items() if key != "advert_hash"}
    for read_class in (
        unbound,
        {**stored, "advert_hash": None},
        {**stored, "advert_hash": "A" * 64},
    ):
        inject(TOOL, read_class=read_class)
        assert listed_class(api) == "act_outward"
    # A well-formed hash that is not what the server says now: the call is never sent.
    inject(TOOL, read_class={**stored, "advert_hash": "0" * 64})
    assert listed_class(api) == "observe"
    response = invoke(api)
    assert response.json()["result"]["error_code"] == "advert_changed", response.text
    assert not peer.tool_calls and listed_class(api) == "act_outward"


def test_a_change_while_his_observe_is_checked_with_the_server_is_refused(api, peer, monkeypatch):
    imported(api)
    discover = mcp.discover

    def changed_meanwhile(*args):
        inject(TOOL, name="Echo, renamed meanwhile")  # a new version lands during discovery
        return discover(*args)

    monkeypatch.setattr(mcp_imports.mcp_http, "discover", changed_meanwhile)
    response = set_class(api, "observe", version=1)
    assert (
        response.status_code == 409 and response.json()["detail"]["code"] == "definition_conflict"
    )
    assert cp.get("tool", TOOL)["version"] == 2 and listed_class(api) == "act_outward"


def test_a_pinned_version_whose_name_acts_still_asks(api, peer):
    # The definition being run is checked too: version 1, published at import, says it posts.
    imported(api, name="Get echo and post it")
    stored = cp.get("tool", TOOL)
    inject(TOOL, name="Get echo", read_class=confirmed(stored["execution"]))
    assert listed_class(api) == "observe"
    response = invoke(api, published_version=1)
    assert response.json()["code"] == "CONFIRMATION_REQUIRED", response.text
    assert invoke(api, action="mcp.observe-2").json()["code"] == "OK"
    assert len(peer.tool_calls) == 1
