"""Publishing with "Let Conker use this tool": visible to agents and granted, or nothing at all."""

from toolgate.core import control_plane as cp
from toolgate.core import editor_publication
from toolgate.tests.test_editor_execution import linear
from toolgate.tests.test_editor_owner_publication import publish, save
from toolgate.tests.test_owner_channel import HEADERS, gate  # noqa: F401

PATH = "/v2/owner/editor-drafts/example/publish"
BODY = {"expected_revision": 1, "expected_publication_version": 0}


def hidden():
    value = linear(("result", "return", {"value": 7}))
    value["agentVisible"] = False
    return value


def with_key(gate, **extra):
    return {**HEADERS, "X-ToolGate-Execution-Key": gate[2], **extra}


def catalogue(gate):
    return (
        gate[0]
        .get("/v2/agent/published-workflows", headers={"X-ToolGate-Execution-Key": gate[2]})
        .json()
    )


def scopes(gate):
    return cp.authenticate_agent(gate[2])["scopes"]


def nothing_published():
    with cp._conn() as conn:
        editor_publication._table(conn)
        rows = [
            conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("v2_publications", "v2_editor_publications")
        ]
    return rows == [0, 0] and cp.list_objects("automation") == []


def test_publish_lets_conker_use_the_workflow_like_the_access_switch(gate):
    client = gate[0]
    assert save(client, hidden()).status_code == 200
    response = client.post(PATH, headers=with_key(gate), json={**BODY, "conkerMayUse": True})
    assert response.status_code == 200, response.text
    body = response.json()
    automation = editor_publication.automation_id("example")
    assert body["automation_id"] == automation and body["conkerMayUse"] is True
    assert body["toolId"] == f"workflow:{automation}:{body['version']}:{body['digest']}"
    assert [item["id"] for item in catalogue(gate)] == [body["toolId"]]
    granted = scopes(gate)
    assert granted == ["tool:example", f"automation:{automation}"]
    events = [event for event in cp.events() if event["event_type"] == "editor_access_granted"]
    assert len(events) == 1 and events[0]["subject_id"] == automation
    # The draft itself is unchanged; only the publication is visible to agents.
    draft = client.get("/v2/owner/editor-drafts/example", headers=HEADERS).json()
    assert draft["revision"] == 1 and draft["document"]["agentVisible"] is False
    # The owner's access switch would have given the key exactly these scopes.
    target = {"version": body["version"], "digest": body["digest"]}
    switch = client.post(
        "/v2/owner/editor-drafts/example/access",
        headers=with_key(gate),
        json={**target, "enabled": True},
    )
    assert switch.json()["enabled"] is True and scopes(gate) == granted


def test_publish_without_it_grants_nothing(gate):
    client = gate[0]
    assert save(client, hidden()).status_code == 200
    body = publish(client).json()
    assert body["conkerMayUse"] is False
    assert body["toolId"] == f"workflow:{body['automation_id']}:{body['version']}:{body['digest']}"
    assert scopes(gate) == ["tool:example"]
    assert catalogue(gate) == []


def test_it_stays_owner_only_and_needs_the_chats_own_key(gate):
    client, _agent, execution = gate
    assert save(client, hidden()).status_code == 200
    body = {**BODY, "conkerMayUse": True}
    assert (
        client.post(PATH, headers={"X-ToolGate-Execution-Key": execution}, json=body).status_code
        == 401
    )
    assert client.post(PATH, headers=HEADERS, json=body).status_code == 401
    assert (
        client.post(PATH, headers=with_key(gate), json={**body, "conkerMayUse": "yes"}).status_code
        == 422
    )
    assert nothing_published() and scopes(gate) == ["tool:example"]


def test_a_refused_grant_publishes_nothing(gate):
    client = gate[0]
    assert save(client, hidden()).status_code == 200
    agent = with_key(gate, **{"X-ToolGate-Agent": "companion"})
    response = client.post(PATH, headers=agent, json={**BODY, "conkerMayUse": True})
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "execution_unavailable"
    assert nothing_published() and scopes(gate) == ["tool:example"]
    assert not [event for event in cp.events() if event["event_type"] == "definition_published"]
    # The same revision then publishes normally: nothing was left half-done.
    assert (
        client.post(PATH, headers=with_key(gate), json={**BODY, "conkerMayUse": True}).status_code
        == 200
    )


def test_replaying_a_publication(gate):
    client = gate[0]
    assert save(client, hidden()).status_code == 200
    first = client.post(PATH, headers=with_key(gate), json={**BODY, "conkerMayUse": True}).json()
    again = client.post(PATH, headers=with_key(gate), json={**BODY, "conkerMayUse": True}).json()
    assert again == first and scopes(gate).count(f"automation:{first['automation_id']}") == 1
    # A revision published hidden from agents cannot be made visible by replaying it.
    assert save(client, hidden(), revision=1).status_code == 200
    assert publish(client, revision=2, previous=1).status_code == 200
    late = client.post(
        PATH,
        headers=with_key(gate),
        json={"expected_revision": 2, "expected_publication_version": 1, "conkerMayUse": True},
    )
    assert late.status_code == 409 and late.json()["detail"]["code"] == "publication_conflict"
