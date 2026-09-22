from concurrent.futures import ThreadPoolExecutor

from toolgate.core import control_plane as cp
from toolgate.tests.test_owner_channel import gate, HEADERS, ADMIN  # noqa: F401
from toolgate.tests.test_editor_execution import linear


def save(client, value=None, revision=0):
    return client.post("/v2/owner/editor-drafts/example", headers=HEADERS, json={
        "expected_revision": revision,
        "document": value or linear(("result", "return", {"value": 7}))})


def publish(client, revision=1, previous=0, **fields):
    return client.post("/v2/owner/editor-drafts/example/publish", headers=HEADERS, json={
        "expected_revision": revision, "expected_publication_version": previous, **fields})


def test_owner_publication_is_atomic_versioned_and_does_not_grant_execution(gate):
    client, agent, execution = gate
    assert save(client).status_code == 200
    first = publish(client)
    assert first.status_code == 200, first.text
    identity = first.json()["automation_id"]
    assert first.json()["version"] == 1
    assert publish(client).json() == first.json()
    assert cp.authenticate_agent(execution)["scopes"] == ["tool:example"]
    assert cp.get("automation", identity)["authorization"] == "owner_confirmation"
    assert save(client, revision=1).status_code == 200
    assert publish(client, revision=2).status_code == 409
    second = publish(client, revision=2, previous=1)
    assert second.status_code == 200, second.text
    assert second.json()["version"] == 2
    history = client.get("/v2/owner/editor-drafts/example/publications", headers=HEADERS).json()["items"]
    assert [row["revision"] for row in history] == [2, 1]
    assert all(row["available"] for row in history)


def test_missing_dependency_rolls_back_definition_and_publication(gate):
    client = gate[0]
    graph = linear(("call", "tool_call", {"tool": "missing", "args": {}}),
                   ("result", "return", {"value": "$last"}))
    assert save(client, graph).status_code == 200
    assert publish(client).status_code == 422
    assert cp.list_objects("automation") == []
    assert client.get("/v2/owner/editor-drafts/example/publications", headers=HEADERS).json() == {"items": []}


def test_channels_and_exact_saved_revision_are_enforced(gate):
    client, _, execution = gate
    assert save(client).status_code == 200
    path = "/v2/owner/editor-drafts/example/publish"
    body = {"expected_revision": 1, "expected_publication_version": 0}
    for headers in ({}, {"X-ToolGate-Key": ADMIN}, {"X-ToolGate-Execution-Key": execution}):
        assert client.post(path, headers=headers, json=body).status_code == 401
    assert publish(client, revision=2).status_code == 409
    assert publish(client, authorization="blocked").status_code == 422
    assert publish(client, authorization="auto").status_code == 200
    assert publish(client, authorization="owner_confirmation").status_code == 409


def test_concurrent_publish_creates_one_immutable_version(gate):
    client = gate[0]
    assert save(client).status_code == 200
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: publish(client), range(2)))
    assert all(response.status_code == 200 for response in results)
    assert results[0].json() == results[1].json()
    with cp._conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM v2_publications").fetchone()[0] == 1
