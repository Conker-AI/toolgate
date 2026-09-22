"""Owner draft persistence must not publish, grant or execute anything."""
from concurrent.futures import ThreadPoolExecutor

from toolgate.core import control_plane as cp
from toolgate.tests.test_owner_channel import gate, HEADERS, ADMIN  # noqa: F401


def document(identity="example"):
    return {"id": identity, "name": "Example", "description": "", "kind": "workflow",
            "nodes": [{"id": "input", "type": "input", "label": "Input",
                       "position": {"x": 0, "y": 0}, "config": {}},
                      {"id": "result", "type": "return", "label": "Return",
                       "position": {"x": 200, "y": 0}, "config": {"value": "$last"}}],
            "edges": [], "inputs": [], "outputs": [], "credentialRefs": [],
            "effect": "read", "agentVisible": True,
            "budgets": {"maxSteps": 80, "maxLoopItems": 20, "timeoutMs": 5000}}


def save(client, revision=0, value=None, headers=None):
    return client.post("/v2/owner/editor-drafts/example", headers=headers or HEADERS,
                       json={"expected_revision": revision, "document": value or document()})


def test_round_trip_retains_disconnected_draft_without_execution_authority(gate):
    client, _, execution = gate
    value = document()
    response = save(client, value=value)
    assert response.status_code == 200, response.text
    assert response.json()["document"] == value
    assert response.json()["revision"] == 1
    assert client.get("/v2/owner/editor-drafts/example", headers=HEADERS).json() == response.json()
    assert client.get("/v2/owner/editor-drafts", headers=HEADERS).json()["items"][0]["id"] == "example"
    assert cp.get("tool", "example") is None
    assert cp.get("automation", "example") is None
    assert cp.authenticate_agent(execution)["scopes"] == ["tool:example"]
    with cp._conn() as db:
        assert db.execute("SELECT COUNT(*) FROM v2_publications").fetchone()[0] == 0


def test_owner_only_and_cannot_be_used_as_admin_or_execution(gate):
    client, _, execution = gate
    for headers in ({"X-ToolGate-Key": ADMIN}, {"X-ToolGate-Execution-Key": execution},
                    {"X-ToolGate-Owner-Key": execution}, {"X-ToolGate-Owner-Key": "wrong"}):
        assert save(client, headers=headers).status_code == 401
        assert client.get("/v2/owner/editor-drafts", headers=headers).status_code == 401
    assert save(client).status_code == 200


def test_stale_and_simultaneous_writes_do_not_overwrite(gate):
    client = gate[0]
    assert save(client).status_code == 200
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: save(client, revision=1).status_code, range(2)))
    assert sorted(results) == [200, 409]
    assert save(client, revision=1).status_code == 409
    assert client.get("/v2/owner/editor-drafts/example", headers=HEADERS).json()["revision"] == 2


def test_invalid_identity_unknown_fields_and_oversized_drafts_rejected(gate):
    client = gate[0]
    for change in ({"id": "different"}, {"script": "not an executable document"},
                   {"credentialRefs": ["raw-secret"]}, {"name": " "}):
        assert save(client, value={**document(), **change}).status_code == 422
    value = document()
    value["nodes"][1]["config"] = {"value": "a" * 150001}
    assert save(client, value=value).status_code == 422
    assert client.get("/v2/owner/editor-drafts", headers=HEADERS).json()["items"] == []


def test_keyset_pagination_has_no_full_documents(gate):
    client = gate[0]
    for identity in ("a", "b", "c"):
        assert client.post(f"/v2/owner/editor-drafts/{identity}", headers=HEADERS,
                           json={"expected_revision": 0, "document": document(identity)}).status_code == 200
    page = client.get("/v2/owner/editor-drafts?limit=2", headers=HEADERS).json()
    assert [item["id"] for item in page["items"]] == ["a", "b"]
    assert all("document" not in item for item in page["items"])
    assert page["next_after"] == "b"
    page = client.get("/v2/owner/editor-drafts?limit=2&after=b", headers=HEADERS).json()
    assert [item["id"] for item in page["items"]] == ["c"]
    assert page["next_after"] is None


def test_saved_graph_validation_is_revision_bound_and_does_not_publish(gate):
    client = gate[0]
    assert save(client).status_code == 200
    path = "/v2/owner/editor-drafts/example/validation"
    assert client.get(path).status_code == 401
    result = client.get(path, headers=HEADERS).json()
    assert result["revision"] == 1 and result["graph_valid"] is False
    assert result["issues"] and result["execution_ready"] is False
    connected = document()
    connected["edges"] = [{"id": "next", "source": "input", "target": "result"}]
    assert save(client, revision=1, value=connected).status_code == 200
    result = client.get(path, headers=HEADERS).json()
    assert result["revision"] == 2 and result["graph_valid"] is True
    assert result["issues"] == [] and result["execution_ready"] is False
    assert cp.get("automation", "example") is None
