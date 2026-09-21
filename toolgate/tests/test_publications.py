import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import publications as pub


@pytest.fixture
def definitions(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "publications.db")
    tool = cp.create_tool({"id": "child", "name": "Child", "description": "Local echo",
                           "execution": {"type": "echo"}, "status": "active"})
    flow = cp.create_automation({"id": "flow", "name": "Flow", "description": "Local workflow",
                                 "status": "active", "workflow": [{"type": "tool_call", "tool_id": "child"}]})
    return tool, flow


def test_publish_pins_dependencies_and_is_idempotent(definitions):
    tool, flow = definitions
    published = pub.publish("automation", "flow", 1)
    assert published["tools"]["child"] == tool
    assert published["definition"] == flow
    assert pub.history("automation", "flow")[0]["published"]
    cp.update_tool("child", {**tool, "name": "Changed"})
    assert pub.publish("automation", "flow", 1) == published
    assert pub.get("automation", "flow", 1, published=True) == published
    assert len([event for event in cp.events() if event["event_type"] == "definition_published"]) == 1


@pytest.mark.parametrize("kind", ["tool", "automation"])
def test_history_survives_delete_and_recreate_without_reusing_version(definitions, kind):
    first = definitions[0 if kind == "tool" else 1]
    obj_id = first["id"]
    saved = pub.publish(kind, obj_id, 1)
    update = getattr(cp, f"update_{kind}")
    second = update(obj_id, {**first, "name": "Second"})
    assert pub.get(kind, obj_id, 1) == first
    assert pub.get(kind, obj_id, 2) == second
    assert pub.get(kind, obj_id, 2, published=True) is None
    assert cp.remove(kind, obj_id)
    third = getattr(cp, f"create_{kind}")({**first, "version": 1})
    assert third["version"] == 3
    assert pub.get(kind, obj_id, 1, published=True) == saved
    assert [item["version"] for item in pub.history(kind, obj_id)] == [3, 2, 1]
    with pytest.raises(cp.DefinitionConflict):
        pub.publish(kind, obj_id, 1)


def test_unresolved_or_mismatched_dependency_rejected(definitions):
    _, flow = definitions
    cp.remove("tool", "child")
    with pytest.raises(pub.PublicationInvalid):
        pub.publish("automation", "flow", 1)
    assert pub.get("automation", "flow", 1, published=True) is None
    tool = cp.create_tool({"id": "child", "execution": {"type": "echo"}})
    changed = cp.update_automation("flow", {**flow, "workflow": [
        {"type": "tool_call", "tool_id": "child", "tool_version": tool["version"] + 1}]})
    with pytest.raises(pub.PublicationInvalid):
        pub.publish("automation", "flow", changed["version"])


@pytest.mark.parametrize("workflow", [
    [{"type": "automation_call", "automation_id": "flow"}],
    [{"type": "return", "value": 1}] * 501,
    [{"type": "retry", "step": {"type": "retry", "step": {"type": "retry", "step": {
        "type": "retry", "step": {"type": "retry", "step": {"type": "return", "value": 1}}}}}}],
])
def test_unsupported_cycles_and_unbounded_structure_rejected(definitions, workflow):
    _, flow = definitions
    saved = cp.update_automation("flow", {**flow, "workflow": workflow})
    with pytest.raises(pub.PublicationInvalid):
        pub.publish("automation", "flow", saved["version"])


def test_database_publication_and_history_are_immutable(definitions):
    pub.publish("tool", "child", 1)
    for table in ["v2_publications", "v2_definition_versions"]:
        for sql in [f"UPDATE {table} SET body='{{}}'", f"DELETE FROM {table}",
                    f"INSERT OR REPLACE INTO {table} SELECT * FROM {table}"]:
            with pytest.raises(sqlite3.IntegrityError), cp._conn() as conn:
                conn.execute(sql)


def test_concurrent_publication_has_one_snapshot(definitions):
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: pub.publish("automation", "flow", 1), range(4)))
    assert all(result == results[0] for result in results)
    assert len([event for event in cp.events() if event["event_type"] == "definition_published"]) == 1


def test_owner_http_publication_and_history(definitions):
    client = TestClient(server.app)
    assert client.post("/v2/automations/flow/publish", json={"expected_version": 1}).status_code in {401, 403}
    server.app.dependency_overrides[server.require_admin] = lambda: "admin"
    try:
        response = client.post("/v2/automations/flow/publish", json={"expected_version": 1})
        assert response.status_code == 200, response.text
        assert response.json()["tools"]["child"]["version"] == 1
        assert client.get("/v2/automations/flow/versions").json()[0]["published"]
        assert client.get("/v2/automations/flow/versions/1?published=true").json() == response.json()
        assert client.get("/v2/automations/flow/versions/99?published=true").status_code == 404
        assert client.post("/v2/automations/flow/publish", json={"expected_version": 9}).status_code == 409
        assert client.post("/v2/automations/missing/publish", json={"expected_version": 1}).status_code == 404
        for invalid in [0, True, "1"]:
            assert client.post("/v2/automations/flow/publish", json={"expected_version": invalid}).status_code == 422
    finally:
        server.app.dependency_overrides.pop(server.require_admin, None)
