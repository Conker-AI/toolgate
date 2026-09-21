"""Stored versions and optimistic definition saves serialize against SQLite writers."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp


@pytest.fixture
def database(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "definitions.db")
    with cp._conn():
        pass


@pytest.mark.parametrize("kind", ["tool", "automation"])
def test_legacy_updates_and_upserts_allocate_from_storage(database, kind):
    create = getattr(cp, f"create_{kind}")
    update = getattr(cp, f"update_{kind}")
    first = create({"id": "item", "version": 7})
    assert first["version"] == 7  # Existing import/bootstrap contract.
    assert update("item", {"version": 1})["version"] == 8
    assert update("item", {"version": 999})["version"] == 9
    assert update("item", {})["version"] == 10
    assert create({"id": "item", "version": 1})["version"] == 11
    assert cp.get(kind, "item")["created_at"] == first["created_at"]
    assert update("missing", {"expected_version": 1}) is None
    assert cp.get(kind, "missing") is None


@pytest.mark.parametrize("kind", ["tool", "automation"])
def test_expected_version_rejects_stale_write_without_mutation(database, kind):
    create = getattr(cp, f"create_{kind}")
    update = getattr(cp, f"update_{kind}")
    create({"id": "item", "name": "Original"})
    saved = update("item", {"name": "Current", "expected_version": 1})
    assert saved["version"] == 2
    assert "expected_version" not in saved
    for save in [lambda: update("item", {"name": "Stale", "expected_version": 1}),
                 lambda: create({"id": "item", "name": "Stale upsert", "expected_version": 1})]:
        with pytest.raises(cp.DefinitionConflict) as error:
            save()
        assert error.value.current_version == 2
        assert cp.get(kind, "item") == saved
    with pytest.raises(cp.DefinitionConflict):
        create({"id": "missing", "expected_version": 1})


@pytest.mark.parametrize("kind", ["tool", "automation"])
def test_concurrent_expected_writers_have_exactly_one_winner(database, kind):
    getattr(cp, f"create_{kind}")({"id": "item"})
    update = getattr(cp, f"update_{kind}")
    barrier = Barrier(2)

    def save(name):
        barrier.wait()
        try:
            return update("item", {"name": name, "expected_version": 1})
        except cp.DefinitionConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(save, ["First", "Second"]))
    assert sum(result is not None for result in results) == 1
    assert cp.get(kind, "item")["version"] == 2


@pytest.mark.parametrize("kind", ["tool", "automation"])
def test_concurrent_legacy_updates_cannot_reuse_versions(database, kind):
    getattr(cp, f"create_{kind}")({"id": "item"})
    update = getattr(cp, f"update_{kind}")
    barrier = Barrier(4)

    def save(index):
        barrier.wait()
        return update("item", {"name": str(index), "version": 1})["version"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sorted(pool.map(save, range(4))) == [2, 3, 4, 5]


@pytest.mark.parametrize("kind", ["tool", "automation"])
def test_http_conflict_validation_and_legacy_compatibility(database, kind):
    server.app.dependency_overrides[server.require_admin] = lambda: "admin"
    try:
        client = TestClient(server.app)  # No lifespan: no bootstrap/provider activity.
        body = {"id": "item", "name": "Item", "execution": {"type": "echo"}} if kind == "tool" else {"id": "item", "workflow": []}
        body.update(name="Item", description="Local definition revision test")
        url = f"/v2/{'tools' if kind == 'tool' else 'automations'}"
        assert client.post(url, json=body).status_code == 200
        response = client.put(url + "/item", json={**body, "expected_version": 1})
        assert response.status_code == 200 and response.json()["version"] == 2
        before = cp.get(kind, "item")
        events_before = cp.events()
        stale = client.put(url + "/item", json={**body, "expected_version": 1})
        assert stale.status_code == 409
        assert stale.json()["detail"]["code"] == "DEFINITION_CONFLICT"
        assert stale.json()["detail"]["current_version"] == 2
        assert cp.get(kind, "item") == before
        assert cp.events() == events_before
        assert client.put(url + "/item", json=body).json()["version"] == 3
        for invalid in [0, -1, True, 1.5, "3"]:
            assert client.put(url + "/item", json={**body, "expected_version": invalid}).status_code == 422
        assert cp.get(kind, "item")["version"] == 3
    finally:
        server.app.dependency_overrides.pop(server.require_admin, None)

