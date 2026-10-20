"""Creating a tool or workflow needs no version; replacing one through POST needs the version seen."""

import pytest
from fastapi.testclient import TestClient

from toolgate.api import deps, server
from toolgate.core import control_plane as cp

TOOL = {
    "id": "echoer",
    "name": "Echoer",
    "description": "Echo test",
    "status": "active",
    "execution": {"type": "echo"},
}
WORKFLOW = {
    "id": "flow",
    "name": "Flow",
    "description": "Replace test",
    "status": "draft",
    "workflow": [{"type": "return", "value": "done"}],
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "replace.db")
    server.app.dependency_overrides[deps.require_admin] = lambda: "admin"
    try:
        yield TestClient(server.app)
    finally:
        server.app.dependency_overrides.pop(deps.require_admin, None)


@pytest.mark.parametrize("kind,path,body", [("tool", "/v2/tools", TOOL), ("automation", "/v2/automations", WORKFLOW)])
def test_post_replaces_only_with_the_version_it_saw(client, kind, path, body):
    assert client.post(path, json=body).status_code == 200
    blind = client.post(path, json={**body, "name": "Overwritten"})
    assert blind.status_code == 409
    assert blind.json()["detail"]["code"] == "DEFINITION_CONFLICT"
    assert cp.get(kind, body["id"])["name"] == body["name"] and cp.get(kind, body["id"])["version"] == 1

    stale = client.post(path, json={**body, "name": "Overwritten", "expected_version": 7})
    assert stale.status_code == 409
    replaced = client.post(path, json={**body, "name": "Renamed", "expected_version": 1})
    assert replaced.status_code == 200, replaced.text
    assert cp.get(kind, body["id"])["name"] == "Renamed" and cp.get(kind, body["id"])["version"] == 2


def test_startup_seeding_still_upserts_without_a_version(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "seed.db")
    cp.create_tool(TOOL)
    cp.create_tool({**TOOL, "name": "Seeded again"})
    assert cp.get("tool", "echoer")["name"] == "Seeded again"
