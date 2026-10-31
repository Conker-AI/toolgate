"""Any agent key can write an informational request to the owner, so its fields are bounded: one
key cannot fill the owner's queue or the audit log, nor label a note with a severity of its own."""

import hashlib

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.api.models import REQUEST_PAYLOAD_BYTES
from toolgate.core import control_plane as cp

ADMIN = "bounds-admin-key-" + "a" * 32
OWNER = "bounds-owner-key-" + "o" * 32


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(server.vault, "get_control_key", lambda _: ADMIN)
    monkeypatch.setenv("TOOLGATE_OWNER_KEY_SHA256", hashlib.sha256(OWNER.encode()).hexdigest())
    _, key = cp.issue_agent_key("Pi", [])
    client = TestClient(server.app)
    yield client, key
    client.close()


def send(client, key, **fields):
    body = {"kind": "info", "title": "Note", "details": "Just so you know", **fields}
    return client.post("/v2/requests", json=body, headers={"X-ToolGate-Execution-Key": key})


def test_a_note_at_each_bound_is_kept(api):
    client, key = api
    response = send(
        client,
        key,
        title="t" * 500,
        details="d" * 8000,
        severity="warning",
        payload={"text": "p" * (REQUEST_PAYLOAD_BYTES - 20)},
    )
    assert response.status_code == 200, response.text
    assert cp.get("request", response.json()["id"])["severity"] == "warning"


@pytest.mark.parametrize(
    "fields",
    [
        {"title": "t" * 501},
        {"details": "d" * 8001},
        {"kind": "k" * 65},
        {"severity": "urgent"},
        {"severity": "x" * 10000},
        {"payload": {"text": "p" * REQUEST_PAYLOAD_BYTES}},
    ],
    ids=["title", "details", "kind", "unknown-severity", "long-severity", "payload"],
)
def test_a_note_past_a_bound_is_refused_and_nothing_is_recorded(api, fields):
    client, key = api
    response = send(client, key, **fields)
    assert response.status_code == 422, response.text
    assert not cp.list_objects("request")
    assert not cp.events(event_type="request_created")
