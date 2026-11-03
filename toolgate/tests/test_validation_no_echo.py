"""A refused request body is never sent back: a secret in a bad request stays out of the reply."""

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp

ADMIN = "echo-admin-key"
SECRET = "sk-never-echo-0123456789"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(server.vault, "get_control_key", lambda _: ADMIN)
    value = TestClient(server.app)
    yield value
    value.close()


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        # A missing field: pydantic's error input is the whole body, secret included.
        ("POST", "/vault/secrets", {"value": SECRET}),
        # A wrong type: the error input is the value itself.
        ("PUT", "/vault/secrets/mail", {"value": [SECRET]}),
        ("POST", "/v2/agent-keys", {"scopes": "x", "note": SECRET}),
    ],
)
def test_refused_body_is_not_echoed(client, method, path, body):
    response = client.request(method, path, json=body, headers={"X-ToolGate-Key": ADMIN})

    assert response.status_code == 422
    assert SECRET not in response.text
    # Callers still learn which field was wrong and why.
    for error in response.json()["detail"]:
        assert set(error) == {"loc", "msg", "type"}
        assert error["loc"][0] == "body"
