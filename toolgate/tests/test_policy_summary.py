import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setattr(control_plane, "DB_PATH", tmp_path / "gate.db")
    agent, key = control_plane.issue_agent_key("Pi", ["summary.visible"])
    client = TestClient(server.app)
    yield client, agent, key
    client.close()


def test_agent_policy_summary_is_scoped_stable_and_secret_free(gate):
    client, _agent, key = gate
    control_plane.create_tool(
        {
            "id": "summary.visible",
            "name": "Visible",
            "description": "Policy evidence",
            "status": "active",
            "authorization": "owner_confirmation",
            "execution": {
                "type": "http",
                "url": "https://secret.invalid",
                "headers": {"Authorization": "secret"},
            },
            "policy": {
                "usage_limits": {"max_per_hour": 7, "max_per_minute": 2},
                "destinations": ["secret.invalid"],
            },
        }
    )
    control_plane.create_tool(
        {
            "id": "summary.hidden",
            "name": "Hidden",
            "status": "active",
            "execution": {"type": "echo"},
        }
    )

    response = client.get("/v2/agent/policy-summary", headers={"X-ToolGate-Execution-Key": key})
    assert response.status_code == 200
    body = response.json()
    assert [item["id"] for item in body["tools"]] == ["summary.visible"]
    assert body["tools"][0]["usageLimits"]["max_per_hour"] == 7
    assert body["tools"][0]["usageLimits"]["max_per_minute"] == 2
    assert body["tools"][0]["usageLimits"]["max_runtime_seconds"] > 0
    assert len(body["tools"][0]["definitionDigest"]) == 64
    assert "secret" not in json.dumps(body).lower()
    evidence = {key: body[key] for key in ("lockdown", "scopePatterns", "tools")}
    expected = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    assert body["digest"] == expected

    visible = control_plane.get("tool", "summary.visible")
    control_plane.update_tool(
        "summary.visible",
        {
            **visible,
            "execution": {
                **visible["execution"],
                "url": "https://rotated.invalid",
                "headers": {"Authorization": "rotated-private-value"},
            },
            "policy": {
                **visible["policy"],
                "destinations": ["rotated.invalid"],
            },
        },
    )
    changed = client.get(
        "/v2/agent/policy-summary", headers={"X-ToolGate-Execution-Key": key}
    ).json()
    assert changed["digest"] != body["digest"]
    assert changed["tools"][0]["definitionDigest"] != body["tools"][0]["definitionDigest"]
    assert changed["tools"][0]["usageLimits"] == body["tools"][0]["usageLimits"]
    assert "rotated" not in json.dumps(changed).lower()
