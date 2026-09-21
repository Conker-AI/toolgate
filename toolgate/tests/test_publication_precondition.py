import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import publications


@pytest.mark.parametrize("kind", ["tool", "automation"])
def test_version_digest_precondition_precedes_approval_and_dispatch(tmp_path, monkeypatch, kind):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "digest.db")
    cp.create_tool({"id": "item", "name": "Tool", "status": "active", "authorization": "owner_confirmation",
                    "execution": {"type": "echo"}})
    cp.create_automation({"id": "item", "name": "Workflow", "status": "active",
                          "authorization": "owner_confirmation", "workflow": []})
    publication = publications.publish(kind, "item", 1)
    agent, raw = cp.issue_agent_key("Caller", ["item", "automation:item"])
    calls = []
    monkeypatch.setattr(server, "_dispatch_tool", lambda *args: calls.append(args) or {"ok": True, "result": {}})
    client = TestClient(server.app)
    url = "/v2/tools/item/invoke" if kind == "tool" else "/v2/automations/item/run"
    headers = {"X-ToolGate-Execution-Key": raw}
    payload = {"action_id": "pinned", "published_version": 1, "expected_publication_digest": "0" * 64}
    mismatch = client.post(url, headers=headers, json=payload)
    assert mismatch.status_code == 409 and mismatch.json()["detail"]["code"] == "PUBLICATION_MISMATCH"
    assert cp.list_objects("request") == [] and journal.get("pinned") is None and calls == []
    without_version = {key: value for key, value in payload.items() if key != "published_version"}
    assert client.post(url, headers=headers, json=without_version).status_code == 422
    for invalid in ["", "wrong", True, 1, "a" * 65]:
        assert client.post(url, headers=headers, json={**payload, "expected_publication_digest": invalid}).status_code == 422
    payload["expected_publication_digest"] = publication["digest"]
    pending = client.post(url, headers=headers, json=payload)
    assert pending.status_code == 200 and pending.json()["code"] == "CONFIRMATION_REQUIRED"
    request_id = pending.json()["request_id"]
    cp.decide_request(request_id, "approved", "owner")
    payload["approval_request_id"] = request_id
    assert client.post(url, headers=headers, json={**payload, "expected_publication_digest": "0" * 64}).status_code == 409
    assert cp.get("request", request_id)["payload"]["binding"]["consumed_at"] is None
    assert client.post(url, headers=headers, json=payload).json()["code"] == "OK"
    assert journal.get("pinned")["actor_id"] == agent["id"]
