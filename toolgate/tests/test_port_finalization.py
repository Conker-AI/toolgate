import json

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import container_lineage, owner_channel, port_finalization, port_replacements
from toolgate.executors import container_control
from toolgate.tests.test_port_control_boundary import (
    setup as boundary_setup,  # noqa: F401
)
from toolgate.tests.test_port_recovery import pending  # noqa: F401


def lost_receipt(request, monkeypatch):
    daemon, agent, _, payload = request.getfixturevalue("pending")

    def crash(*args, **kwargs):
        journal.unknown(payload.action_id)
        raise RuntimeError("synthetic lost receipt")

    monkeypatch.setattr(journal, "finish", crash)
    with pytest.raises(RuntimeError, match="synthetic lost receipt"):
        server.run_tool("system.port-control", payload, agent)
    return daemon, agent, payload


def test_verified_receipt_recovery_has_no_external_effects(request, monkeypatch):
    daemon, agent, payload = lost_receipt(request, monkeypatch)
    count = len(daemon.requests)
    assert container_control.targets() == []
    approved = []
    result = port_finalization.finalize(payload.action_id, agent["id"],
                                        authorize=lambda conn: approved.append(conn.in_transaction))
    assert approved == [True]
    assert result["status"] == "completed"
    assert container_control.targets() == [result["response"]["result"]["result"]["replacementId"]]
    assert len(daemon.requests) == count
    assert "private-value" not in json.dumps(result["response"])
    with pytest.raises(port_replacements.ReplacementError):
        port_finalization.finalize(payload.action_id, agent["id"], authorize=lambda conn: pytest.fail())


def test_denied_authorization_rolls_back_approval_and_receipt(request, monkeypatch):
    _, agent, payload = lost_receipt(request, monkeypatch)
    with cp._conn() as conn:
        conn.execute("CREATE TABLE synthetic_approval(value TEXT)")

    def deny(conn):
        conn.execute("INSERT INTO synthetic_approval VALUES ('used')")
        raise PermissionError()

    with pytest.raises(PermissionError):
        port_finalization.finalize(payload.action_id, agent["id"], authorize=deny)
    assert journal.get(payload.action_id)["status"] == "outcome_unknown"
    with cp._conn() as conn:
        assert conn.execute("SELECT * FROM synthetic_approval").fetchall() == []


def test_other_actor_and_missing_lineage_cannot_finalize(request, monkeypatch):
    _, agent, payload = lost_receipt(request, monkeypatch)
    with pytest.raises(port_replacements.ReplacementError):
        port_finalization.finalize(payload.action_id, "other", authorize=lambda conn: pytest.fail())
    monkeypatch.setenv("TOOLGATE_DOCKER_SOCKET", "/other/docker.sock")
    with pytest.raises(port_replacements.ReplacementError):
        port_finalization.finalize(payload.action_id, agent["id"], authorize=lambda conn: pytest.fail())


def test_partial_execution_cannot_finalize(request):
    daemon, agent, _, payload = request.getfixturevalue("pending")
    daemon.fail = "/start"
    assert server.run_tool("system.port-control", payload, agent)["code"] == "OUTCOME_UNKNOWN"
    with pytest.raises(port_replacements.ReplacementError):
        port_finalization.finalize(payload.action_id, agent["id"], authorize=lambda conn: pytest.fail())


def test_http_recovery_requires_own_exact_approval_and_replays_receipt(request, monkeypatch):
    daemon, _agent, payload = lost_receipt(request, monkeypatch)
    _, _, key, _ = request.getfixturevalue("pending")
    client = TestClient(server.app)
    url = "/v2/agent/system/port-finalizations"
    body = {"action_id": payload.action_id}
    headers = {"X-ToolGate-Execution-Key": key}
    count = len(daemon.requests)
    assert client.post(url, json=body).status_code == 401
    _other, other_key = cp.issue_agent_key("Other", ["tool:system.port-control"])
    assert client.post(url, json=body, headers={"X-ToolGate-Execution-Key": other_key}).status_code == 409
    response = client.post(url, json=body, headers=headers)
    assert response.status_code == 200 and response.json()["code"] == "CONFIRMATION_REQUIRED"
    rid = response.json()["request_id"]
    assert "private-value" not in json.dumps(cp.get("request", rid))
    with cp._conn() as conn:
        assert owner_channel.project(conn, cp.get("request", rid))["reviewable"]
    # Original execution approval must not authorize recovery.
    assert client.post(url, json={**body, "approval_request_id": payload.approval_request_id},
                       headers=headers).status_code == 409
    approved_body = {**body, "approval_request_id": rid}
    assert client.post(url, json=approved_body, headers=headers).status_code == 409
    cp.decide_request(rid, "approved", "owner")
    done = client.post(url, json=approved_body, headers=headers)
    assert done.status_code == 200 and done.json()["code"] == "OK", done.text
    assert done.headers["cache-control"] == "no-store"
    assert cp.get("request", rid)["payload"]["binding"]["consumed_at"]
    assert client.post(url, json=approved_body, headers=headers).json() == done.json()
    assert len(daemon.requests) == count


def test_http_partial_recovery_does_not_create_approval(request):
    daemon, agent, _, payload = request.getfixturevalue("pending")
    daemon.fail = "/start"
    server.run_tool("system.port-control", payload, agent)
    before = len(cp.list_objects("request"))
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as error:
        server.finalize_port_recovery(server.PortFinalizationRequest(action_id=payload.action_id), agent)
    assert error.value.status_code == 409
    assert len(cp.list_objects("request")) == before


def test_crash_after_atomic_verification_can_recover_without_docker_replay(request, monkeypatch):
    daemon, agent, _, payload = request.getfixturevalue("pending")
    actual = container_lineage.record

    def crash_after_commit(*args, **kwargs):
        actual(*args, **kwargs)
        raise RuntimeError("lost verification acknowledgement")

    monkeypatch.setattr(container_lineage, "record", crash_after_commit)
    assert server.run_tool("system.port-control", payload, agent)["code"] == "OUTCOME_UNKNOWN"
    assert port_replacements.steps(payload.action_id)[-1]["status"] == "observed"
    count = len(daemon.requests)
    approved = []
    recovered = port_finalization.finalize(payload.action_id, agent["id"],
        authorize=lambda conn: approved.append(conn.in_transaction))
    assert approved == [True] and recovered["status"] == "completed"
    assert len(daemon.requests) == count


def test_failed_lineage_write_cannot_leave_successful_verification(request):
    daemon, agent, _, payload = request.getfixturevalue("pending")
    with cp._conn() as conn:
        conn.executescript(container_lineage.SCHEMA)
        conn.executescript("""CREATE TRIGGER synthetic_disk_failure BEFORE INSERT ON v2_container_lineage
            BEGIN SELECT RAISE(ABORT, 'synthetic disk failure'); END;""")
    assert server.run_tool("system.port-control", payload, agent)["code"] == "OUTCOME_UNKNOWN"
    assert port_replacements.steps(payload.action_id)[-1]["status"] == "outcome_unknown"
    with cp._conn() as conn:
        assert conn.execute("SELECT * FROM v2_container_lineage").fetchall() == []
    with pytest.raises(port_replacements.ReplacementError):
        port_finalization.finalize(payload.action_id, agent["id"], authorize=lambda conn: pytest.fail())
