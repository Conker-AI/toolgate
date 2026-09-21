import json

import httpx
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


def interrupted_verification(request, monkeypatch):
    daemon, agent, _, payload = request.getfixturevalue("pending")
    original = daemon.handle

    def handle(message):
        if message.method == "GET" and daemon.replacement and daemon.replacement["State"]["Running"]:
            raise httpx.ReadTimeout("private-value")
        return original(message)

    monkeypatch.setattr(daemon, "handle", handle)
    assert server.run_tool("system.port-control", payload, agent)["code"] == "OUTCOME_UNKNOWN"
    monkeypatch.setattr(daemon, "handle", original)
    return daemon, agent, payload


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
        port_finalization.finalize(payload.action_id, agent["id"], authorize=lambda conn: pytest.fail(),
            transport=httpx.MockTransport(lambda request: httpx.Response(503)))


def test_final_read_can_be_recovered_with_fresh_approval_and_no_effects(request, monkeypatch):
    daemon, agent, payload = interrupted_verification(request, monkeypatch)
    transport = httpx.MockTransport(daemon.handle)
    count = len(daemon.requests)
    receipt = port_finalization.preview(payload.action_id, agent["id"], transport=transport)
    assert receipt["originalRetained"]
    assert journal.get(payload.action_id)["status"] == "outcome_unknown"
    assert port_replacements.steps(payload.action_id)[-1]["status"] == "outcome_unknown"
    approved = []
    done = port_finalization.finalize(payload.action_id, agent["id"], transport=transport,
        authorize=lambda conn: approved.append(conn.in_transaction))
    assert approved == [True] and done["status"] == "completed"
    assert all(message.method == "GET" for message in daemon.requests[count:])
    assert container_control.targets() == [receipt["replacementId"]]
    assert "private-value" not in json.dumps(done["response"])
    assert b"private-value" not in cp.DB_PATH.read_bytes()


@pytest.mark.parametrize("change", ["command", "mount", "network", "ports", "socket", "source"])
def test_reverification_refuses_drift(request, monkeypatch, change):
    daemon, agent, payload = interrupted_verification(request, monkeypatch)
    if change == "command":
        daemon.replacement["Config"]["Cmd"] = ["different"]
    elif change == "mount":
        daemon.replacement["Mounts"] = []
    elif change == "network":
        daemon.bad_network = True
    elif change == "ports":
        daemon.bad_verification = True
    elif change == "socket":
        monkeypatch.setenv("TOOLGATE_DOCKER_SOCKET", "/different.sock")
    else:
        daemon.original["State"]["Running"] = True
    with pytest.raises(port_replacements.ReplacementError):
        port_finalization.finalize(payload.action_id, agent["id"],
            transport=httpx.MockTransport(daemon.handle), authorize=lambda conn: pytest.fail())
    assert journal.get(payload.action_id)["status"] == "outcome_unknown"


def test_reverification_denial_leaves_no_new_observation_or_lineage(request, monkeypatch):
    daemon, agent, payload = interrupted_verification(request, monkeypatch)

    def deny(conn):
        raise PermissionError()

    with pytest.raises(PermissionError):
        port_finalization.finalize(payload.action_id, agent["id"],
            transport=httpx.MockTransport(daemon.handle), authorize=deny)
    assert port_replacements.steps(payload.action_id)[-1]["status"] == "outcome_unknown"
    with cp._conn() as conn:
        assert conn.execute("SELECT * FROM v2_container_lineage").fetchall() == []


def test_http_reverification_rechecks_after_approval_and_replays_without_reads(request, monkeypatch):
    daemon, agent, payload = interrupted_verification(request, monkeypatch)
    preview, finalize = port_finalization.preview, port_finalization.finalize
    monkeypatch.setattr(port_finalization, "preview", lambda *args: preview(
        *args, transport=httpx.MockTransport(daemon.handle)))
    monkeypatch.setattr(port_finalization, "finalize", lambda *args, **kwargs: finalize(
        *args, **kwargs, transport=httpx.MockTransport(daemon.handle)))
    body = server.PortFinalizationRequest(action_id=payload.action_id)
    count = len(daemon.requests)
    pending = server.finalize_port_recovery(body, agent)
    rid = json.loads(pending.body)["request_id"]
    cp.decide_request(rid, "approved", "owner")
    body.approval_request_id = rid
    original_command = daemon.replacement["Config"]["Cmd"]
    daemon.replacement["Config"]["Cmd"] = ["changed-after-review"]
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as error:
        server.finalize_port_recovery(body, agent)
    assert error.value.status_code == 409
    assert not cp.get("request", rid)["payload"]["binding"].get("consumed_at")
    daemon.replacement["Config"]["Cmd"] = original_command
    done = server.finalize_port_recovery(body, agent)
    assert json.loads(done.body)["code"] == "OK"
    assert all(message.method == "GET" for message in daemon.requests[count:])
    count = len(daemon.requests)
    assert server.finalize_port_recovery(body, agent).body == done.body
    assert len(daemon.requests) == count


def test_reverification_after_process_recovery_normalizes_unfinished_read(request, monkeypatch):
    monkeypatch.setattr(port_replacements, "unknown", lambda identity, ordinal: journal.unknown(identity))
    daemon, agent, payload = interrupted_verification(request, monkeypatch)
    with cp._conn() as conn:
        assert conn.execute("SELECT status FROM v2_port_steps WHERE action_id=? AND name='verify'",
                            (payload.action_id,)).fetchone()[0] == "dispatching"
    assert port_finalization.finalize(payload.action_id, agent["id"],
        transport=httpx.MockTransport(daemon.handle), authorize=lambda conn: None)["status"] == "completed"


def test_legacy_missing_basis_and_foreign_actor_cannot_reverify(request, monkeypatch):
    monkeypatch.setattr(port_replacements, "save_verification_basis", lambda *args: None)
    daemon, agent, payload = interrupted_verification(request, monkeypatch)
    count = len(daemon.requests)
    for actor in ("other", agent["id"]):
        with pytest.raises(port_replacements.ReplacementError):
            port_finalization.preview(payload.action_id, actor, transport=httpx.MockTransport(daemon.handle))
    assert len(daemon.requests) == count
