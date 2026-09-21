import json

import httpx
import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.executors import port_recovery
from toolgate.tests.test_port_control import Stream
from toolgate.tests.test_port_control_boundary import (
    setup as boundary_setup,  # noqa: F401
)
from toolgate.tests.test_port_spec import CID, MAPPING


@pytest.fixture
def pending(request):
    daemon, agent, key = request.getfixturevalue("boundary_setup")
    response = server.create_port_review(server.PortReviewRequest(
        container_id=CID, operation="create", mapping=MAPPING), agent)
    rid = json.loads(response.body)["reviewId"]
    payload = server.V2Invoke(action_id="change-1", args={"container_id": CID, "review_id": rid})
    approval = server.run_tool("system.port-control", payload, agent)
    cp.decide_request(approval["request_id"], "approved", "owner")
    payload.approval_request_id = approval["request_id"]
    return daemon, agent, key, payload


def test_uncertain_start_inspection_is_read_only_and_does_not_release_claim(pending):
    daemon, agent, _, payload = pending
    daemon.fail = "/start"
    assert server.run_tool("system.port-control", payload, agent)["code"] == "OUTCOME_UNKNOWN"
    previous = journal.get("change-1")
    count = len(daemon.requests)
    value = port_recovery.inspect("change-1", agent["id"], transport=httpx.MockTransport(daemon.handle))
    assert value["source"]["presence"] == "present" and value["source"]["running"] is False
    assert value["replacement"]["presence"] == "present"
    assert value["replacement"]["running"] is False
    assert value["replacementBindingsMatch"] is True
    assert not value["canResume"] and not value["canReleaseReservation"]
    assert "private-value" not in json.dumps(value)
    assert all(request.method == "GET" for request in daemon.requests[count:])
    assert journal.get("change-1") == previous


def test_unconfirmed_create_identity_is_not_guessed_from_name(pending):
    daemon, agent, _, payload = pending
    daemon.fail = "/create"
    assert server.run_tool("system.port-control", payload, agent)["code"] == "OUTCOME_UNKNOWN"
    count = len(daemon.requests)
    value = port_recovery.inspect("change-1", agent["id"], transport=httpx.MockTransport(daemon.handle))
    assert value["replacement"] == {"containerId": None, "presence": "identity_unconfirmed"}
    assert value["inspection"] == "partial"
    assert len(daemon.requests) == count + 1


def test_cross_actor_cannot_inspect_private_recovery(pending):
    daemon, agent, _, payload = pending
    daemon.fail = "/start"
    server.run_tool("system.port-control", payload, agent)
    count = len(daemon.requests)
    with pytest.raises(port_recovery.RecoveryError):
        port_recovery.inspect("change-1", "other", transport=httpx.MockTransport(daemon.handle))
    assert len(daemon.requests) == count


def test_missing_container_and_failed_read_remain_distinct(pending):
    daemon, agent, _, payload = pending
    daemon.fail = "/start"
    server.run_tool("system.port-control", payload, agent)

    def handle(request):
        return httpx.Response(404 if CID in request.url.path else 500, stream=Stream(b""))
    value = port_recovery.inspect("change-1", agent["id"], transport=httpx.MockTransport(handle))
    assert value["source"]["presence"] == "missing"
    assert value["replacement"]["presence"] == "unavailable"
    assert value["inspection"] == "partial"
    assert journal.get("change-1")["status"] == "outcome_unknown"


def test_scoped_no_store_recovery_endpoint(pending, monkeypatch):
    daemon, agent, key, payload = pending
    daemon.fail = "/start"
    server.run_tool("system.port-control", payload, agent)
    actual = port_recovery.inspect
    monkeypatch.setattr(port_recovery, "inspect", lambda *args: actual(
        *args, transport=httpx.MockTransport(daemon.handle)))
    client = TestClient(server.app)
    path = "/v2/agent/system/port-recovery/change-1"
    assert client.get(path).status_code == 401
    response = client.get(path, headers={"X-ToolGate-Execution-Key": key})
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert "private-value" not in response.text
