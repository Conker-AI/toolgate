from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from fastapi import HTTPException

from toolgate.api import server
from toolgate.core import container_admission as admission
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import port_reviews
from toolgate.executors import port_control
from toolgate.tests.test_port_control_boundary import (
    setup as boundary_setup,  # noqa: F401
)
from toolgate.tests.test_port_spec import CID, MAPPING


@pytest.fixture
def ready(request):
    daemon, _, _ = request.getfixturevalue("boundary_setup")
    agent, _ = cp.issue_agent_key("Both operations", ["tool:system.container-control", "tool:system.port-control"])
    response = server.create_port_review(server.PortReviewRequest(
        container_id=CID, operation="create", mapping=MAPPING), agent)
    import json
    rid = json.loads(response.body)["reviewId"]
    requests = {
        "system.port-control": server.V2Invoke(action_id="change-1", args={"container_id": CID, "review_id": rid}),
        "system.container-control": server.V2Invoke(action_id="lifecycle-1", args={"container_id": CID, "action": "restart"}),
    }
    for tool, payload in requests.items():
        pending = server.run_tool(tool, payload, agent)
        cp.decide_request(pending["request_id"], "approved", "owner")
        payload.approval_request_id = pending["request_id"]
    return daemon, agent, rid, requests


@pytest.mark.parametrize("first", ["system.port-control", "system.container-control"])
def test_mixed_approved_actions_cannot_dispatch_concurrently(ready, monkeypatch, first):
    daemon, agent, rid, requests = ready
    entered, release = Event(), Event()
    actual_port = port_control.execute
    actual_dispatch = server._dispatch_tool

    def port(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return actual_port(*args, **kwargs)

    def dispatch(tool, args):
        if tool["id"] != "system.container-control":
            return actual_dispatch(tool, args)
        entered.set()
        assert release.wait(5)
        return {"ok": True, "result": {"containerId": CID, "outcome": "observed"}}

    monkeypatch.setattr(port_control, "execute", port)
    monkeypatch.setattr(server, "_dispatch_tool", dispatch)
    second = next(tool for tool in requests if tool != first)
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(server.run_tool, first, requests[first], agent)
        assert entered.wait(5)
        count = len(daemon.requests)
        try:
            with pytest.raises(HTTPException) as error:
                server.run_tool(second, requests[second], agent)
            assert error.value.detail["code"] == "ACTION_CONFLICT"
            assert len(daemon.requests) == count
            assert journal.get(requests[second].action_id) is None
            # Failed competing admission rolls the owner decision consumption back.
            assert cp.get("request", requests[second].approval_request_id)["status"] == "approved"
            if second == "system.port-control":
                assert not port_reviews.get(rid, agent["id"])["consumed"]
        finally:
            release.set()
        assert future.result()["code"] == "OK"


def test_unknown_claim_never_expires_into_dispatch_permission(ready):
    _, _, _, _requests = ready
    def claim(identity):
        return journal.begin(identity, "tool", "custom-container-alias", {"container_id": CID}, "actor", 1,
                             reserve=lambda conn: admission.reserve(conn, identity, CID))
    claim("first")
    journal.recover_interrupted()
    with pytest.raises(admission.ContainerBusy):
        claim("second")
    assert journal.get("second") is None


def test_completed_claim_allows_next_action(ready):
    for identity in ("first", "second"):
        journal.begin(identity, "tool", "custom-container-alias", {"container_id": CID}, "actor", 1,
                      reserve=lambda conn, identity=identity: admission.reserve(conn, identity, CID))
        journal.finish(identity, {"code": "OK"})
