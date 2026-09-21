import json

import pytest

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import port_finalization, port_replacements
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
