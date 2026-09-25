import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import spending
from toolgate.tests.test_spending import invoke, setup_budget
from toolgate.tests.test_spending import paid as paid


def held(paid, monkeypatch):
    job = setup_budget()
    def fail(*args, **kwargs):
        raise TimeoutError("provider reply lost")
    monkeypatch.setattr(server, "_dispatch_tool", fail)
    assert invoke(paid, job)["code"] == "OUTCOME_UNKNOWN"
    return job


def test_owner_release_frees_local_hold_without_allowing_redispatch(paid, monkeypatch):
    job = held(paid, monkeypatch)
    monkeypatch.setattr(server.vault, "get_control_key", lambda _: "owner")
    _, key = cp.issue_agent_key("worker", ["tool:*"])
    client = TestClient(server.app)
    body = {"confirmed_not_executed": True, "evidence": "Provider checked action root: no execution and no charge"}
    assert client.post("/v2/spending/releases/root", json=body,
                       headers={"X-ToolGate-Execution-Key": key}).status_code == 401
    first = client.post("/v2/spending/releases/root", json=body, headers={"X-ToolGate-Key": "owner"})
    assert first.status_code == 200
    assert first.json()["status"] == "local_hold_released"
    assert spending.status()["held_microusd"] == 0
    assert spending.status()["accounted_and_reserved_microusd"] == 0
    assert client.post("/v2/spending/releases/root", json=body, headers={"X-ToolGate-Key": "owner"}).json() == first.json()
    assert invoke(paid, job)["code"] == "OUTCOME_UNKNOWN"
    client.close()


def test_release_requires_owner_evidence_and_inactive_dispatch(paid):
    job = setup_budget()
    price = spending.quote(spending.MODEL, 128)
    journal.begin("root", "tool", "paid", {}, "agent", 1, job_id=job,
                  reserve=lambda db: spending.reserve(db, "root", job, "agent", None, price))
    with pytest.raises(spending.BudgetDenied):
        spending.release_hold("root", "Provider checked: no execution", True)
    journal.unknown("root")
    with pytest.raises(spending.BudgetDenied):
        spending.release_hold("root", "Provider checked: no execution", False)
    with pytest.raises(spending.BudgetDenied):
        spending.release_hold("root", "", True)


def test_late_reply_disputes_release_and_restores_budget_hold(paid, monkeypatch):
    held(paid, monkeypatch)
    original = spending.status()["held_microusd"]
    spending.release_hold("root", "Provider said no execution", True)
    journal.finish("root", {"code": "OK"}, reconcile=lambda db: spending.reconcile(db, "root", None))
    status = spending.status()
    assert status["policy"]["enabled"] == 0
    assert status["held_microusd"] == original
