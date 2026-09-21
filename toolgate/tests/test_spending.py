"""Exercise real SQLite reservations and the outbound HTTP boundary without paid calls."""
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import Mock

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane, spending
from toolgate.core import execution_journal as journal
from toolgate.executors import research


@pytest.fixture
def paid(tmp_path, monkeypatch):
    monkeypatch.setattr(control_plane, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(server.vault, "get_key", lambda _: "test-secret")
    return {"id": "paid", "name": "Paid", "version": 1, "authorization": "auto",
            "status": "active", "inputs": [], "outputs": [], "execution": {
                "type": "gemini_generate", "model": spending.MODEL,
                "prompt_template": "hello", "secret_ref": "GOOGLE_API_KEY", "max_tokens": 128}}


def setup_budget(root="root", cap=10_000_000, cumulative=20_000_000, actor="agent"):
    spending.configure(True, cumulative, min(cap, cumulative))
    spending.set_price(spending.MODEL, 1_000_000, 2_000_000,
                       time.time() + 3600, "https://provider.example/pricing")
    return spending.create_job(actor, root, cap)["job_id"]


def invoke(paid, job=None, action="root", actor="agent", **kwargs):
    return server.invoke_tool(paid, {}, "Actor", actor_id=actor, action_id=action,
                              job_id=job, **kwargs)


def provider(monkeypatch, usage=None, before=None):
    calls = []

    def post(url, **kwargs):
        if before:
            before()
        calls.append(kwargs["json"])
        body = kwargs["json"]
        assert body["generationConfig"]["maxOutputTokens"] == 128
        assert body["generationConfig"]["thinkingConfig"] == {"thinkingBudget": 0}
        assert set(body) == {"contents", "generationConfig"}
        return Mock(raise_for_status=lambda: None, json=lambda: {
            "candidates": [{"content": {"parts": [{"text": "reply"}]}}],
            **({"usageMetadata": usage} if usage is not None else {})})

    monkeypatch.setattr(server.httpx, "post", post)
    return calls


def test_default_disabled_and_unknown_or_expired_prices_cannot_reach_network(paid, monkeypatch):
    calls = provider(monkeypatch)
    for stage in range(3):
        if stage == 1:
            spending.configure(True, 10_000_000, 10_000_000)
        if stage == 2:
            spending.set_price(spending.MODEL, 1, 2, time.time() + 1, "https://p.example")
            monkeypatch.setattr(spending.time, "time", lambda: 10**12)
        with pytest.raises(HTTPException) as error:
            invoke(paid)
        assert error.value.detail["code"] == "BUDGET_DENIED"
    assert calls == []
    assert journal.get("root") is None


def test_reservation_precedes_network_reconciles_and_replay_does_not_charge(paid, monkeypatch):
    job = setup_budget()
    ceiling = spending.amount(spending.quote(spending.MODEL, 128), spending.MAX_INPUT_TOKENS, 128)

    def before():
        with sqlite3.connect(control_plane.DB_PATH) as db:
            assert db.execute("SELECT status FROM v2_actions").fetchone() == ("dispatching",)
            assert db.execute("SELECT reserved,accounted FROM v2_spend_reservations").fetchone() == (ceiling, None)

    calls = provider(monkeypatch, {"promptTokenCount": 42, "candidatesTokenCount": 8,
                                   "totalTokenCount": 50}, before)
    first = invoke(paid, job)
    assert first["code"] == "OK"
    assert invoke(paid, job) == first
    assert len(calls) == 1
    assert spending.status()["accounted_and_reserved_microusd"] == 58
    assert spending.status()["held_microusd"] == 0


@pytest.mark.parametrize("mode", ["missing_usage", "timeout", "crash", "bad_usage"])
def test_uncertain_billing_keeps_reservation_across_restart(paid, monkeypatch, mode):
    job = setup_budget(cap=1_100_000, cumulative=1_100_000)
    if mode in {"timeout", "crash"}:
        def post(*args, **kwargs):
            raise (SystemExit("power loss") if mode == "crash" else httpx.ReadTimeout("lost reply"))
        monkeypatch.setattr(server.httpx, "post", post)
    else:
        provider(monkeypatch, {"promptTokenCount": 1, "totalTokenCount": 1} if mode == "bad_usage" else None)
    if mode == "crash":
        with pytest.raises(SystemExit):
            invoke(paid, job)
    else:
        first = invoke(paid, job)
        assert first["code"] == ("OUTCOME_UNKNOWN" if mode == "timeout" else "OK")
    journal.recover_interrupted()
    expected = spending.amount(spending.quote(spending.MODEL, 128), spending.MAX_INPUT_TOKENS, 128)
    assert spending.status()["held_microusd"] == expected
    second = spending.create_job("agent", "second", 1_100_000)["job_id"]
    monkeypatch.setattr(server.httpx, "post", lambda *a, **kw: pytest.fail("exceeded cumulative ceiling"))
    with pytest.raises(HTTPException) as error:
        invoke(paid, second, "second")
    assert error.value.detail["code"] == "BUDGET_DENIED"
    assert journal.get("second") is None
    invoke(paid, job)


def test_budget_denial_rolls_back_approval_and_dispatch_together(paid, monkeypatch):
    job = setup_budget(cap=1)
    paid["authorization"] = "owner_confirmation"
    request = control_plane.create_verification_request("Run", "exact", "Actor", "tool", "paid", {}, 1,
                                                        actor_id="agent")
    control_plane.decide_request(request["id"], "approved", "owner")
    calls = provider(monkeypatch)
    with pytest.raises(HTTPException) as error:
        invoke(paid, job, approval_request_id=request["id"])
    assert error.value.detail["code"] == "BUDGET_DENIED"
    assert control_plane.get("request", request["id"])["payload"]["binding"]["consumed_at"] is None
    assert journal.get("root") is None
    assert calls == []


@pytest.mark.parametrize("actor,action", [("impostor", "root"), ("agent", "another")])
def test_job_cannot_be_reused_by_another_agent_or_root(paid, monkeypatch, actor, action):
    job = setup_budget()
    calls = provider(monkeypatch)
    with pytest.raises(HTTPException) as error:
        invoke(paid, job, action, actor)
    assert error.value.detail["code"] == "BUDGET_DENIED"
    assert calls == []


def test_workflow_children_share_job_ceiling_and_cannot_resume_partial_run(paid, monkeypatch):
    agent, _ = control_plane.issue_agent_key("Actor", ["automation:flow"])
    job = setup_budget(cap=1_100_000, actor=agent["id"])
    paid["policy"] = {"usage_limits": {"cooldown_seconds": 0, "max_per_minute": 60, "max_per_hour": 600}}
    control_plane.create_tool(paid)
    automation = {"id": "flow", "name": "Flow", "version": 1, "status": "active",
                  "authorization": "auto", "inputs": [], "workflow": [
                      {"type": "tool_call", "tool_id": "paid"},
                      {"type": "loop", "items": [1, 2], "max_iterations": 2, "steps": [{"type": "tool_call", "tool_id": "paid"}]}]}
    control_plane.create_automation(automation)
    calls = provider(monkeypatch)
    payload = server.V2Invoke(action_id="root", job_id=job)
    result = server.run_automation("flow", payload, agent)
    assert result["code"] == "OUTCOME_UNKNOWN"
    assert server.run_automation("flow", payload, agent) == result
    assert len(calls) == 1
    records = journal.list_actions()
    assert len(records) == 2
    assert {r["job_id"] for r in records} == {job}
    child = next(r for r in records if r["subject_type"] == "tool")
    assert child["parent_action_id"] == "root"


def test_concurrent_jobs_cannot_overbook_cumulative_cap(paid):
    first = setup_budget(cap=1_100_000, cumulative=1_100_000)
    second = spending.create_job("agent", "second", 1_100_000)["job_id"]
    price = spending.quote(spending.MODEL, 128)
    barrier = Barrier(2)

    def attempt(action, job):
        barrier.wait(timeout=5)
        try:
            journal.begin(action, "tool", "paid", {}, "agent", 1, job_id=job,
                          reserve=lambda db: spending.reserve(db, action, job, "agent", None, price))
            return "reserved"
        except spending.BudgetDenied:
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(attempt, "root", first), pool.submit(attempt, "second", second)]
        assert sorted(f.result() for f in futures) == ["denied", "reserved"]
    assert len(journal.list_actions()) == 1


def test_owner_only_can_set_caps_prices_and_mint_jobs(paid, monkeypatch):
    monkeypatch.setattr(server.vault, "get_control_key", lambda _: "owner-secret")
    _, key = control_plane.issue_agent_key("agent", ["tool:*"])
    with TestClient(server.app, raise_server_exceptions=True) as client:
        for method, path, body in [
            ("PUT", "/v2/spending/policy", {"enabled": True, "cumulative_cap": 10, "max_job_cap": 10}),
            ("PUT", "/v2/spending/prices/" + spending.MODEL,
             {"input_per_million": 1, "output_per_million": 2, "valid_until": time.time()+60, "source": "https://p.example"}),
            ("POST", "/v2/spending/jobs", {"actor_id": "agent", "root_action_id": "root", "cap": 10}),
        ]:
            assert client.request(method, path, json=body, headers={"X-ToolGate-Execution-Key": key}).status_code == 401
            assert client.request(method, path, json=body, headers={"X-ToolGate-Key": "owner-secret"}).status_code == 200


@pytest.mark.parametrize("kind", ["http_json", "memorygate", "tavily", "unsupported_model"])
def test_unaccounted_paid_routes_never_reach_network(paid, monkeypatch, kind):
    setup_budget()
    calls = provider(monkeypatch)
    if kind == "tavily":
        with pytest.raises(research.ResearchError, match="disabled"):
            research._tavily("query", "general", 1, 1, 1)
    else:
        if kind == "unsupported_model":
            paid["execution"]["model"] = "gemini-3.5-flash-lite"
        else:
            paid["execution"] = {"type": kind, "operation": "ask"}
        with pytest.raises(HTTPException) as error:
            invoke(paid)
        assert error.value.detail["code"] == "BUDGET_DENIED"
    assert calls == []


def test_provider_bound_violation_disables_further_paid_dispatch(paid, monkeypatch):
    job = setup_budget()
    provider(monkeypatch, {"promptTokenCount": 42, "candidatesTokenCount": 129, "totalTokenCount": 171})
    invoke(paid, job)
    assert spending.status()["policy"]["enabled"] == 0
    assert spending.status()["accounted_and_reserved_microusd"] >= spending.MAX_INPUT_TOKENS


@pytest.mark.parametrize("mode", ["disabled", "missing", "expired"])
def test_quote_requires_enabled_policy_and_current_known_price(paid, mode):
    setup_budget()
    with control_plane._conn() as db:
        if mode == "disabled":
            db.execute("UPDATE v2_spend_policy SET enabled=0")
        elif mode == "missing":
            db.execute("DELETE FROM v2_spend_prices")
        else:
            db.execute("UPDATE v2_spend_prices SET valid_until=0")
    with pytest.raises(spending.BudgetDenied):
        spending.quote(spending.MODEL, 128)


def test_reservations_and_job_identity_cannot_be_erased(paid, monkeypatch):
    job = setup_budget()
    provider(monkeypatch)
    invoke(paid, job)
    for sql in ["DELETE FROM v2_spend_reservations", "UPDATE v2_spend_reservations SET reserved=0",
                "INSERT OR REPLACE INTO v2_spend_reservations SELECT * FROM v2_spend_reservations",
                "DELETE FROM v2_spend_jobs", "UPDATE v2_spend_jobs SET cap=999999999",
                "INSERT OR REPLACE INTO v2_spend_jobs SELECT * FROM v2_spend_jobs"]:
        with control_plane._conn() as db:
            with pytest.raises(sqlite3.IntegrityError):
                db.execute(sql)


def test_budget_policy_changes_do_not_reset_cumulative_usage(paid, monkeypatch):
    job = setup_budget()
    provider(monkeypatch, {"promptTokenCount": 42, "candidatesTokenCount": 8, "totalTokenCount": 50})
    invoke(paid, job)
    spending.configure(False, 100, 100)
    spending.configure(True, 100, 100)
    assert spending.status()["accounted_and_reserved_microusd"] == 58


def test_price_change_before_reservation_cannot_use_old_rates(paid):
    job = setup_budget()
    price = spending.quote(spending.MODEL, 128)
    spending.set_price(spending.MODEL, 9_000_000, 9_000_000,
                       time.time() + 3600, "https://provider.example/pricing")
    with pytest.raises(spending.BudgetDenied, match="Pricing changed"):
        journal.begin("root", "tool", "paid", {}, "agent", 1, job_id=job,
                      reserve=lambda db: spending.reserve(db, "root", job, "agent", None, price))
    assert journal.get("root") is None
    assert spending.status()["accounted_and_reserved_microusd"] == 0
