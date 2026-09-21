"""Real SQLite allowance accounting; no provider or network calls."""
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from toolgate.core import control_plane, spending, spending_allowances as allowances
from toolgate.core import execution_journal as journal


@pytest.fixture
def target(tmp_path, monkeypatch):
    monkeypatch.setattr(control_plane, "DB_PATH", tmp_path / "gate.db")
    spending.configure(True, 1000, 100)
    return {"kind": "tool", "id": "paid", "publishedVersion": 2,
            "digest": "a" * 64, "args": {"x": 1, "nested": {"b": 2, "a": 1}}}


def grant(target, **overrides):
    return allowances.create(**{"actor_id": "agent", "target": target, "per_run_cap": 100,
        "total_cap": 250, "max_runs": 3, "expires_at": time.time() + 3600, **overrides})


def allocate(row, target, root="root", actor="agent"):
    return allowances.allocate(row["allowance_id"], actor, root, target)


def enforce(job, target):
    return journal.begin(job["root_action_id"], target["kind"], target["id"], target["args"],
        job["actor_id"], target["publishedVersion"], job_id=job["job_id"],
        publication_digest=target["digest"], reserve=lambda conn: allowances.enforce(conn, job,
            conn.execute("SELECT * FROM v2_actions WHERE action_id=?", (job["root_action_id"],)).fetchone()))


def test_canonical_target_and_permanent_full_cap_accounting(target):
    row = grant(target)
    job = allocate(row, target)
    reordered = {**target, "args": {"nested": {"a": 1, "b": 2}, "x": 1}}
    assert allocate(row, reordered) == job
    allocate(row, target, "second")
    with pytest.raises(spending.BudgetDenied, match="exhausted"):
        allocate(row, target, "third")
    read = allowances.get(row["allowance_id"], "agent")
    assert (read["allocated_runs"], read["allocated_cap"], read["remaining_cap"], read["remaining_runs"]) == (2, 200, 50, 0)
    assert spending.status()["accounted_and_reserved_microusd"] == 0
    assert allowances.get(row["allowance_id"], "impostor") is None
    assert allowances.get("missing") is None


def test_real_reservation_rechecks_allowance(target):
    spending.set_price(spending.MODEL, 1, 1, time.time() + 3600, "https://example.test/prices")
    price = spending.quote(spending.MODEL, 128)
    row = grant(target)
    job = allocate(row, target)
    allowances.revoke(row["allowance_id"])
    with pytest.raises(spending.BudgetDenied):
        journal.begin("root", "tool", target["id"], target["args"], "agent", 2,
            job_id=job["job_id"], publication_digest=target["digest"],
            reserve=lambda conn: spending.reserve(conn, "root", job["job_id"], "agent", None, price))
    assert journal.get("root") is None


def test_allowance_api_authority_and_actor_isolation(target):
    from fastapi.testclient import TestClient
    from toolgate.api import server
    app = server.app
    with TestClient(app) as client:
        assert client.post("/v2/spending/allowances", json={}).status_code in (401, 403)
        app.dependency_overrides[server.require_admin] = lambda: "admin"
        app.dependency_overrides[server.require_agent] = lambda: {"id": "agent", "scopes": ["*"]}
        try:
            response = client.post("/v2/spending/allowances", json={"actor_id": "agent",
                "target": target, "per_run_cap": 100, "total_cap": 200,
                "max_runs": 2, "expires_at": time.time() + 3600})
            assert response.status_code == 200
            identity = response.json()["allowance_id"]
            path = f"/v2/agent/spending/allowances/{identity}/allocate"
            payload = {"root_action_id": "root", "target": target}
            first = client.post(path, json=payload)
            assert first.status_code == 200
            assert first.headers["cache-control"] == "no-store"
            assert client.post(path, json=payload).json() == first.json()
            app.dependency_overrides[server.require_agent] = lambda: {"id": "other", "scopes": ["*"]}
            assert client.post(path, json=payload).status_code == 422
            assert client.post(f"/v2/spending/allowances/{identity}/revoke").status_code == 200
        finally:
            app.dependency_overrides.clear()


@pytest.mark.parametrize("same_root", [True, False])
def test_concurrent_allocation_is_serial_and_idempotent(target, same_root):
    row = grant(target, max_runs=1)
    barrier = Barrier(2)

    def attempt(index):
        barrier.wait(timeout=5)
        try:
            return allocate(row, target, "root" if same_root else f"root{index}")
        except spending.BudgetDenied:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, range(2)))
    if same_root:
        assert results[0] == results[1]
    else:
        assert sum(result is not None for result in results) == 1
    assert allowances.get(row["allowance_id"])["allocated_runs"] == 1


@pytest.mark.parametrize("mode", ["revoked", "expired", "disabled", "lowered_cap"])
def test_existing_jobs_cannot_dispatch_after_authority_changes(target, monkeypatch, mode):
    row = grant(target)
    job = allocate(row, target)
    if mode == "revoked":
        receipt = allowances.revoke(row["allowance_id"])
        assert allowances.revoke(row["allowance_id"]) == receipt
    elif mode == "expired":
        monkeypatch.setattr(allowances.time, "time", lambda: row["expires_at"] + 1)
    else:
        spending.configure(mode != "disabled", 1000, 50 if mode == "lowered_cap" else 100)
    assert allocate(row, target) == job
    with pytest.raises(spending.BudgetDenied):
        allocate(row, target, "second")
    with pytest.raises(spending.BudgetDenied):
        enforce(job, target)
    assert journal.get("root") is None


@pytest.mark.parametrize("field,value", [("kind", "automation"), ("id", "other"),
    ("publishedVersion", 3), ("digest", "b" * 64), ("args", {"x": 2})])
def test_actual_root_must_match_every_target_field(target, field, value):
    row = grant(target)
    different = {**target, field: value}
    with pytest.raises(spending.BudgetDenied):
        allocate(row, different)
    job = allocate(row, target)
    with pytest.raises(spending.BudgetDenied):
        enforce(job, different)
    assert journal.get("root") is None
    assert enforce(job, target)[1] is True


def test_other_actor_grant_and_ordinary_job_cannot_claim_existing_root(target):
    row = grant(target)
    with pytest.raises(spending.BudgetDenied):
        allocate(row, target, actor="impostor")
    allocate(row, target)
    with pytest.raises(spending.BudgetDenied):
        allocate(grant(target), target)
    spending.create_job("agent", "ordinary", 100)
    with pytest.raises(spending.BudgetDenied):
        allocate(row, target, "ordinary")


def test_ordinary_jobs_are_unaffected_and_enforcement_does_not_commit(target):
    job = spending.create_job("agent", "root", 100)
    with control_plane._conn() as conn:
        allowances.initialize(conn)
        conn.execute("BEGIN IMMEDIATE")
        allowances.enforce(conn, job, None)
        assert conn.in_transaction


@pytest.mark.parametrize("table", ["v2_spend_allowances", "v2_spend_allowance_allocations", "v2_spend_allowance_revocations"])
def test_grants_allocations_and_revocation_receipts_are_immutable(target, table):
    row = grant(target)
    allocate(row, target)
    allowances.revoke(row["allowance_id"])
    for query in [f"DELETE FROM {table}", f"UPDATE {table} SET allowance_id='changed'",
                  f"INSERT OR REPLACE INTO {table} SELECT * FROM {table}"]:
        with control_plane._conn() as conn:
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(query)


@pytest.mark.parametrize("overrides", [{"per_run_cap": True}, {"total_cap": 99}, {"max_runs": 0},
    {"expires_at": float("inf")}, {"expires_at": float("nan")}, {"expires_at": 0},
    {"actor_id": ""}, {"per_run_cap": 101}])
def test_invalid_grants_fail_closed(target, overrides):
    with pytest.raises(spending.BudgetDenied):
        grant(target, **overrides)


@pytest.mark.parametrize("patch", [{"extra": True}, {"publishedVersion": True},
    {"args": {"x": float("nan")}}, {"args": {1: "not a JSON key"}}, {"digest": ""}])
def test_invalid_target_fails_closed(target, patch):
    with pytest.raises(spending.BudgetDenied):
        grant({**target, **patch})
