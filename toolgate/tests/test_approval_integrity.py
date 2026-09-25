"""Exercise forged approvals, stale decisions and restart authority against SQLite."""

import hashlib
import hmac
import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import vault
from toolgate.tests.test_approval_boundary import TOOL, TOOL_ID


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(vault, "ENV_PATH", tmp_path / "vault.env")
    monkeypatch.setenv("TOOLGATE_ADMIN_KEY", "integrity-owner")
    monkeypatch.setenv("TOOLGATE_VAULT_KEY_FILE", str(tmp_path / "vault.key"))
    monkeypatch.delenv("TOOLGATE_BOOTSTRAP_EXECUTION_KEY", raising=False)
    monkeypatch.delenv("TOOLGATE_BOOTSTRAP_SCOPES", raising=False)
    cp.create_tool(
        {
            **TOOL,
            "policy": {
                "usage_limits": {
                    "max_per_minute": 1000,
                    "max_per_hour": 1000,
                    "cooldown_seconds": 0,
                }
            },
        }
    )
    agent, key = cp.issue_agent_key("integrity caller", [f"tool:{TOOL_ID}"])
    with TestClient(server.app) as client:
        yield client, agent, key


def invoke(gate, request_id=None):
    client, _, key = gate
    return client.post(
        f"/v2/tools/{TOOL_ID}/invoke",
        headers={"X-ToolGate-Execution-Key": key},
        json={"args": {"value": "real action"}, "approval_request_id": request_id},
    )


def mint(gate):
    response = invoke(gate)
    assert response.status_code == 200
    assert response.json()["code"] == "CONFIRMATION_REQUIRED"
    return response.json()["request_id"]


def consume(gate, request_id):
    _, agent, _ = gate
    return cp.consume_verification(
        request_id,
        "tool",
        TOOL_ID,
        {"value": "real action"},
        TOOL["version"],
        agent["name"],
        agent["id"],
    )


def test_execution_key_cannot_forge_approval_text_or_binding(gate):
    client, agent, key = gate
    forged = {
        "kind": "verification",
        "title": "Harmless daily summary",
        "details": "Just reading",
        "payload": {
            "created_by_agent_key": agent["id"],
            "subject_type": "tool",
            "subject_id": TOOL_ID,
            "args": {"value": "real action"},
            "binding": {
                "subject_type": "tool",
                "subject_id": TOOL_ID,
                "version": TOOL["version"],
                "args_digest": cp.action_digest(
                    "tool", TOOL_ID, {"value": "real action"}, TOOL["version"]
                ),
                "nonce": "attacker-nonce",
                "expires_at": "2099-01-01T00:00:00+00:00",
                "consumed_at": None,
            },
        },
    }
    for path, headers in [
        ("/v2/requests", {"X-ToolGate-Execution-Key": key}),
        ("/v2/admin/requests", {"X-ToolGate-Key": "integrity-owner"}),
    ]:
        response = client.post(path, json=forged, headers=headers)
        assert response.status_code == 422
    assert cp.list_objects("request") == []
    # Informational requests can carry suggestions, but an approval of one confers no execution authority.
    response = client.post(
        "/v2/requests",
        json={**forged, "kind": "suggestion"},
        headers={"X-ToolGate-Execution-Key": key},
    )
    assert response.status_code == 200
    cp.decide_request(response.json()["id"], "approved", "admin")
    assert invoke(gate, response.json()["id"]).status_code == 409
    request_id = mint(gate)
    record = cp.get("request", request_id)
    assert record["title"] == f"Run {TOOL['name']}"
    assert record["payload"]["binding"]["nonce"] != "attacker-nonce"
    expiry = datetime.fromisoformat(record["payload"]["binding"]["expires_at"])
    assert (
        datetime.now(UTC)
        < expiry
        <= datetime.now(UTC) + timedelta(seconds=900)
    )
    cp.decide_request(request_id, "approved", "admin")
    assert invoke(gate, request_id).json()["code"] == "OK"


def test_late_decision_cannot_restore_a_consumed_token(gate, monkeypatch):
    request_id = mint(gate)
    read_pending = threading.Event()
    release = threading.Event()
    errors = []
    original_connect = sqlite3.connect

    class CoordinatedCursor(sqlite3.Cursor):
        def fetchone(self):
            row = super().fetchone()
            columns = row.keys() if row is not None else ()
            if (
                threading.current_thread().name == "late-decision"
                and row is not None
                and "body" in columns
                and row["id"] == request_id
            ):
                read_pending.set()
                assert release.wait(5), "decision race coordinator stalled"
            return row

    class CoordinatedConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            return self.cursor(factory=CoordinatedCursor).execute(sql, parameters)

    def connect(*args, **kwargs):
        # Coordinate real database reads; the test is independent of storage-helper names.
        return original_connect(
            *args, **{**kwargs, "timeout": 0.05, "factory": CoordinatedConnection}
        )

    def late_decision():
        try:
            cp.decide_request(request_id, "approved", "second owner interface")
        except (ValueError, sqlite3.Error, AssertionError) as exc:
            errors.append(exc)

    monkeypatch.setattr(sqlite3, "connect", connect)
    late = threading.Thread(target=late_decision, name="late-decision")
    late.start()
    first = None
    try:
        assert read_pending.wait(5)
        try:
            cp.decide_request(request_id, "approved", "first owner interface")
            first = consume(gate, request_id)
        except sqlite3.OperationalError as exc:
            # The correct implementation owns the writer lock before reading pending.
            assert "locked" in str(exc)
    finally:
        release.set()
        late.join(timeout=5)
    assert not late.is_alive() and not errors
    if first is None:
        first = consume(gate, request_id)
    assert first[0], first
    assert not consume(gate, request_id)[0], (
        "late approval resurrected an already consumed token"
    )
    assert (
        len([e for e in cp.events(500) if e["event_type"] == "verification_consumed"])
        == 1
    )


def test_generic_request_replacement_cannot_undo_consumption(gate):
    request_id = mint(gate)
    stale = cp.get("request", request_id)
    cp.decide_request(request_id, "approved", "admin")
    assert consume(gate, request_id)[0]
    with pytest.raises(ValueError, match="cannot be replaced"):
        cp._put("request", request_id, stale)
    assert not consume(gate, request_id)[0]


def test_restart_never_widens_or_revives_bootstrap_key(gate, monkeypatch):
    raw = "tgx_deployment_key_for_integrity_test"
    monkeypatch.setenv("TOOLGATE_BOOTSTRAP_EXECUTION_KEY", raw)
    monkeypatch.setenv("TOOLGATE_BOOTSTRAP_SCOPES", "tool:*,automation:*")
    server.startup()
    initial = cp.authenticate_agent(raw)
    cp.update_agent_key_scopes(initial["id"], [f"tool:{TOOL_ID}"])
    server.startup()
    narrowed = cp.authenticate_agent(raw)
    assert narrowed["id"] == initial["id"]
    assert narrowed["scopes"] == [f"tool:{TOOL_ID}"]
    cp.revoke_agent_key(initial["id"])
    server.startup()
    assert cp.authenticate_agent(raw) is None
    persisted = next(k for k in cp.list_agent_keys() if k["id"] == initial["id"])
    assert (
        persisted["scopes"] == [f"tool:{TOOL_ID}"] and persisted["status"] == "revoked"
    )
    # A scope edit is not a key-reactivation operation either.
    cp.update_agent_key_scopes(initial["id"], [])
    assert cp.authenticate_agent(raw) is None


def test_bootstrap_defaults_to_no_scope_and_concurrent_seed_is_idempotent(
    gate, monkeypatch
):
    raw = "tgx_empty_bootstrap_for_integrity_test"
    monkeypatch.setenv("TOOLGATE_BOOTSTRAP_EXECUTION_KEY", raw)
    server.startup()
    assert cp.authenticate_agent(raw)["scopes"] == []
    other = "tgx_concurrent_bootstrap_for_integrity"
    with ThreadPoolExecutor(max_workers=8) as pool:
        records = list(
            pool.map(lambda _: cp.ensure_bootstrap_agent_key(other, []), range(8))
        )
    assert len({record["id"] for record in records}) == 1
    assert len([k for k in cp.list_agent_keys() if k["id"] == records[0]["id"]]) == 1


def test_old_approvals_are_invalid_before_migration_and_cancelled_on_upgrade(gate):
    valid_id = mint(gate)
    valid = cp.get("request", valid_id)
    for status in ("pending", "approved"):
        legacy = {**valid, "status": status, "title": "Unverifiable pre-upgrade text"}
        cp._put("request", f"old-{status}", legacy)
        assert not consume(gate, f"old-{status}")[0]
    with pytest.raises(ValueError, match="not issued"):
        cp.decide_request("old-pending", "approved", "admin")
    assert cp.invalidate_legacy_verifications() == 2
    assert cp.invalidate_legacy_verifications() == 0
    for status in ("pending", "approved"):
        legacy = cp.get("request", f"old-{status}")
        assert legacy["status"] == "cancelled"
        assert legacy["title"] == "Unverifiable pre-upgrade text"
    cp.decide_request(valid_id, "approved", "admin")
    assert consume(gate, valid_id)[0]


@pytest.mark.parametrize("field", ["title", "expires_at"])
def test_altered_issuance_cannot_be_approved_or_consumed(gate, field):
    request_id = mint(gate)
    record = cp.get("request", request_id)
    if field == "title":
        record["title"] = "Misleading replacement"
    else:
        record["payload"]["binding"]["expires_at"] = "2099-01-01T00:00:00+00:00"
    with cp._conn() as conn:
        conn.execute(
            "UPDATE v2_objects SET body=? WHERE kind='request' AND id=?",
            (json.dumps(record), request_id),
        )
    with pytest.raises(ValueError, match="not issued"):
        cp.decide_request(request_id, "approved", "admin")


@pytest.mark.parametrize(
    "phase", ["request_created", "request_decided", "verification_consumed"]
)
def test_audit_failure_rolls_back_the_request_transition(gate, phase):
    request_id = None
    if phase != "request_created":
        request_id = mint(gate)
    if phase == "verification_consumed":
        cp.decide_request(request_id, "approved", "admin")
    before = cp.list_objects("request")
    with cp._conn() as conn:
        conn.execute(f"""CREATE TRIGGER reject_audit BEFORE INSERT ON v2_events
                         WHEN NEW.event_type='{phase}' BEGIN SELECT RAISE(ABORT,'audit drill'); END""")
    with pytest.raises(sqlite3.IntegrityError, match="audit drill"):
        if phase == "request_created":
            mint(gate)
        elif phase == "request_decided":
            cp.decide_request(request_id, "approved", "admin")
        else:
            consume(gate, request_id)
    assert cp.list_objects("request") == before


def test_competing_signed_callbacks_return_conflict_without_rewriting(
    gate, monkeypatch
):
    request_id = mint(gate)
    vault.set_secret("INTEGRITY_CALLBACK_SECRET", "callback-test-secret")
    method = cp.create_verification_method(
        {"name": "race adapter", "secret_ref": "INTEGRITY_CALLBACK_SECRET"}
    )
    record = cp.get("request", request_id)
    body = {
        "request_id": request_id,
        "method_id": method["id"],
        "decision": "approved",
        "nonce": record["payload"]["binding"]["nonce"],
    }
    timestamp = int(time.time())
    canonical = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    signature = hmac.new(
        b"callback-test-secret", f"{timestamp}.{canonical}".encode(), hashlib.sha256
    ).hexdigest()
    barrier = threading.Barrier(2)
    original_get = cp.get

    def get(kind, obj_id):
        value = original_get(kind, obj_id)
        if kind == "request" and obj_id == request_id:
            barrier.wait(timeout=5)
        return value

    monkeypatch.setattr(cp, "get", get)

    def callback():
        return gate[0].post(
            "/v2/verification/callback",
            json=body,
            headers={
                "X-ToolGate-Timestamp": str(timestamp),
                "X-ToolGate-Signature": signature,
            },
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: callback(), range(2)))
    assert sorted(r.status_code for r in responses) == [200, 409]
    assert consume(gate, request_id)[0]
    assert not consume(gate, request_id)[0]


def test_expired_requests_cannot_be_reported_as_approved(gate, monkeypatch):
    request_id = mint(gate)
    future = datetime.now(UTC) + timedelta(seconds=901)

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return future

    monkeypatch.setattr(cp, "datetime", Later)
    response = gate[0].post(
        f"/v2/requests/{request_id}/decision",
        json={"status": "approved"},
        headers={"X-ToolGate-Key": "integrity-owner"},
    )
    assert response.status_code == 409
    assert "expired" in response.json()["detail"]
    assert cp.get("request", request_id)["status"] == "pending"


def test_malformed_old_binding_is_cancelled_without_preventing_startup(gate):
    cp._put(
        "request",
        "malformed-legacy",
        {
            "kind": "verification",
            "status": "pending",
            "title": "Malformed old request",
            "payload": {"binding": None},
        },
    )
    server.startup()
    assert cp.get("request", "malformed-legacy")["status"] == "cancelled"
