"""Dedicated owner authority never becomes administration or agent execution."""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane as cp
from toolgate.core import owner_channel as owner
from toolgate.core import vault

KEY = "dedicated-owner-" + "x" * 40
ADMIN = "operator-only-" + "a" * 40
HEADERS = {"X-ToolGate-Owner-Key": KEY}


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(vault, "ENV_PATH", tmp_path / "vault.env")
    monkeypatch.setenv("TOOLGATE_ADMIN_KEY", ADMIN)
    monkeypatch.setenv(owner.OWNER_HASH, hashlib.sha256(KEY.encode()).hexdigest())
    agent, execution = cp.issue_agent_key("Pi", ["tool:example"])
    client = TestClient(server.app)  # No startup, listeners, vault reads or external services.
    yield client, agent, execution
    client.close()


def mint(gate, args=None):
    return cp.create_verification_request("Run example", "Review the exact invocation.", "Pi",
        "tool", "example", {"text": "precise action"} if args is None else args, 1,
        actor_id=gate[1]["id"])


def detail(gate, identity):
    return gate[0].get(f"/v2/owner/requests/{identity}", headers=HEADERS)


def decide(gate, identity, status="approved", **extra):
    return gate[0].post(f"/v2/owner/requests/{identity}/decision", headers=HEADERS,
                        json={"status": status, "note": "Owner checked", **extra})


def test_channels_are_separate_even_if_host_accidentally_reuses_credentials(gate, monkeypatch):
    client, _, execution = gate
    request = mint(gate)
    for headers in ({}, {"X-ToolGate-Key": ADMIN}, {"X-ToolGate-Execution-Key": execution},
                    {"X-ToolGate-Owner-Key": ADMIN}, {"X-ToolGate-Owner-Key": execution}):
        assert client.get("/v2/owner/requests", headers=headers).status_code == 401
    for broad_key in (ADMIN, execution):
        monkeypatch.setenv(owner.OWNER_HASH, hashlib.sha256(broad_key.encode()).hexdigest())
        assert client.get("/v2/owner/requests", headers={"X-ToolGate-Owner-Key": broad_key}).status_code == 401
    monkeypatch.setenv(owner.OWNER_HASH, hashlib.sha256(KEY.encode()).hexdigest())
    for path, headers in (("/v2/requests", HEADERS), ("/v2/tools", {"X-ToolGate-Key": KEY}),
                          ("/v2/agent/tools", {"X-ToolGate-Execution-Key": KEY})):
        assert client.get(path, headers=headers).status_code == 401
    assert detail(gate, request["id"]).status_code == 200
    monkeypatch.delenv(owner.OWNER_HASH)
    assert client.get("/v2/owner/requests", headers=HEADERS).status_code == 503


def test_fixed_projection_has_full_args_but_no_nonce_originating_key_or_unknown_payload(gate):
    request = mint(gate, {"text": "hello", "nested": [True, None, {"n": 1}]})
    view = detail(gate, request["id"]).json()
    assert view["action"]["args"] == request["payload"]["args"] and view["reviewable"]
    assert view["approval"]["origin_valid"] and view["unavailable_reason"] is None
    assert set(view) == {"id", "kind", "title", "details", "actor", "severity", "status",
                         "created_at", "updated_at", "decision", "action", "approval",
                         "reviewable", "unavailable_reason"}
    text = json.dumps(view)
    for hidden in ("nonce", "args_digest", "created_by_agent_key", request["payload"]["binding"]["nonce"],
                   gate[1]["id"], KEY, ADMIN):
        assert hidden not in text
    # Informational messages can never masquerade as execution approvals.
    other = cp.create_request("info", "Message", "No execution authority", "Pi", {"secret": "hidden"})
    assert detail(gate, other["id"]).status_code == 404
    assert decide(gate, other["id"]).status_code == 404
    assert len(gate[0].get("/v2/owner/requests", headers=HEADERS).json()["results"]) == 1


@pytest.mark.parametrize("args", [{"text": "x" * 32768}, {str(i): i for i in range(1100)},
                                  {"invalid": float("nan")}, {"n": 9007199254740993},
                                  {"nested": [{"n": -9007199254740993}]}])
def test_withheld_arguments_never_authorize_a_decision(gate, args):
    request = mint(gate, args)
    view = detail(gate, request["id"]).json()
    assert view["action"]["args"] is None and not view["reviewable"]
    assert view["unavailable_reason"] == "arguments_unavailable"
    for status in ("approved", "rejected", "dismissed"):
        assert decide(gate, request["id"], status).status_code == 409
    assert cp.get("request", request["id"])["status"] == "pending"


def test_origin_tampering_between_review_and_decision_fails_closed(gate):
    request = mint(gate)
    assert detail(gate, request["id"]).json()["reviewable"]
    record = cp.get("request", request["id"])
    record["payload"]["args"] = {"text": "changed after owner view"}
    with cp._conn() as db:
        db.execute("UPDATE v2_objects SET body=? WHERE kind='request' AND id=?",
                   (json.dumps(record), request["id"]))
    assert decide(gate, request["id"]).status_code == 409
    view = detail(gate, request["id"]).json()
    assert view["unavailable_reason"] == "invalid_origin" and view["action"]["args"] is None
    assert cp.get("request", request["id"])["status"] == "pending"


def test_legacy_malformed_binding_is_read_only_not_server_error(gate):
    record = cp._put("request", "old-request", {"kind": "verification", "status": "pending",
        "payload": {"binding": {"subject_type": [], "subject_id": {}, "version": True}}})
    view = detail(gate, record["id"])
    assert view.status_code == 200 and view.json()["unavailable_reason"] == "invalid_origin"
    assert decide(gate, record["id"]).status_code == 409


def test_expired_pending_remains_pending_but_can_only_be_rejected_or_dismissed(gate, monkeypatch):
    class Past(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(UTC) - timedelta(hours=1)
    with monkeypatch.context() as context:
        context.setattr(cp, "datetime", Past)
        request = mint(gate)
    view = detail(gate, request["id"]).json()
    assert view["status"] == "pending" and view["unavailable_reason"] == "expired"
    assert decide(gate, request["id"]).status_code == 409
    rejected = decide(gate, request["id"], "rejected")
    assert rejected.status_code == 200 and rejected.json()["decision"]["status"] == "rejected"


def test_strict_decision_body_and_safe_errors(gate):
    request = mint(gate)
    for extra in ({"note": "private" * 400}, {"status": "pending"}, {"secret": "do-not-echo"}):
        response = decide(gate, request["id"], **extra)
        assert response.status_code == 422
        assert "private" not in response.text and "do-not-echo" not in response.text
    assert cp.get("request", request["id"])["status"] == "pending"


def test_concurrent_decisions_commit_one_transition_and_reconcile_by_detail(gate):
    request = mint(gate)
    def run(status):
        try:
            return owner.decide(request["id"], status, "review")["status"]
        except owner.OwnerError as error:
            return error.status
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run, status) for status in ("approved", "rejected")]
        results = [future.result() for future in futures]
    assert results.count(409) == 1
    view = detail(gate, request["id"]).json()
    assert view["status"] in {"approved", "rejected"} and not view["reviewable"]
    assert view["decision"]["actor"] == "gateway-owner"
    assert decide(gate, request["id"], view["status"]).status_code == 409
    with cp._conn() as db:
        assert db.execute("SELECT count(*) FROM v2_events WHERE subject_id=? AND event_type='request_decided'",
                          (request["id"],)).fetchone()[0] == 1


def test_consumption_cannot_be_undone_by_a_late_decision(gate):
    request = mint(gate)
    assert decide(gate, request["id"]).status_code == 200
    assert cp.consume_verification(request["id"], "tool", "example", {"text": "precise action"},
                                   1, "Pi", gate[1]["id"])[0]
    assert decide(gate, request["id"]).status_code == 409
    view = detail(gate, request["id"]).json()
    assert view["unavailable_reason"] == "consumed" and view["approval"]["consumed_at"]


def test_pagination_uses_creation_order_even_after_decisions(gate):
    records = [mint(gate) for _ in range(4)]
    found, cursor = [], None
    while True:
        page = gate[0].get("/v2/owner/requests", headers=HEADERS,
                           params={"limit": 1, **({"cursor": cursor} if cursor else {})}).json()
        found.extend(item["id"] for item in page["results"])
        if cursor is None:
            assert decide(gate, records[0]["id"]).status_code == 200
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert len(found) == len(set(found)) == 4
    assert set(found) == {record["id"] for record in records}


def test_owner_configuration_is_not_a_tool_or_vault_secret(gate, monkeypatch):
    for name in (owner.OWNER_HASH, "TOOLGATE_OWNER_KEY"):
        monkeypatch.setenv(name, "private-config")
        with pytest.raises(KeyError):
            vault.get_key(name)
        with pytest.raises(ValueError):
            vault.set_secret(name, "cannot-write")
        with pytest.raises(ValueError):
            vault.delete_secret(name)
        assert name not in vault.list_placeholders()


def test_page_byte_budget_preserves_next_cursor_without_truncating_arguments(gate, monkeypatch):
    monkeypatch.setattr(owner, "PAGE_BYTES", 2200)
    records = [mint(gate, {"text": "x" * 1000}) for _ in range(3)]
    found, cursor = [], None
    while True:
        page = owner.list_requests(200, cursor)
        assert len(page["results"]) == 1
        assert page["results"][0]["action"]["args"] == {"text": "x" * 1000}
        found.append(page["results"][0]["id"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert set(found) == {record["id"] for record in records}
