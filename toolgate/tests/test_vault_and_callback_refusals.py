"""Vault routes and signed verification callbacks refuse every bad input without changing state.

Through the real HTTP API on a temporary database and vault. Vault names that are not secrets
(the admin key, runtime configuration, names that are not SCREAMING_SNAKE_CASE) are refused with a
400 on create, update and delete, and an existing secret is never overwritten by a create. A signed
callback that comes during lockdown, names an unusable method, carries a bad signature, a stale
time, a wrong nonce or a request that is no longer pending decides nothing; five bad signatures in a
row lock ToolGate down.
"""

import hashlib
import hmac
import json
import time

from toolgate.core import control_plane as cp
from toolgate.core import vault
from toolgate.tests.test_approval_integrity import gate as gate
from toolgate.tests.test_approval_integrity import mint

ADMIN = {"X-ToolGate-Key": "integrity-owner"}
SECRET_NAME = "CALLBACK_TEST_SECRET"
SECRET = "callback-test-secret"


def code(response) -> str:
    return response.json()["detail"]["code"]


# --- vault ------------------------------------------------------------------


def test_vault_routes_refuse_without_the_admin_key(gate):
    client = gate[0]
    calls = [
        ("get", "/auth/check", None),
        ("get", "/vault/secrets", None),
        ("post", "/vault/secrets", {"name": "GITHUB_TOKEN", "value": "x"}),
        ("put", "/vault/secrets/GITHUB_TOKEN", {"value": "x"}),
        ("delete", "/vault/secrets/GITHUB_TOKEN", None),
        ("post", "/settings/keys/admin/rotate", None),
    ]
    for method, path, body in calls:
        for headers in ({}, {"X-ToolGate-Key": "not-the-key"}):
            kwargs = {"headers": headers} | ({"json": body} if body else {})
            assert getattr(client, method)(path, **kwargs).status_code == 401, path
    assert vault.list_placeholders() == []


def test_names_that_are_not_secrets_are_refused_on_every_write(gate):
    client = gate[0]
    for name, words in (
        ("TOOLGATE_ADMIN_KEY", "internal control key"),
        ("MEMORYGATE_URL", "runtime configuration"),
        ("github_token", "SCREAMING_SNAKE_CASE"),
    ):
        created = client.post("/vault/secrets", headers=ADMIN, json={"name": name, "value": "x"})
        assert created.status_code == 400 and words in created.json()["detail"]
        updated = client.put(f"/vault/secrets/{name}", headers=ADMIN, json={"value": "x"})
        assert updated.status_code == 400 and words in updated.json()["detail"]
    assert vault.list_placeholders() == []
    assert client.get("/auth/check", headers=ADMIN).json() == {"tier": "admin"}


def test_deleting_a_configuration_name_is_a_400_and_deletes_nothing(gate):
    client = gate[0]
    for name in ("TOOLGATE_ADMIN_KEY", "MEMORYGATE_URL"):
        response = client.delete(f"/vault/secrets/{name}", headers=ADMIN)
        assert response.status_code == 400, response.text
        assert "runtime configuration" in response.json()["detail"]
    assert client.get("/auth/check", headers=ADMIN).status_code == 200


def test_a_create_never_overwrites_and_the_list_never_shows_values(gate):
    client = gate[0]
    body = {"name": "GITHUB_TOKEN", "value": "first-value"}
    created = client.post("/vault/secrets", headers=ADMIN, json=body)
    assert created.json() == {"name": "GITHUB_TOKEN"}
    again = client.post("/vault/secrets", headers=ADMIN, json={**body, "value": "second-value"})
    assert again.status_code == 400 and "already exists" in again.json()["detail"]
    assert vault.get_key("GITHUB_TOKEN") == "first-value"

    listed = client.get("/vault/secrets", headers=ADMIN)
    assert listed.json() == ["GITHUB_TOKEN"] and "first-value" not in listed.text

    changed = client.put("/vault/secrets/GITHUB_TOKEN", headers=ADMIN, json={"value": "new"})
    assert changed.status_code == 200 and vault.get_key("GITHUB_TOKEN") == "new"
    deleted = client.delete("/vault/secrets/GITHUB_TOKEN", headers=ADMIN)
    assert deleted.json() == {"name": "GITHUB_TOKEN"}
    missing = client.delete("/vault/secrets/GITHUB_TOKEN", headers=ADMIN)
    assert missing.status_code == 404 and missing.json()["detail"] == "secret not found"
    assert vault.list_placeholders() == []


def test_rotating_the_admin_key_retires_the_old_one(gate):
    client = gate[0]
    new_key = client.post("/settings/keys/admin/rotate", headers=ADMIN).json()["key"]
    assert new_key and new_key != ADMIN["X-ToolGate-Key"]
    assert client.get("/auth/check", headers=ADMIN).status_code == 401
    assert client.get("/auth/check", headers={"X-ToolGate-Key": new_key}).status_code == 200


# --- verification methods ---------------------------------------------------


def test_a_verification_method_needs_a_configured_vault_name(gate):
    client = gate[0]

    def create(secret_ref):
        body = {"name": "x", "secret_ref": secret_ref}
        return client.post("/v2/verification-methods", headers=ADMIN, json=body)

    lower = create("not_a_ref")
    assert lower.status_code == 422 and "vault reference name" in lower.json()["detail"]
    unknown = create("NOT_SET")
    assert unknown.status_code == 422 and "not configured" in unknown.json()["detail"]
    assert create("TOOLGATE_ADMIN_KEY").status_code == 422  # never signs callbacks
    assert client.get("/v2/verification-methods", headers=ADMIN).json() == []
    gone = client.delete("/v2/verification-methods/vm_missing", headers=ADMIN)
    assert gone.status_code == 404


# --- signed callbacks -------------------------------------------------------


def method_for(gate) -> dict:
    vault.set_secret(SECRET_NAME, SECRET)
    response = gate[0].post(
        "/v2/verification-methods",
        headers=ADMIN,
        json={"name": "phone adapter", "secret_ref": SECRET_NAME},
    )
    assert response.status_code == 200, response.text
    return response.json()


def stored(kind: str, obj_id: str) -> dict:
    record = cp.get(kind, obj_id)
    assert record is not None, f"{kind} {obj_id} is missing"
    return record


def body_for(request_id: str, method: dict, **changes) -> dict:
    nonce = stored("request", request_id)["payload"]["binding"]["nonce"]
    return {
        "request_id": request_id,
        "method_id": method["id"],
        "decision": "approved",
        "nonce": nonce,
        **changes,
    }


def call(gate, body, *, secret=SECRET, timestamp=None, signature=None):
    stamp = int(time.time()) if timestamp is None else timestamp
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    signed = hmac.new(secret.encode(), f"{stamp}.{canonical}".encode(), hashlib.sha256)
    headers = {
        "X-ToolGate-Timestamp": str(stamp),
        "X-ToolGate-Signature": signature or signed.hexdigest(),
    }
    return gate[0].post("/v2/verification/callback", json=body, headers=headers)


def status_of(request_id: str) -> str:
    return stored("request", request_id)["status"]


def test_a_valid_callback_decides_the_request_once(gate):
    method = method_for(gate)
    request_id = mint(gate)
    body = body_for(request_id, method)
    accepted = call(gate, body)
    assert accepted.json() == {"status": "approved", "request_id": request_id}
    assert stored("verification_method", method["id"])["last_seen_at"]
    replay = call(gate, body)
    assert replay.status_code == 409 and code(replay) == "REQUEST_NOT_PENDING"


def test_a_callback_during_lockdown_decides_nothing(gate):
    method = method_for(gate)
    request_id = mint(gate)
    cp.set_lockdown(True, "admin", "test")
    response = call(gate, body_for(request_id, method))
    assert response.status_code == 423 and code(response) == "LOCKED_DOWN"
    assert status_of(request_id) == "pending"


def test_a_callback_naming_an_unusable_method_is_refused(gate):
    method = method_for(gate)
    request_id = mint(gate)

    unknown = call(gate, body_for(request_id, method, method_id="vm_missing"))
    assert unknown.status_code == 401 and code(unknown) == "VERIFICATION_METHOD_INVALID"

    cp.update_verification_method(method["id"], {"status": "disabled"})
    disabled = call(gate, body_for(request_id, method))
    assert disabled.status_code == 401 and code(disabled) == "VERIFICATION_METHOD_INVALID"

    cp.update_verification_method(method["id"], {"status": "active"})
    vault.delete_secret(SECRET_NAME)
    no_secret = call(gate, body_for(request_id, method))
    assert no_secret.status_code == 503 and code(no_secret) == "VERIFICATION_METHOD_INVALID"
    assert status_of(request_id) == "pending"


def test_a_bad_signature_or_stale_time_decides_nothing(gate):
    method = method_for(gate)
    request_id = mint(gate)
    body = body_for(request_id, method)

    for response in (
        call(gate, body, secret="someone-elses-secret"),
        call(gate, body, timestamp=int(time.time()) - 120),
        call(gate, body, timestamp=0),
        call(gate, body, signature="sha256=" + "0" * 64),
    ):
        assert response.status_code == 401 and code(response) == "CALLBACK_SIGNATURE_INVALID"
    assert status_of(request_id) == "pending"
    assert not cp.settings().get("lockdown")


def test_five_bad_signatures_lock_toolgate_down(gate):
    method = method_for(gate)
    request_id = mint(gate)
    body = body_for(request_id, method)
    for _ in range(5):
        assert call(gate, body, secret="wrong").status_code == 401
    assert cp.settings()["lockdown"] is True
    # Even a correctly signed callback now waits for the owner to lift lockdown.
    assert call(gate, body).status_code == 423
    assert status_of(request_id) == "pending"


def test_a_wrong_nonce_or_an_unknown_decision_decides_nothing(gate):
    method = method_for(gate)
    request_id = mint(gate)

    wrong_nonce = call(gate, body_for(request_id, method, nonce="not-the-nonce"))
    assert wrong_nonce.status_code == 409 and code(wrong_nonce) == "CALLBACK_NONCE_INVALID"
    maybe = call(gate, body_for(request_id, method, decision="maybe"))
    assert maybe.status_code == 422 and "approved or rejected" in maybe.json()["detail"]
    missing = call(gate, {**body_for(request_id, method), "request_id": "req_missing"})
    assert missing.status_code == 409 and code(missing) == "REQUEST_NOT_PENDING"
    assert status_of(request_id) == "pending"

    rejected = call(gate, body_for(request_id, method, decision="rejected"))
    assert rejected.json() == {"status": "rejected", "request_id": request_id}
