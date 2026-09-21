import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import port_replacements as store
from toolgate.core import vault
from toolgate.executors.port_spec import Replacement

CID = "a" * 64


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(vault, "ENV_PATH", tmp_path / "vault.env")
    monkeypatch.setenv("TOOLGATE_VAULT_SECRET", "synthetic-test-key")
    monkeypatch.setenv("TOOLGATE_VAULT_SALT", "a1" * 16)
    journal.begin("replace-1", "tool", "system.port-control", {"container_id": CID}, "actor", 1)
    replacement = Replacement({"containerId": CID}, {"Env": ["SECRET=private-test-value"]}, "private-fingerprint", "app")
    store.save("replace-1", replacement)
    return replacement


def test_real_encrypted_roundtrip_never_puts_private_payload_in_receipts(setup):
    assert store.load_private("replace-1")._body == setup._body
    assert b"private-test-value" not in cp.DB_PATH.read_bytes()
    assert "private-test-value" not in json.dumps(journal.get("replace-1"))
    assert "private-test-value" not in repr(store.load_private("replace-1"))
    with cp._conn() as conn:
        assert conn.execute("SELECT sealed FROM v2_port_replacements").fetchone()[0].startswith("enc:v1:")


def test_once_only_concurrent_step_claim_and_order(setup):
    def claim(_):
        return store.begin_step("replace-1", 0, "stop", authorize=lambda conn: None)
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(claim, range(2))) == [False, True]
    with pytest.raises(store.ReplacementError):
        store.begin_step("replace-1", 1, "snapshot", authorize=lambda conn: None)
    store.observed("replace-1", 0)
    assert store.begin_step("replace-1", 1, "snapshot", authorize=lambda conn: None)
    store.observed("replace-1", 1, reference="sha256:" + "b" * 64)
    assert [step["status"] for step in store.steps("replace-1")] == ["observed", "observed"]


def test_crash_recovery_cannot_claim_next_step_or_retry(setup):
    store.begin_step("replace-1", 0, "stop", authorize=lambda conn: None)
    assert journal.recover_interrupted() == 1
    assert store.steps("replace-1")[0]["status"] == "outcome_unknown"
    for ordinal, name in [(0, "stop"), (1, "snapshot")]:
        with pytest.raises(store.ReplacementError):
            store.begin_step("replace-1", ordinal, name, authorize=lambda conn: None)


def test_authority_failure_rolls_back_claim(setup):
    def denied(conn):
        raise PermissionError("revoked")
    with pytest.raises(PermissionError):
        store.begin_step("replace-1", 0, "stop", authorize=denied)
    assert store.steps("replace-1") == []


def test_unknown_effect_halts_parent_and_preserves_evidence(setup):
    store.begin_step("replace-1", 0, "stop", authorize=lambda conn: None)
    store.unknown("replace-1", 0)
    assert journal.get("replace-1")["status"] == "outcome_unknown"
    assert store.steps("replace-1")[0]["status"] == "outcome_unknown"
    # A late confirmed observation improves evidence, but never reopens parent.
    store.observed("replace-1", 0)
    assert store.steps("replace-1")[0]["status"] == "observed"
    with pytest.raises(store.ReplacementError):
        store.begin_step("replace-1", 1, "snapshot", authorize=lambda conn: None)


def test_public_reference_rejects_arbitrary_diagnostics(setup):
    store.begin_step("replace-1", 0, "stop", authorize=lambda conn: None)
    with pytest.raises(store.ReplacementError):
        store.observed("replace-1", 0, reference="SECRET=private-test-value")
    assert "private-test-value" not in json.dumps(store.steps("replace-1"))


def test_frozen_payload_and_completed_step_cannot_be_rewritten(setup):
    with pytest.raises(store.ReplacementError):
        store.save("replace-1", setup)
    store.begin_step("replace-1", 0, "stop", authorize=lambda conn: None)
    store.observed("replace-1", 0)
    store.observed("replace-1", 0)
    for sql in ["DELETE FROM v2_port_replacements", "UPDATE v2_port_replacements SET sealed='cleartext'",
                "DELETE FROM v2_port_steps", "UPDATE v2_port_steps SET status='dispatching'"]:
        with pytest.raises(sqlite3.IntegrityError), cp._conn() as conn:
            conn.execute(sql)


def test_wrong_key_and_cleartext_fallback_are_rejected(setup, monkeypatch):
    monkeypatch.setenv("TOOLGATE_VAULT_SECRET", "different-test-key")
    with pytest.raises(store.ReplacementError) as error:
        store.load_private("replace-1")
    assert "private-test-value" not in str(error.value)


def test_unrelated_action_cannot_own_replacement(setup):
    journal.begin("other", "tool", "system.container-control", {"container_id": CID}, "actor", 1)
    with pytest.raises(store.ReplacementError):
        store.save("other", setup)


def test_ciphertext_is_bound_to_exact_action_not_only_vault_key(setup):
    journal.begin("replace-2", "tool", "system.port-control", {"container_id": CID}, "actor", 1)
    with cp._conn() as conn:
        sealed = conn.execute("SELECT sealed FROM v2_port_replacements").fetchone()[0]
        conn.execute("INSERT INTO v2_port_replacements VALUES (?,?)", ("replace-2", sealed))
    with pytest.raises(store.ReplacementError):
        store.load_private("replace-2")
