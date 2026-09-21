import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from toolgate.core import control_plane as cp
from toolgate.core import execution_journal as journal
from toolgate.core import port_replacements as records
from toolgate.core import port_reviews as reviews
from toolgate.core import vault
from toolgate.executors.port_spec import Replacement

CID = "a" * 64


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "DB_PATH", tmp_path / "gate.db")
    monkeypatch.setattr(vault, "ENV_PATH", tmp_path / "vault.env")
    monkeypatch.setenv("TOOLGATE_VAULT_SECRET", "synthetic-review-key")
    monkeypatch.setenv("TOOLGATE_VAULT_SALT", "a1" * 16)
    return reviews.create("actor", Replacement({"containerId": CID}, {"Env": ["SECRET=private-value"]}, "source", "app"))


def admit(review_id, action="action-1", actor="actor", cid=CID):
    return journal.begin(action, "tool", "system.port-control", {"container_id": cid, "review_id": review_id}, actor, 1,
                         reserve=lambda conn: reviews.consume_in_transaction(conn, review_id, actor, action))


def test_review_public_private_and_atomic_admission(setup):
    review_id = setup["reviewId"]
    assert "private-value" not in json.dumps(reviews.get(review_id, "actor"))
    assert b"private-value" not in cp.DB_PATH.read_bytes()
    assert admit(review_id)[1]
    assert reviews.get(review_id, "actor")["consumed"]
    assert records.load_private("action-1")._body == {"Env": ["SECRET=private-value"]}
    assert not admit(review_id)[1]


def test_two_actions_cannot_consume_same_review(setup):
    def attempt(action):
        try:
            admit(setup["reviewId"], action)
            return True
        except reviews.ReviewError:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, ["action-1", "action-2"])) == [False, True]
    assert len(journal.list_actions()) == 1


def test_expired_review_rolls_back_parent(setup, monkeypatch):
    monkeypatch.setattr(reviews.time, "time", lambda: setup["expiresAt"] + 1)
    with pytest.raises(reviews.ReviewError):
        admit(setup["reviewId"])
    assert journal.get("action-1") is None
    assert not reviews.get(setup["reviewId"], "actor")["consumed"]


def test_cross_actor_review_not_discoverable_or_consumable(setup):
    with pytest.raises(reviews.ReviewError):
        reviews.get(setup["reviewId"], "other")
    with pytest.raises(reviews.ReviewError):
        admit(setup["reviewId"], actor="other")
    assert journal.get("action-1") is None


def test_target_change_rolls_back_review_and_parent(setup):
    with pytest.raises(records.ReplacementError):
        admit(setup["reviewId"], cid="b" * 64)
    assert journal.get("action-1") is None
    assert not reviews.get(setup["reviewId"], "actor")["consumed"]


def test_failed_transaction_does_not_burn_review(setup):
    def reserve(conn):
        reviews.consume_in_transaction(conn, setup["reviewId"], "actor", "action-1")
        raise sqlite3.OperationalError("synthetic commit failure")
    with pytest.raises(sqlite3.OperationalError):
        journal.begin("action-1", "tool", "system.port-control", {"container_id": CID, "review_id": setup["reviewId"]},
                      "actor", 1, reserve=reserve)
    assert journal.get("action-1") is None
    assert not reviews.get(setup["reviewId"], "actor")["consumed"]
    assert admit(setup["reviewId"])[1]


def test_review_cannot_be_changed_or_replaced(setup):
    for sql in ["UPDATE v2_port_reviews SET expires_at=99999999999", "DELETE FROM v2_port_reviews",
                "UPDATE v2_port_reviews SET preview='{}'"]:
        with pytest.raises(sqlite3.IntegrityError), cp._conn() as conn:
            conn.execute(sql)


def test_key_change_fails_without_leaking_or_consuming(setup, monkeypatch):
    monkeypatch.setenv("TOOLGATE_VAULT_SECRET", "wrong-key")
    with pytest.raises(reviews.ReviewError) as error:
        admit(setup["reviewId"])
    assert "private-value" not in str(error.value)
    assert not reviews.get(setup["reviewId"], "actor")["consumed"]
