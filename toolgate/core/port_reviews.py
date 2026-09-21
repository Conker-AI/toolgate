"""Expiring exact port-change reviews. These are not execution approvals."""

import json
import secrets
import time

from toolgate.core import control_plane as cp
from toolgate.core import port_replacements as records
from toolgate.core import vault
from toolgate.executors.port_spec import Replacement

SCHEMA = """
CREATE TABLE IF NOT EXISTS v2_port_reviews (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, preview TEXT NOT NULL,
 sealed TEXT NOT NULL, expires_at REAL NOT NULL, consumed_action TEXT
);
CREATE TRIGGER IF NOT EXISTS port_review_immutable BEFORE UPDATE ON v2_port_reviews
WHEN NEW.id IS NOT OLD.id OR NEW.actor_id IS NOT OLD.actor_id
 OR NEW.preview IS NOT OLD.preview OR NEW.sealed IS NOT OLD.sealed
 OR NEW.expires_at IS NOT OLD.expires_at OR OLD.consumed_action IS NOT NULL
BEGIN SELECT RAISE(ABORT,'port review identity is immutable'); END;
CREATE TRIGGER IF NOT EXISTS port_review_no_delete BEFORE DELETE ON v2_port_reviews
BEGIN SELECT RAISE(ABORT,'port review identity is permanent'); END;
CREATE TRIGGER IF NOT EXISTS port_review_no_replace BEFORE INSERT ON v2_port_reviews
WHEN EXISTS(SELECT 1 FROM v2_port_reviews WHERE id=NEW.id)
BEGIN SELECT RAISE(ABORT,'port review already exists'); END;
"""


class ReviewError(ValueError):
    def __init__(self):
        super().__init__("Port review is unavailable, expired or already used.")


def initialize(conn):
    records._initialize(conn)
    conn.executescript(SCHEMA)


def _public(row):
    return {"reviewId": row["id"], "preview": json.loads(row["preview"]),
            "expiresAt": row["expires_at"], "consumed": row["consumed_action"] is not None,
            "expired": row["expires_at"] <= time.time()}


def create(actor_id, replacement, *, ttl=300):
    if (not isinstance(actor_id, str) or not actor_id or len(actor_id) > 200
            or not isinstance(replacement, Replacement) or type(ttl) is not int or not 1 <= ttl <= 600):
        raise ReviewError()
    review_id = secrets.token_hex(24)
    expires = time.time() + ttl
    public = json.dumps(replacement.preview, allow_nan=False)
    payload = json.dumps({"reviewId": review_id, "actorId": actor_id, "expiresAt": expires,
                          "preview": replacement.preview, "body": replacement._body,
                          "source": replacement._source, "name": replacement.name}, allow_nan=False)
    if len(payload.encode()) > 2 * 1024 * 1024:
        raise ReviewError()
    sealed = vault._encrypt(payload)
    with cp._conn() as conn:
        initialize(conn)
        conn.execute("INSERT INTO v2_port_reviews VALUES (?,?,?,?,?,NULL)", (review_id, actor_id, public, sealed, expires))
        return _public(conn.execute("SELECT * FROM v2_port_reviews WHERE id=?", (review_id,)).fetchone())


def get(review_id, actor_id):
    with cp._conn() as conn:
        initialize(conn)
        row = conn.execute("SELECT * FROM v2_port_reviews WHERE id=? AND actor_id=?", (review_id, actor_id)).fetchone()
        if not row:
            raise ReviewError()
        return _public(row)


def consume_in_transaction(conn, review_id, actor_id, action_id):
    """Journal.reserve callback, after owner approval and parent INSERT, same txn."""
    row = conn.execute("SELECT * FROM v2_port_reviews WHERE id=? AND actor_id=?", (review_id, actor_id)).fetchone()
    if not row or row["consumed_action"] is not None or row["expires_at"] <= time.time():
        raise ReviewError()
    parent = records._parent(conn, action_id, active=True)
    args = json.loads(parent["args"])
    if parent["actor_id"] != actor_id or args.get("review_id") != review_id:
        raise ReviewError()
    try:
        if not row["sealed"].startswith(vault.ENCRYPTED_PREFIX):
            raise ReviewError()
        payload = json.loads(vault._decrypt("port review", row["sealed"]))
        if (payload["reviewId"] != review_id or payload["actorId"] != actor_id
                or payload["expiresAt"] != row["expires_at"]
                or payload["preview"] != json.loads(row["preview"])):
            raise ReviewError()
        replacement = Replacement(payload["preview"], payload["body"], payload["source"], payload["name"])
    except (vault.VaultError, KeyError, ValueError, TypeError):
        raise ReviewError() from None
    records.save_in_transaction(conn, action_id, replacement)
    conn.execute("UPDATE v2_port_reviews SET consumed_action=? WHERE id=?", (action_id, review_id))
