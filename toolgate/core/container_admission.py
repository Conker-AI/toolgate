"""Shared container mutation reservations inside the existing action transaction."""

import json
import re

SCHEMA = """
CREATE TABLE IF NOT EXISTS v2_container_claims (
 action_id TEXT PRIMARY KEY REFERENCES v2_actions(action_id), container_id TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS container_claim_no_update BEFORE UPDATE ON v2_container_claims
BEGIN SELECT RAISE(ABORT,'container claim is immutable'); END;
CREATE TRIGGER IF NOT EXISTS container_claim_no_delete BEFORE DELETE ON v2_container_claims
BEGIN SELECT RAISE(ABORT,'container claim is permanent'); END;
CREATE TRIGGER IF NOT EXISTS container_claim_no_replace BEFORE INSERT ON v2_container_claims
WHEN EXISTS(SELECT 1 FROM v2_container_claims WHERE action_id=NEW.action_id)
BEGIN SELECT RAISE(ABORT,'container claim already exists'); END;
"""


class ContainerBusy(ValueError):
    def __init__(self):
        super().__init__("Container has a pending or uncertain action; inspect it before retrying.")


def reserve(conn, action_id, container_id):
    if (not conn.in_transaction or not isinstance(container_id, str)
            or not re.fullmatch(r"[a-f0-9]{64}", container_id)):
        raise ContainerBusy()
    parent = conn.execute("SELECT * FROM v2_actions WHERE action_id=?", (action_id,)).fetchone()
    if (not parent or parent["subject_type"] != "tool" or parent["status"] != "dispatching"
            or json.loads(parent["args"]).get("container_id") != container_id):
        raise ContainerBusy()
    conflict = conn.execute(
        "SELECT 1 FROM v2_actions a LEFT JOIN v2_container_claims c ON c.action_id=a.action_id"
        " WHERE a.action_id<>? AND a.status IN ('dispatching','outcome_unknown')"
        " AND (c.container_id=? OR (a.subject_type='tool'"
        " AND a.subject_id IN ('system.container-control','system.port-control')"
        " AND json_extract(a.args,'$.container_id')=?)) LIMIT 1",
        (action_id, container_id, container_id),).fetchone()
    if conflict:
        raise ContainerBusy()
    existing = conn.execute("SELECT container_id FROM v2_container_claims WHERE action_id=?", (action_id,)).fetchone()
    if existing:
        if existing["container_id"] != container_id:
            raise ContainerBusy()
        return
    conn.execute("INSERT INTO v2_container_claims VALUES (?,?)", (action_id, container_id))
