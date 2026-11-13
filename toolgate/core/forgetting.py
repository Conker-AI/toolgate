"""Forget a chat's tool records (context/design/forgetting-data-map.md, gap 9).

ToolGate blanks named approval requests and actions once. The arguments, results and words they
carried go; who, when, what kind and the decision stay, with one `v2_forgotten` row and one event
each. An action keeps its fingerprint, so a retry of the same action id answers the forgotten
receipt and can never dispatch again. An agent reaches only its own records; the admin key
reaches any. Nothing waiting for the owner and nothing still running is touched.
"""

from __future__ import annotations

import json
import uuid

from toolgate.core import approvals, control_plane, recovery_journal
from toolgate.core import execution_journal as journal
from toolgate.core.control_plane import _now, _row

FORGOTTEN_TEXT = "Forgotten with its chat."
EMPTY = "{}"


class RecoveryHeld(ValueError):
    pass


def _outcomes() -> dict:
    return {"forgotten": [], "already": [], "unknown": [], "refused": []}


def _event(conn, event_type: str, subject_type: str, subject_id: str, actor: str, payload: dict) -> None:
    conn.execute("INSERT INTO v2_events VALUES(?,?,?,?,?,?,?,?)",
                 (str(uuid.uuid4()), event_type, "info", subject_type, subject_id, actor,
                  json.dumps(payload), _now()))


def _already(conn, object_type: str, object_id: str) -> bool:
    return conn.execute("SELECT 1 FROM v2_forgotten WHERE object_type=? AND object_id=?",
                        (object_type, object_id)).fetchone() is not None


def _mark(conn, object_type: str, object_id: str, by: str) -> None:
    conn.execute("INSERT OR IGNORE INTO v2_forgotten VALUES(?,?,?,?)", (object_type, object_id, _now(), by))


def _blank_request(conn, record: dict, by: str) -> None:
    kind, status = record.get("kind"), record.get("status")
    payload = dict(record.get("payload") or {})
    if kind == "verification":
        binding = dict(payload.get("binding") or {})
        if status == "approved" and not binding.get("consumed_at"):
            # An approval not used yet can never run once its chat is forgotten.
            binding["consumed_at"], binding["consumed_by"] = _now(), "forgetting"
        binding.pop("args_digest", None)
        payload = {**payload, "args": {}, "binding": binding}
    else:
        # An informational request's title and payload are the agent's own words.
        payload = {"created_by_agent_key": payload.get("created_by_agent_key")}
        record["title"] = f"Forgotten {kind} message"
        conn.execute("UPDATE v2_events SET payload=? WHERE subject_type='request' AND subject_id=?"
                     " AND event_type='request_created'",
                     (json.dumps({"kind": kind, "title": record["title"]}), record["id"]))
    if status == "pending":
        # A message to the owner from a forgotten chat leaves his Inbox with its words.
        record["status"] = approvals.WITHDRAWN
        record["decision"] = {"actor": by, "note": "", "at": _now()}
    record["payload"], record["details"] = payload, FORGOTTEN_TEXT
    if isinstance(record.get("decision"), dict):
        record["decision"] = {**record["decision"], "note": ""}
    _mark(conn, "request", record["id"], by)
    approvals._save_request(conn, record)
    if kind == "verification":
        # Terminal and consumed, so a re-sealed origin grants nothing; it keeps the Inbox
        # history from reading the blanked record as tampered.
        conn.execute("UPDATE v2_verification_origins SET fingerprint=? WHERE request_id=?",
                     (approvals._verification_fingerprint(record), record["id"]))
    _event(conn, "request_forgotten", "request", record["id"], by, {"kind": kind, "status": status})


def _requests(conn, ids: list[str], agent_id: str | None, by: str) -> dict:
    result = _outcomes()
    for request_id in dict.fromkeys(ids):
        row = conn.execute("SELECT * FROM v2_objects WHERE kind='request' AND id=?", (request_id,)).fetchone()
        record = _row(row) if row else None
        if not record or (agent_id is not None
                          and record.get("payload", {}).get("created_by_agent_key") != agent_id):
            result["unknown"].append(request_id)
        elif _already(conn, "request", request_id):
            result["already"].append(request_id)
        elif record.get("status") == "pending" and record.get("kind") == "verification":
            # An approval still waiting is withdrawn first (POST .../withdraw), never blanked open.
            result["refused"].append({"id": request_id, "code": "still_pending"})
        else:
            _blank_request(conn, record, by)
            result["forgotten"].append(request_id)
    return result


def _tree(conn, action_id: str) -> list[str]:
    return [row[0] for row in conn.execute(
        "WITH RECURSIVE tree(id) AS (SELECT ? UNION SELECT a.action_id FROM v2_actions a"
        " JOIN tree ON a.parent_action_id = tree.id) SELECT id FROM tree", (action_id,))]


def _blank_action(conn, action_id: str, by: str) -> None:
    _mark(conn, "action", action_id, by)
    conn.execute("UPDATE v2_actions SET args=?, response=CASE WHEN status='completed' THEN ?"
                 " ELSE response END WHERE action_id=?", (EMPTY, journal.FORGOTTEN_RESPONSE, action_id))
    receipt = conn.execute("SELECT record FROM v2_recovery_receipts WHERE action_id=?", (action_id,)).fetchone()
    if receipt:
        record = json.loads(receipt[0])
        record["args"] = EMPTY
        if record.get("status") == "completed":
            record["response"] = journal.FORGOTTEN_RESPONSE
        conn.execute("UPDATE v2_recovery_receipts SET record=? WHERE action_id=?",
                     (json.dumps(record, sort_keys=True), action_id))
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='v2_editor_runs'").fetchone():
        conn.execute("UPDATE v2_editor_runs SET args=?, response=CASE WHEN response IS NULL THEN NULL"
                     " ELSE ? END WHERE action_id=?", (EMPTY, journal.FORGOTTEN_RESPONSE, action_id))


def _editor_run_only(conn, action_id: str, agent_id: str | None, by: str, result: dict) -> None:
    """An editor run waiting on approval (or refused before dispatch) has no journal row yet;
    one `held` is between its own record and its journal row, about to dispatch."""
    run = None
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='v2_editor_runs'").fetchone():
        run = conn.execute("SELECT * FROM v2_editor_runs WHERE action_id=?", (action_id,)).fetchone()
    if not run or (agent_id is not None and run["actor_id"] != agent_id):
        result["unknown"].append(action_id)
    elif _already(conn, "action", action_id):
        result["already"].append(action_id)
    elif run["state"] == "held":
        result["refused"].append({"id": action_id, "code": "still_running"})
    else:
        # Its arguments become {}, so the same run sent again conflicts instead of running.
        _blank_action(conn, action_id, by)
        _event(conn, "action_forgotten", "action", action_id, by,
               {"subject_type": "editor_run", "subject_id": run["draft_id"],
                "status": run["state"], "children": 0})
        result["forgotten"].append(action_id)


def _actions(conn, ids: list[str], agent_id: str | None, by: str) -> dict:
    result = _outcomes()
    for action_id in dict.fromkeys(ids):
        row = recovery_journal.lookup(conn, action_id)
        if not row:
            _editor_run_only(conn, action_id, agent_id, by, result)
            continue
        if agent_id is not None and row["actor_id"] != agent_id:
            result["unknown"].append(action_id)
            continue
        if _already(conn, "action", action_id):
            result["already"].append(action_id)
            continue
        tree = _tree(conn, action_id)
        statuses = [recovery_journal.lookup(conn, member)["status"] for member in tree]
        if "dispatching" in statuses:
            result["refused"].append({"id": action_id, "code": "still_running"})
            continue
        for member in tree:
            _blank_action(conn, member, by)
        _event(conn, "action_forgotten", "action", action_id, by,
               {"subject_type": row["subject_type"], "subject_id": row["subject_id"],
                "status": row["status"], "children": len(tree) - 1})
        result["forgotten"].append(action_id)
    return result


def forget(request_ids: list[str], action_ids: list[str], by: str, agent_id: str | None = None) -> dict:
    """Blank the named records in one transaction. `agent_id` limits it to that key's own
    records (another key's and unknown ids answer `unknown` alike); None is the admin's reach."""
    with control_plane._conn() as conn:
        journal.initialize(conn)
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT 1 FROM v2_recovery_hold").fetchone():
            raise RecoveryHeld("Recovery is held; nothing is forgotten until it is reconciled.")
        return {"requests": _requests(conn, request_ids, agent_id, by),
                "actions": _actions(conn, action_ids, agent_id, by)}
