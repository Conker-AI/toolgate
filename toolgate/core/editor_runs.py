"""Owner-reviewed editor grants and durable browser run identities.

The API requires both owner authority and a distinct execution credential. Runs
still enter run_automation, which enforces scopes, approval and dispatch journals.
"""
import json
import uuid
from typing import Annotated

from pydantic import Field, JsonValue, model_validator

from . import control_plane as cp
from . import editor_publication, publications
from . import execution_journal as journal
from .editor_drafts import StrictDocument, _identity
from .editor_values import bounded
from .owner_channel import OwnerError


class Target(StrictDocument):
    version: Annotated[int, Field(ge=1)]
    digest: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class Access(Target):
    enabled: bool


class Run(Target):
    action_id: Annotated[str, Field(pattern=r"^editor_[a-f0-9]{32}$")]
    args: dict[str, JsonValue] = Field(default_factory=dict)
    approval_request_id: Annotated[str, Field(max_length=100)] | None = None

    @model_validator(mode="after")
    def bounded_args(self):
        bounded(self.args)
        if len(json.dumps(self.args, ensure_ascii=False).encode('utf-8')) > 32768:
            raise ValueError('Workflow arguments exceed the owner review limit.')
        return self


def _table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS v2_editor_runs (
        action_id TEXT PRIMARY KEY, draft_id TEXT NOT NULL, actor_id TEXT NOT NULL,
        version INTEGER NOT NULL, digest TEXT NOT NULL, args TEXT NOT NULL,
        state TEXT NOT NULL, response TEXT, created_at TEXT NOT NULL)""")


def target(conn, identity, version, digest, *, available=True):
    _identity(identity)
    editor_publication._table(conn)
    row = conn.execute("SELECT automation_id FROM v2_editor_publications WHERE draft_id=? AND version=?",
                       (identity, version)).fetchone()
    if not row:
        raise OwnerError("publication_not_found", "This editor version is not published.", 404)
    if available:
        publication = publications.for_execution(conn, "automation", row[0], version)
    else:
        saved = conn.execute("SELECT body FROM v2_publications WHERE kind='automation' AND id=? AND version=?",
                             (row[0], version)).fetchone()
        publication = json.loads(saved[0])
    if publication["digest"] != digest:
        raise OwnerError("publication_conflict", "Publication digest does not match.", 409)
    return publication


def scopes(publication):
    return list(dict.fromkeys(f"automation:{member['id']}" for member in publications.members(publication)))


def access(identity, payload: Target, agent, *, enabled=None):
    with cp._conn() as conn:
        if enabled is not None:
            conn.execute("BEGIN IMMEDIATE")
        publication = target(conn, identity, payload.version, payload.digest, available=enabled is True)
        row = conn.execute("SELECT * FROM v2_agent_keys WHERE id=?", (agent["id"],)).fetchone()
        if not row or row["status"] != "active":
            raise OwnerError("execution_unavailable", "Execution credential is no longer active.", 403)
        caller = cp.public_agent_key(row)
        required = scopes(publication)
        if enabled is not None:
            # Remove only the root on revocation. Nested workflows may have their
            # own independent grants and other callers; never revoke those here.
            updated = list(dict.fromkeys([*caller["scopes"], *required])) if enabled else [s for s in caller["scopes"] if s != required[0]]
            if not enabled and cp.is_scoped({**caller, "scopes": updated}, required[0]):
                raise OwnerError("broad_execution_grant", "This caller has a broader grant; remove it through host administration first.", 409)
            conn.execute("UPDATE v2_agent_keys SET scopes=? WHERE id=?", (json.dumps(updated), agent["id"]))
            conn.execute("INSERT INTO v2_events VALUES(?,?,?,?,?,?,?,?)", (uuid.uuid4().hex,
                "editor_access_granted" if enabled else "editor_access_revoked", "warning", "automation",
                publication["id"], "owner", json.dumps({"actor_id": agent["id"], "scopes": required}), cp._now()))
            caller["scopes"] = updated
        return {"actor_id": caller["id"], "actor_name": caller["name"], "automation_id": publication["id"],
                "enabled": all(cp.is_scoped(caller, scope) for scope in required), "required_scopes": required}


def _response(row):
    record = journal.get(row["action_id"])
    if record:
        return journal.response(record)
    if row["response"]:
        return json.loads(row["response"])
    return {"action_id": row["action_id"], "code": "OUTCOME_UNKNOWN",
            "message": "The run request is recorded; its outcome is not yet confirmed. Do not repeat it."}


def begin(identity, payload: Run, agent):
    args = json.dumps(payload.args, sort_keys=True, separators=(",", ":"), allow_nan=False)
    with cp._conn() as conn:
        _table(conn)
        conn.execute("BEGIN IMMEDIATE")
        publication = target(conn, identity, payload.version, payload.digest)
        row = conn.execute("SELECT * FROM v2_editor_runs WHERE action_id=?", (payload.action_id,)).fetchone()
        if row:
            if (row["draft_id"], row["actor_id"], row["version"], row["digest"], row["args"]) != (
                    identity, agent["id"], payload.version, payload.digest, args):
                raise OwnerError("run_conflict", "Run identity already belongs to a different request.", 409)
            response = json.loads(row["response"]) if row["response"] else {}
            if not (row["state"] == "approval" and payload.approval_request_id
                    and payload.approval_request_id == response.get("request_id")):
                return publication, dict(row), False
            conn.execute("UPDATE v2_editor_runs SET state='held',response=NULL WHERE action_id=?", (payload.action_id,))
        else:
            if payload.approval_request_id:
                raise OwnerError("invalid_run_approval", "Start this run before attaching an approval.", 422)
            conn.execute("INSERT INTO v2_editor_runs VALUES(?,?,?,?,?,?,'held',NULL,?)",
                         (payload.action_id, identity, agent["id"], payload.version, payload.digest, args, cp._now()))
        return publication, None, True


def finish(action_id, response):
    with cp._conn() as conn:
        conn.execute("UPDATE v2_editor_runs SET state=?,response=? WHERE action_id=?",
                     ("approval" if response.get("code") == "CONFIRMATION_REQUIRED" else "finished",
                      json.dumps(response, allow_nan=False), action_id))
    return response


def history(identity, agent):
    _identity(identity)
    with cp._conn() as conn:
        _table(conn)
        rows = [dict(row) for row in conn.execute(
            "SELECT * FROM v2_editor_runs WHERE draft_id=? AND actor_id=? ORDER BY created_at DESC LIMIT 30",
            (identity, agent["id"]))]
    return {"items": [{"action_id": row["action_id"], "version": row["version"], "digest": row["digest"],
                       "created_at": row["created_at"], "args": json.loads(row["args"]),
                       "response": _response(row)} for row in rows]}
