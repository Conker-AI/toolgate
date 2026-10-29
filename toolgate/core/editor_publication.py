"""Bridge visual documents into the existing immutable automation registry."""
import hashlib
import json
import math
from typing import Annotated, Literal

from pydantic import Field

from . import control_plane as cp
from . import editor_drafts
from .editor_drafts import EditorDocument
from .editor_graph import validate_graph
from .owner_channel import OwnerError


def document_from_block(block):
    if set(block) != {"type", "document"} or block["type"] != "editor_graph":
        raise ValueError("Editor graph block requires only type and document.")
    document = EditorDocument.model_validate(block["document"])
    issues = validate_graph(document)
    if issues:
        raise ValueError(issues[0]["message"])
    # Credentials belong to the registered capability's runtime binding. A draft
    # cannot introduce a new vault binding merely by naming a connection.
    if document.credentialRefs:
        raise ValueError("Bind credentials on registered tools, not the editor graph.")
    return document


def dependency_steps(block):
    """All branches, including untaken paths, take part in publication review."""
    document = document_from_block(block)
    steps = []
    for node in document.nodes:
        config = node.config
        if node.type == "tool_call":
            steps.append({"type": "tool_call", "tool_id": config["tool"]})
        elif node.type == "workflow_call":
            steps.append({"type": "automation_call", "automation_id": config["toolId"],
                          "published_version": config["version"]})
        else:
            # Count computation nodes too, without treating their configuration
            # as the older structured-workflow language.
            steps.append({"type": "set"})
    return steps


class PublishDraft(editor_drafts.StrictDocument):
    expected_revision: Annotated[int, Field(ge=1)]
    expected_publication_version: Annotated[int, Field(ge=0)]
    authorization: Literal["auto", "owner_confirmation"] = "owner_confirmation"
    # "Let Conker use this tool": publish it visible to agents and grant the presenting key.
    conkerMayUse: bool = False


def automation_id(identity):
    # Stable opaque registry identity avoids case/underscore collisions in draft IDs.
    return "editor-" + hashlib.sha256(identity.encode()).hexdigest()[:32]


def definition(identity, document: EditorDocument, block, authorization):
    """The registry definition a publication of this document stores."""
    return {"id": identity, "name": document.name,
            "description": document.description or "Owner-authored visual workflow",
            "inputs": [item.model_dump(exclude_unset=True) for item in document.inputs],
            "workflow": [block], "authorization": authorization, "status": "active",
            "policy": cp.with_default_limits({"usage_limits": {"max_steps": document.budgets.maxSteps,
                "max_runtime_seconds": math.ceil(document.budgets.timeoutMs / 1000)}})}


def _table(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS v2_editor_publications (
        draft_id TEXT NOT NULL, revision INTEGER NOT NULL, automation_id TEXT NOT NULL,
        version INTEGER NOT NULL, authorization TEXT NOT NULL,
        PRIMARY KEY(draft_id,revision), UNIQUE(automation_id,version))""")


def history(identity):
    from . import publications
    editor_drafts.get(identity)
    with cp._conn() as conn:
        _table(conn)
        rows = conn.execute("SELECT * FROM v2_editor_publications WHERE draft_id=? ORDER BY revision DESC LIMIT 100",
                            (identity,)).fetchall()
        result = []
        for row in rows:
            saved = conn.execute("SELECT body FROM v2_publications WHERE kind='automation' AND id=? AND version=?",
                                 (row["automation_id"], row["version"])).fetchone()
            publication = json.loads(saved[0])
            try:
                publications.for_execution(conn, "automation", row["automation_id"], row["version"])
                available = True
            except publications.PublicationInvalid:
                available = False
            result.append({**dict(row), "digest": publication["digest"],
                           "published_at": publication["published_at"], "available": available})
        return result


def _let_conker_use(conn, publication, agent):
    from . import editor_runs
    if not publication["definition"]["workflow"][0]["document"].get("agentVisible"):
        raise OwnerError("publication_conflict", "This draft revision is already published without "
                         "Conker's access; save the draft again to publish it with access.", 409)
    if agent is None:
        raise OwnerError("execution_unavailable", "Send the chat's execution key to grant it access.", 401)
    editor_runs.change(conn, publication, editor_runs.caller_key(conn, agent), True)


def publish_draft(identity, payload: PublishDraft, *, validate, validate_tool, agent=None):
    """Publish the saved revision; with conkerMayUse, grant `agent`'s key in the same transaction."""
    from . import publications
    editor_drafts._identity(identity)
    registry_id = automation_id(identity)
    with cp._conn() as conn:
        editor_drafts._table(conn)
        _table(conn)
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM v2_editor_drafts WHERE id=?", (identity,)).fetchone()
        if not row:
            raise OwnerError("draft_not_found", "Editor draft not found.", 404)
        if row["revision"] != payload.expected_revision:
            raise OwnerError("draft_revision_conflict", "Draft changed; reload before publishing.", 409)
        previous = conn.execute("SELECT * FROM v2_editor_publications WHERE draft_id=? ORDER BY revision DESC LIMIT 1",
                                (identity,)).fetchone()
        if previous and previous["revision"] == payload.expected_revision:
            if previous["authorization"] != payload.authorization:
                raise OwnerError("publication_conflict", "This draft revision is already published with different authorization.", 409)
            saved = conn.execute("SELECT body FROM v2_publications WHERE kind='automation' AND id=? AND version=?",
                                 (registry_id, previous["version"])).fetchone()
            publication = json.loads(saved[0])
            if payload.conkerMayUse:
                _let_conker_use(conn, publication, agent)
            return publication
        latest_version = previous["version"] if previous else 0
        if latest_version != payload.expected_publication_version:
            raise OwnerError("publication_conflict", "Publication changed; reload before publishing.", 409)
        body = json.loads(row["body"])
        if payload.conkerMayUse:
            # Agents see a published workflow only when its document says so.
            body["agentVisible"] = True
        block = {"type": "editor_graph", "document": body}
        document = document_from_block(block)
        existing = conn.execute("SELECT * FROM v2_objects WHERE kind='automation' AND id=?", (registry_id,)).fetchone()
        if (previous and (not existing or cp._row(existing)["version"] != latest_version)) or (existing and not previous):
            raise OwnerError("publication_conflict", "Registry definition changed outside this editor; review it before publishing.", 409)
        stored = definition(registry_id, document, block, payload.authorization)
        validate(stored)
        saved = cp._put("automation", registry_id, stored,
                        expected_version=latest_version or None, connection=conn)
        publication = publications.publish("automation", registry_id, saved["version"],
                                            validate_tool=validate_tool, connection=conn)
        conn.execute("INSERT INTO v2_editor_publications VALUES(?,?,?,?,?)",
            (identity, payload.expected_revision, registry_id, saved["version"], payload.authorization))
        if payload.conkerMayUse:
            # Inside the publish transaction: a refused grant rolls the publication back too.
            _let_conker_use(conn, publication, agent)
        return publication
