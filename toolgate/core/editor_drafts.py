"""Durable owner editor documents. Drafts confer no execution authority."""
from __future__ import annotations

import json
import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from . import control_plane as cp
from .owner_channel import OwnerError

Identifier = Annotated[str, Field(pattern=r"^[a-zA-Z][a-zA-Z0-9_-]{0,63}$")]


class StrictDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class Position(StrictDocument):
    x: float
    y: float


class Node(StrictDocument):
    id: Identifier
    type: Literal["input", "tool_call", "workflow_call", "set", "calculation", "condition", "loop", "return"]
    label: Annotated[str, Field(min_length=1, max_length=100)]
    position: Position
    config: dict[str, JsonValue]


class Edge(StrictDocument):
    id: Identifier
    source: Identifier
    target: Identifier
    branch: Literal["true", "false"] | None = None


class ToolField(StrictDocument):
    name: Identifier
    type: Literal["string", "number", "boolean", "array", "object"]
    required: bool
    description: Annotated[str, Field(max_length=500)] | None = None
    default: JsonValue = None


class Budgets(StrictDocument):
    maxSteps: Annotated[int, Field(ge=2, le=200)]
    maxLoopItems: Annotated[int, Field(ge=1, le=50)]
    timeoutMs: Annotated[int, Field(ge=100, le=30000)]


class EditorDocument(StrictDocument):
    id: Identifier
    name: Annotated[str, Field(min_length=1, max_length=100)]
    description: Annotated[str, Field(max_length=2000)]
    kind: Literal["connector", "workflow"]
    nodes: Annotated[list[Node], Field(min_length=2, max_length=60)]
    edges: Annotated[list[Edge], Field(max_length=120)]
    inputs: Annotated[list[ToolField], Field(max_length=30)]
    outputs: Annotated[list[ToolField], Field(max_length=30)]
    credentialRefs: Annotated[list[Annotated[str, Field(pattern=r"^connection:[a-zA-Z][a-zA-Z0-9_-]{0,63}$")]], Field(max_length=20)]
    effect: Literal["read", "prepare", "write"]
    agentVisible: bool
    budgets: Budgets

    @model_validator(mode="after")
    def bounded_document(self):
        if not self.name.strip():
            raise ValueError("Give the draft a name")
        body = self.model_dump(exclude_unset=True)
        # Bounds apply to drafts too, even before graph/execution validation.
        pending = [(body, 0)]
        count = 0
        while pending:
            value, depth = pending.pop()
            count += 1
            if count > 12000 or depth > 20:
                raise ValueError("Draft structure exceeds its limit")
            if isinstance(value, dict):
                pending.extend((child, depth + 1) for child in value.values())
            elif isinstance(value, list):
                pending.extend((child, depth + 1) for child in value)
        if len(json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")) > 150000:
            raise ValueError("Draft exceeds 150000 bytes")
        return self


class SaveDraft(StrictDocument):
    expected_revision: Annotated[int, Field(ge=0)]
    document: EditorDocument


def _identity(identity):
    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,63}", identity):
        raise OwnerError("invalid_draft_id", "Invalid editor draft identity.", 422)


def _table(db):
    db.execute("""CREATE TABLE IF NOT EXISTS v2_editor_drafts (
        id TEXT PRIMARY KEY, revision INTEGER NOT NULL, body TEXT NOT NULL,
        updated_at TEXT NOT NULL)""")


def _record(row):
    return {"id": row["id"], "revision": row["revision"], "updated_at": row["updated_at"],
            "document": json.loads(row["body"])}


def get(identity):
    _identity(identity)
    with cp._conn() as db:
        _table(db)
        row = db.execute("SELECT * FROM v2_editor_drafts WHERE id=?", (identity,)).fetchone()
        if row is None:
            raise OwnerError("draft_not_found", "Editor draft not found.", 404)
        return _record(row)


def list_drafts(limit=50, after=None):
    if after is not None:
        _identity(after)
    with cp._conn() as db:
        _table(db)
        rows = db.execute("SELECT * FROM v2_editor_drafts WHERE id>? ORDER BY id LIMIT ?",
                          (after or "", limit + 1)).fetchall()
        items = []
        for row in rows[:limit]:
            document = json.loads(row["body"])
            items.append({"id": row["id"], "revision": row["revision"],
                          "updated_at": row["updated_at"], "name": document["name"],
                          "kind": document["kind"]})
        return {"items": items, "next_after": items[-1]["id"] if len(rows) > limit else None}


def save(identity, payload: SaveDraft):
    _identity(identity)
    if payload.document.id != identity:
        raise OwnerError("draft_id_mismatch", "Document identity differs from its route.", 422)
    body = json.dumps(payload.document.model_dump(exclude_unset=True), ensure_ascii=False, allow_nan=False)
    with cp._conn() as db:
        _table(db)
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT revision FROM v2_editor_drafts WHERE id=?", (identity,)).fetchone()
        revision = row["revision"] if row else 0
        if revision != payload.expected_revision:
            raise OwnerError("draft_revision_conflict", "Draft changed; reload before saving.", 409)
        now = cp._now()
        db.execute("INSERT INTO v2_editor_drafts VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                   "revision=excluded.revision, body=excluded.body, updated_at=excluded.updated_at",
                   (identity, revision + 1, body, now))
        return {"id": identity, "revision": revision + 1, "updated_at": now,
                "document": json.loads(body)}
