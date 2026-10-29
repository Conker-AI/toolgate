"""Read-only check of one editor document against the rules publishing applies.

Pi's drafter checks a draft before the owner sees it. Nothing is saved, granted or run: the check
only reads tools and publications. Rules that depend on the owner's choice at publish time (the
"auto" authorization) are left to publishing.
"""

from __future__ import annotations

import re

from pydantic import JsonValue, ValidationError

from . import control_plane as cp
from . import editor_publication, publications
from .editor_drafts import EditorDocument, StrictDocument
from .editor_graph import validate_graph

ISSUE_LIMIT = 50
NODE_ID = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{0,63}")


class Check(StrictDocument):
    document: dict[str, JsonValue]


def _issue(code, message, node_id=None):
    return {"code": code, "message": message, "nodeId": node_id}


def _shape_issues(raw, error: ValidationError):
    nodes = raw.get("nodes") if isinstance(raw.get("nodes"), list) else []
    issues = []
    for item in error.errors(include_url=False, include_input=False):
        loc = item["loc"]
        node_id = None
        if len(loc) > 1 and loc[0] == "nodes" and isinstance(loc[1], int) and loc[1] < len(nodes):
            node = nodes[loc[1]]
            candidate = node.get("id") if isinstance(node, dict) else None
            if isinstance(candidate, str) and NODE_ID.fullmatch(candidate):
                node_id = candidate
        message = item["msg"].removeprefix("Value error, ")
        path = ".".join(str(part) for part in loc)
        issues.append(
            _issue("invalid_document", f"{path}: {message}" if path else message, node_id)
        )
    return issues


def _capability_issues(conn, document: EditorDocument, tool_errors):
    """Every tool_call names an active tool; every workflow_call an available publication."""
    issues, automations = [], {}
    for node in document.nodes:
        config = node.config
        if node.type == "tool_call":
            tool_id = config.get("tool")
            if not isinstance(tool_id, str) or not tool_id or tool_id.startswith("$"):
                continue  # The graph check already names this step.
            row = conn.execute(
                "SELECT * FROM v2_objects WHERE kind='tool' AND id=?", (tool_id,)
            ).fetchone()
            tool = cp._row(row) if row else None
            if not tool or tool.get("status") != "active" or tool.get("authorization") == "blocked":
                issues.append(
                    _issue(
                        "tool_unavailable",
                        f"Tool '{tool_id[:80]}' does not exist or is not active.",
                        node.id,
                    )
                )
            elif tool_errors(tool):
                issues.append(
                    _issue(
                        "tool_invalid",
                        f"Tool '{tool_id[:80]}' has an incomplete definition; the owner must fix it "
                        "before a workflow can use it.",
                        node.id,
                    )
                )
        elif node.type == "workflow_call":
            target, version = config.get("toolId"), config.get("version")
            if (
                not isinstance(target, str)
                or not target
                or target.startswith("$")
                or type(version) is not int
                or version < 1
            ):
                continue
            try:
                automations[f"{target}@{version}"] = publications.for_execution(
                    conn, "automation", target, version
                )
            except publications.PublicationInvalid:
                issues.append(
                    _issue(
                        "workflow_unavailable",
                        f"Workflow '{target[:80]}' version {version} is not published, or a tool it "
                        "uses was revoked.",
                        node.id,
                    )
                )
    return issues, automations


def check(raw: dict, *, metadata_errors, tool_errors) -> dict:
    """`metadata_errors(definition)` and `tool_errors(tool)` are the validators publishing uses."""
    try:
        document = EditorDocument.model_validate(raw)
    except ValidationError as exc:
        issues = _shape_issues(raw, exc)
        return {"valid": False, "issues": issues[:ISSUE_LIMIT]}
    issues = [
        _issue("invalid_graph", item["message"], item["node_id"])
        for item in validate_graph(document)
    ]
    if document.credentialRefs:
        issues.append(
            _issue(
                "credentials_not_allowed",
                "Bind credentials on registered tools, not the editor graph.",
            )
        )
    identity = editor_publication.automation_id(document.id)
    block = {"type": "editor_graph", "document": document.model_dump(exclude_unset=True)}
    definition = editor_publication.definition(identity, document, block, "owner_confirmation")
    issues.extend(_issue("invalid_definition", message) for message in metadata_errors(definition))
    with cp._conn() as conn:
        conn.execute("BEGIN")  # One consistent read; nothing is written.
        found, automations = _capability_issues(conn, document, tool_errors)
        issues.extend(found)
        if not issues:
            # The expanded size, nesting and cycle limits publishing enforces.
            snapshot = {"id": identity, "definition": definition}
            if automations:
                snapshot["automations"] = automations
            try:
                publications.graph_limits(snapshot)
            except publications.PublicationInvalid as exc:
                issues.append(_issue("workflow_limit", str(exc)))
    return {"valid": not issues, "issues": issues[:ISSUE_LIMIT]}
