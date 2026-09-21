"""Immutable owner publications. Definitions contain references, never resolved secrets."""
from __future__ import annotations

import hashlib
import json
import uuid

from toolgate.core import control_plane as cp


class PublicationInvalid(ValueError):
    pass


def _kind(kind: str) -> None:
    if kind not in {"tool", "automation"}:
        raise ValueError("Only tools and automations have definition versions")


def digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def get(kind: str, obj_id: str, version: int, *, published: bool = False) -> dict | None:
    _kind(kind)
    table = "v2_publications" if published else "v2_definition_versions"
    with cp._conn() as conn:
        row = conn.execute(f"SELECT body FROM {table} WHERE kind=? AND id=? AND version=?",
                           (kind, obj_id, version)).fetchone()
        if row:
            return json.loads(row["body"])
        if not published:
            current = conn.execute("SELECT * FROM v2_objects WHERE kind=? AND id=?", (kind, obj_id)).fetchone()
            if current and cp._row(current).get("version", 1) == version:
                return cp._row(current)
    return None


def history(kind: str, obj_id: str) -> list[dict]:
    _kind(kind)
    with cp._conn() as conn:
        rows = conn.execute("SELECT version,body FROM v2_definition_versions WHERE kind=? AND id=? ORDER BY version DESC",
                            (kind, obj_id)).fetchall()
        definitions = {row["version"]: json.loads(row["body"]) for row in rows}
        current = conn.execute("SELECT * FROM v2_objects WHERE kind=? AND id=?", (kind, obj_id)).fetchone()
        if current:
            definition = cp._row(current)
            definitions.setdefault(definition.get("version", 1), definition)
        published = {row["version"]: json.loads(row["body"]) for row in conn.execute(
            "SELECT version,body FROM v2_publications WHERE kind=? AND id=?", (kind, obj_id))}
    return [{"version": version, "name": definition.get("name", obj_id),
             "updated_at": definition.get("updated_at"), "published": version in published,
             "published_at": published.get(version, {}).get("published_at")}
            for version, definition in sorted(definitions.items(), reverse=True)]


def for_execution(conn, kind: str, obj_id: str, version: int) -> dict:
    """Resolve only the requested publication and enforce current owner revocations."""
    _kind(kind)
    row = conn.execute("SELECT body FROM v2_publications WHERE kind=? AND id=? AND version=?",
                       (kind, obj_id, version)).fetchone()
    if not row:
        raise PublicationInvalid("The exact published version was not found")
    publication = json.loads(row["body"])
    graph_limits(publication)
    subjects = []
    for member in members(publication):
        subjects.append((member["kind"], member["definition"]))
        subjects.extend(("tool", tool) for tool in member["tools"].values())
    for subject_kind, saved in subjects:
        current_row = conn.execute("SELECT * FROM v2_objects WHERE kind=? AND id=?",
                                   (subject_kind, saved["id"])).fetchone()
        current = cp._row(current_row) if current_row else None
        if (not current or current.get("status") != "active"
                or current.get("created_at") != saved.get("created_at")
                or current.get("authorization") == "blocked"
                or current.get("authorization") != saved.get("authorization")
                or current.get("policy") != saved.get("policy")):
            raise PublicationInvalid(f"Published dependency '{saved['id']}' is revoked or its owner policy changed")
    return publication


def nested_key(step: dict) -> str:
    identity, version = step.get("automation_id"), step.get("published_version")
    if not isinstance(identity, str) or not identity or type(version) is not int or version < 1:
        raise PublicationInvalid("automation_call requires a literal automation_id and positive published_version")
    return f"{identity}@{version}"


def members(publication: dict):
    yield publication
    for child in publication.get("automations", {}).values():
        yield from members(child)


def automation_bindings(publication: dict) -> dict:
    return {f"{child['id']}@{child['version']}": {"version": child["version"], "digest": child["digest"]}
            for child in list(members(publication))[1:]}


def graph_limits(publication: dict) -> None:
    """Bound the expanded source graph, counting repeated calls and all branches."""
    count = 0
    def visit(current, steps, depth, ancestors):
        nonlocal count
        if not isinstance(steps, list) or depth > 4:
            raise PublicationInvalid("Expanded workflow nesting cannot exceed four levels")
        for step in steps:
            count += 1
            if count > 500 or not isinstance(step, dict):
                raise PublicationInvalid("Expanded workflow cannot exceed 500 typed blocks")
            kind = step.get("type")
            if kind == "automation_call":
                child = current.get("automations", {}).get(nested_key(step))
                if not child or step.get("publication_digest", child["digest"]) != child["digest"]:
                    raise PublicationInvalid("Nested publication is unavailable or its digest does not match")
                if child["id"] in ancestors:
                    raise PublicationInvalid("Automation dependency cycles are not supported, including across revisions")
                visit(child, child["definition"].get("workflow", []), depth + 1, (*ancestors, child["id"]))
            elif kind == "condition":
                visit(current, step.get("then", []), depth + 1, ancestors)
                visit(current, step.get("else", []), depth + 1, ancestors)
            elif kind == "switch":
                for branch in step.get("cases", {}).values():
                    visit(current, branch, depth + 1, ancestors)
                visit(current, step.get("default", []), depth + 1, ancestors)
            elif kind == "loop":
                visit(current, step.get("steps", []), depth + 1, ancestors)
            elif kind == "retry":
                visit(current, [step.get("step")], depth + 1, ancestors)
    visit(publication, publication["definition"].get("workflow", []), 0, (publication["id"],))


def dependencies(conn, definition: dict) -> tuple[dict, dict]:
    """Visit every possible branch, bounded independently of runtime control flow."""
    tools = {}
    automations = {}
    count = 0

    def visit(steps, depth=0):
        nonlocal count
        if not isinstance(steps, list) or depth > 4:
            raise PublicationInvalid("Workflow must be a list with at most four nested levels")
        for step in steps:
            count += 1
            if count > 500 or not isinstance(step, dict):
                raise PublicationInvalid("Workflow must contain at most 500 typed blocks")
            kind = step.get("type")
            if kind == "tool_call":
                tool_id = step.get("tool_id")
                if not isinstance(tool_id, str):
                    raise PublicationInvalid("Tool calls require a literal tool_id")
                row = conn.execute("SELECT * FROM v2_objects WHERE kind='tool' AND id=?", (tool_id,)).fetchone()
                tool = cp._row(row) if row else None
                if not tool or tool.get("status") != "active" or tool.get("authorization") == "blocked":
                    raise PublicationInvalid(f"Dependency '{tool_id}' is unavailable")
                requested = step.get("tool_version")
                if requested is not None and (type(requested) is not int or requested != tool.get("version")):
                    raise PublicationInvalid(f"Dependency '{tool_id}' does not match its requested version")
                if definition.get("authorization", "auto") == "auto" and tool.get("authorization", "auto") != "auto":
                    raise PublicationInvalid(f"Dependency '{tool_id}' requires owner confirmation")
                tools[tool_id] = tool
            elif kind == "automation_call":
                key = nested_key(step)
                child = for_execution(conn, "automation", step["automation_id"], step["published_version"])
                if step.get("publication_digest", child["digest"]) != child["digest"]:
                    raise PublicationInvalid("Nested publication digest does not match")
                if definition.get("authorization", "auto") == "auto" and child["definition"].get("authorization", "auto") != "auto":
                    raise PublicationInvalid("Nested publication requires owner confirmation on the root")
                automations[key] = child
            elif kind == "condition":
                visit(step.get("then", []), depth + 1)
                visit(step.get("else", []), depth + 1)
            elif kind == "switch":
                cases = step.get("cases", {})
                if not isinstance(cases, dict) or len(cases) > 10:
                    raise PublicationInvalid("Switch must have at most ten cases")
                for branch in cases.values():
                    visit(branch, depth + 1)
                visit(step.get("default", []), depth + 1)
            elif kind == "loop":
                visit(step.get("steps", []), depth + 1)
            elif kind == "retry":
                visit([step.get("step")], depth + 1)
            elif kind not in {"set", "calculation", "delay", "notification", "return"}:
                raise PublicationInvalid("Unsupported workflow block")

    visit(definition.get("workflow", []))
    return tools, automations


def publish(kind: str, obj_id: str, expected_version: int, *, validate=None, validate_tool=None) -> dict | None:
    _kind(kind)
    if type(expected_version) is not int or expected_version < 1:
        raise ValueError("expected_version must be a positive integer")
    with cp._conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM v2_objects WHERE kind=? AND id=?", (kind, obj_id)).fetchone()
        if not row:
            return None
        definition = cp._row(row)
        if definition.get("version", 1) != expected_version:
            raise cp.DefinitionConflict(definition.get("version", 1))
        old = conn.execute("SELECT body FROM v2_publications WHERE kind=? AND id=? AND version=?",
                           (kind, obj_id, expected_version)).fetchone()
        if old:
            return json.loads(old["body"])
        if definition.get("status") != "active" or definition.get("authorization") == "blocked":
            raise PublicationInvalid("Only active, unblocked definitions can be published")
        tools, automations = dependencies(conn, definition) if kind == "automation" else ({}, {})
        if validate_tool:
            for tool in tools.values():
                validate_tool(tool)
        snapshot = {"kind": kind, "id": obj_id, "version": expected_version,
                    "definition": definition, "tools": tools}
        if automations:
            snapshot["automations"] = automations
        graph_limits(snapshot)
        if validate:
            validate(definition)
        result = {**snapshot, "digest": digest(snapshot), "published_at": cp._now()}
        cp.retain_definition(conn, kind, definition)
        conn.execute("INSERT INTO v2_publications VALUES(?,?,?,?)",
                     (kind, obj_id, expected_version, json.dumps(result)))
        conn.execute("INSERT INTO v2_events VALUES(?,?,?,?,?,?,?,?)",
                     (uuid.uuid4().hex, "definition_published", "info", kind, obj_id, "admin",
                      json.dumps({"version": expected_version, "digest": result["digest"]}), result["published_at"]))
        return result
