"""Owner-reviewed MCP imports; discovery and publication never grant execution scopes."""

from __future__ import annotations

import json
import re
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field

from toolgate.executors import mcp_http

from . import control_plane as cp
from . import mcp_observe, publications, tool_access
from .owner_channel import OwnerError


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Discover(StrictRequest):
    url: str = Field(min_length=1, max_length=2048)
    secret_ref: str | None = Field(default=None, max_length=100)


class Import(Discover):
    id: str = Field(pattern=r"^mcp[.][a-z0-9][a-z0-9.-]{1,74}$")
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=4000)
    tool_name: str = Field(min_length=1, max_length=128)
    input_schema: dict
    schema_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class State(StrictRequest):
    enabled: bool
    expected_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReadClass(StrictRequest):
    """Observe (runs without asking) or Act outward (asks for every exact call), for the exact
    tool version the owner saw. Pi's gateway asks his password for Observe (ADR-0010)."""

    read_class: Literal["observe", "act_outward"]
    expected_version: int = Field(ge=1)


def projection(tool):
    execution = tool["execution"]
    return {
        "id": tool["id"],
        "name": tool["name"],
        "description": tool["description"],
        "status": tool["status"],
        "authorization": tool["authorization"],
        "url": execution["url"],
        "tool_name": execution["tool_name"],
        "schema_hash": execution["schema_hash"],
        "secret_ref": execution.get("secret_ref"),
        "read_class": mcp_observe.stated(tool),
        "version": tool["version"],
        "digest": publications.digest(tool),
    }


def list_tools():
    with cp._conn() as conn:
        rows = conn.execute(
            "SELECT * FROM v2_objects WHERE kind='tool' AND id LIKE 'mcp.%' ORDER BY id LIMIT 201"
        ).fetchall()
        if len(rows) > 200:
            raise OwnerError(
                "catalogue_limit", "The imported MCP catalogue exceeds 200 tools.", 409
            )
        values = [cp._row(row) for row in rows]
    return {
        "schemaVersion": 1,
        "tools": [
            projection(tool)
            for tool in values
            if tool.get("execution", {}).get("type") == "mcp_http"
        ],
    }


def import_tool(payload: Import, validate):
    execution = {
        "type": "mcp_http",
        "url": payload.url,
        "tool_name": payload.tool_name,
        "input_schema": payload.input_schema,
        "schema_hash": payload.schema_hash,
        "secret_ref": payload.secret_ref,
    }
    mcp_http.validate_execution(execution)
    discovered = mcp_http.discover(payload.url, payload.secret_ref)
    mcp_observe.notice(payload.url, payload.secret_ref, discovered)
    mcp_http.require_match(discovered["tools"], execution, discovered.get("unsupportedTools", []))
    body = {
        "id": payload.id,
        "name": payload.name.strip(),
        "description": payload.description.strip(),
        "category": "external-mcp",
        "authorization": "owner_confirmation",
        "status": "active",
        "inputs": [
            {
                "name": "arguments",
                "type": "object",
                "required": True,
                "description": "JSON arguments matching the imported MCP schema: "
                + json.dumps(payload.input_schema, separators=(",", ":"), ensure_ascii=False),
            }
        ],
        "outputs": [],
        "execution": execution,
        "policy": cp.with_default_limits({}),
    }
    validate(body)
    with cp._conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if (
            conn.execute(
                "SELECT 1 FROM v2_objects WHERE kind='tool' AND id=?", (payload.id,)
            ).fetchone()
            or conn.execute(
                "SELECT 1 FROM v2_definition_versions WHERE kind='tool' AND id=?", (payload.id,)
            ).fetchone()
        ):
            raise OwnerError(
                "import_conflict", "This tool ID was already used; choose a new MCP ID.", 409
            )
        if (
            conn.execute(
                "SELECT COUNT(*) FROM v2_objects WHERE kind='tool' AND id LIKE 'mcp.%'"
            ).fetchone()[0]
            >= 200
        ):
            raise OwnerError(
                "catalogue_limit", "At most 200 MCP tool definitions may be imported.", 409
            )
        saved = cp._put("tool", payload.id, body, connection=conn)
        publications.publish(
            "tool", payload.id, saved["version"], validate=validate, connection=conn
        )
    cp.event(
        "mcp_tool_imported",
        "info",
        "tool",
        payload.id,
        "owner",
        {"schema_hash": payload.schema_hash},
    )
    return {"schemaVersion": 1, "tool": projection(saved)}


def set_state(identity, payload: State, validate):
    if not re.fullmatch(r"mcp[.][a-z0-9][a-z0-9.-]{1,74}", identity):
        raise OwnerError("mcp_tool_not_found", "Imported MCP tool not found.", 404)
    with cp._conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM v2_objects WHERE kind='tool' AND id=?", (identity,)
        ).fetchone()
        tool = cp._row(row) if row else None
        if not tool or tool.get("execution", {}).get("type") != "mcp_http":
            raise OwnerError("mcp_tool_not_found", "Imported MCP tool not found.", 404)
        if publications.digest(tool) != payload.expected_digest:
            raise OwnerError(
                "definition_conflict",
                "The MCP tool changed; reload before changing its state.",
                409,
            )
        status = "active" if payload.enabled else "disabled"
        if tool["status"] == status:
            return {"schemaVersion": 1, "tool": projection(tool)}
        body = {
            key: value for key, value in tool.items() if key not in {"created_at", "updated_at"}
        }
        body["status"] = status
        validate(body)
        saved = cp._put("tool", identity, body, expected_version=tool["version"], connection=conn)
        if payload.enabled:
            publications.publish(
                "tool", identity, saved["version"], validate=validate, connection=conn
            )
    cp.event(
        "mcp_tool_enabled" if payload.enabled else "mcp_tool_disabled",
        "info",
        "tool",
        identity,
        "owner",
    )
    return {"schemaVersion": 1, "tool": projection(saved)}


def _stored_tool(conn, identity):
    row = conn.execute(
        "SELECT * FROM v2_objects WHERE kind='tool' AND id=?", (identity,)
    ).fetchone()
    return cp._row(row) if row else None


def _confirmable(identity, payload: ReadClass, not_found):
    """Before his Observe is saved, and outside the write transaction: the names read, and the
    server still advertises this exact tool and schema, with annotations (if it gives any) that
    say read-only. Without annotations the names must have the short shape (get_weather); the
    server's read-only hint allows longer ones. Returns what Observe binds: the execution, the
    advert hash and whether the read-only hint was given."""
    with cp._conn() as conn:
        tool = _stored_tool(conn, identity)
    execution = mcp_observe.bound(tool.get("execution")) if tool else None
    if not tool or execution is None:
        raise not_found
    if tool["version"] != payload.expected_version:
        raise OwnerError("definition_conflict", "The MCP tool changed; reload it first.", 409)
    names = (identity, tool.get("name"), execution["tool_name"])
    refused = OwnerError(
        "act_outward_name",
        "Only a tool named like get_weather or list_emails (or longer, when its server says it "
        "is read-only) and saying nothing that acts can run without asking.",
        422,
    )
    # Names that act even with the server's read-only hint are refused before it is asked.
    if any(mcp_observe.says_act_outward(name, True) for name in names):
        raise refused
    discovered = mcp_http.discover(execution["url"], execution["secret_ref"])
    mcp_observe.notice(execution["url"], execution["secret_ref"], discovered)
    mcp_http.require_match(discovered["tools"], execution, discovered.get("unsupportedTools", []))
    (advertised,) = [item for item in discovered["tools"] if item["name"] == execution["tool_name"]]
    if mcp_observe.hints_act(advertised.get("annotations")):
        raise OwnerError(
            "act_outward_hint",
            "The server's annotations do not say this tool is read-only, so it always asks.",
            422,
        )
    read_only_hint = advertised.get("annotations") is not None
    if mcp_observe.names_act(names, read_only_hint):
        raise refused
    return execution, advertised["advertHash"], read_only_hint


def set_class(identity, payload: ReadClass):
    """Mark one imported tool Observe or Act outward. Observe is refused unless the names read,
    the server's annotations (if any) say read-only and it still advertises the tool as imported;
    a stale version is refused; the change is its own audited version."""
    not_found = OwnerError("mcp_tool_not_found", "Imported MCP tool not found.", 404)
    if not mcp_observe.MCP_ID.fullmatch(identity):
        raise not_found
    observe = payload.read_class == mcp_observe.OBSERVE
    confirmable = _confirmable(identity, payload, not_found) if observe else None
    with cp._conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        tool = _stored_tool(conn, identity)
        execution = mcp_observe.bound(tool.get("execution")) if tool else None
        if not tool or execution is None:
            raise not_found
        if tool.get("version") != payload.expected_version:
            raise OwnerError(
                "definition_conflict",
                "The MCP tool changed; reload before changing its class.",
                409,
            )
        if confirmable is not None:
            confirmed, advert_hash, read_only_hint = confirmable
            if confirmed != execution:
                raise OwnerError(
                    "definition_conflict", "The MCP tool changed; reload it first.", 409
                )
            read_class = {
                "class": mcp_observe.OBSERVE,
                **execution,
                "advert_hash": advert_hash,
                "read_only_hint": read_only_hint,
            }
        else:
            read_class = {"class": mcp_observe.ACT_OUTWARD}
        if tool.get("read_class", {"class": mcp_observe.ACT_OUTWARD}) == read_class:
            return {"schemaVersion": 1, "tool": projection(tool)}
        saved = mcp_observe.save(conn, tool, read_class)
        # In the same transaction: the class never changes without its audit event.
        cp.event(
            "mcp_class_changed",
            "warning",
            "tool",
            identity,
            "owner",
            {"read_class": payload.read_class, "version": saved["version"]},
            connection=conn,
        )
    return {"schemaVersion": 1, "tool": projection(saved)}


def access(identity, agent, payload: State | None = None):
    def not_found():
        return OwnerError("mcp_tool_not_found", "Imported MCP tool not found.", 404)

    if not re.fullmatch(r"mcp[.][a-z0-9][a-z0-9.-]{1,74}", identity):
        raise not_found()
    return tool_access.access(
        identity,
        agent,
        cast("tool_access.State | None", payload),
        accept=lambda tool: tool.get("execution", {}).get("type") == "mcp_http",
        not_found=not_found,
        event_prefix="mcp_access",
    )
