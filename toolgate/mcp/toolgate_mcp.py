#!/usr/bin/env python3
"""Opt-in stdio transport for the authenticated ToolGate HTTP execution API.

No database, vault, admin credential, or in-process execution access belongs in
this process. Each request is authenticated again by ToolGate, so revocation and
scope changes take effect without restarting a client.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

SERVER_NAME = "toolgate"
SERVER_VERSION = "0.9.0"


def _request(method: str, path: str, body: dict | None = None) -> Any:
    key = os.environ.get("TOOLGATE_EXECUTION_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "Set TOOLGATE_EXECUTION_KEY to a scoped agent key before starting MCP"
        )
    base = os.environ.get("TOOLGATE_URL", "http://127.0.0.1:8010").rstrip("/")
    url = urlsplit(base)
    if (
        url.scheme not in {"http", "https"}
        or not url.hostname
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.path not in {"", "/"}
        or (
            url.scheme == "http"
            and url.hostname not in {"localhost", "127.0.0.1", "::1"}
        )
    ):
        raise RuntimeError("Set TOOLGATE_URL to an HTTPS origin, or HTTP on loopback")
    try:
        # Redirects and environment proxies must never receive the execution key.
        with httpx.Client(
            follow_redirects=False, trust_env=False, timeout=300
        ) as client:
            response = client.request(
                method,
                base + path,
                json=body,
                headers={"X-ToolGate-Execution-Key": key},
            )
        if response.is_redirect:
            raise RuntimeError(
                "ToolGate redirected the request; set TOOLGATE_URL to its direct origin"
            )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        try:
            detail = exc.response.json().get("detail")
        except ValueError:
            detail = None
        raise RuntimeError(
            json.dumps(
                {
                    "status": exc.response.status_code,
                    "detail": detail,
                    "next_action": "Check the scoped key and ToolGate request status before retrying",
                }
            )
        ) from None
    except (httpx.HTTPError, ValueError):
        # A timeout can follow a completed action. This transport never retries.
        raise RuntimeError(
            "ToolGate response unavailable; outcome may be unknown. Check its execution records before retrying"
        ) from None


def _json_type(field_type: str) -> str:
    return (
        field_type
        if field_type in {"string", "integer", "number", "boolean", "array", "object"}
        else "string"
    )


def _mcp_tool_name(tool_id: str) -> str:
    """Return a broad-client-compatible MCP name while preserving ToolGate IDs internally."""
    name = re.sub(r"[^A-Za-z0-9_-]", "_", tool_id).strip("_") or "toolgate_tool"
    if not re.match(r"^[A-Za-z_]", name):
        name = f"tool_{name}"
    suffix = hashlib.sha256(tool_id.encode("utf-8")).hexdigest()[:12]
    name = f"{name[:51]}_{suffix}"
    return name


def _schema_for_field(field: dict) -> dict:
    schema: dict[str, Any] = {"type": _json_type(str(field.get("type", "string")))}
    if field.get("description"):
        schema["description"] = field["description"]
    if "default" in field:
        schema["default"] = field["default"]
    if field.get("allowed_values"):
        schema["enum"] = list(field["allowed_values"])
    if schema["type"] == "string":
        if field.get("min_length") is not None:
            schema["minLength"] = field["min_length"]
        if field.get("max_length") is not None:
            schema["maxLength"] = field["max_length"]
        if field.get("pattern"):
            schema["pattern"] = field["pattern"]
    if schema["type"] in {"integer", "number"}:
        if field.get("minimum") is not None:
            schema["minimum"] = field["minimum"]
        if field.get("maximum") is not None:
            schema["maximum"] = field["maximum"]
    if schema["type"] == "array":
        item_schema: dict[str, Any] = {}
        if field.get("item_type"):
            item_schema["type"] = _json_type(str(field["item_type"]))
        if field.get("item_pattern"):
            item_schema["pattern"] = field["item_pattern"]
        if item_schema:
            schema["items"] = item_schema
        if field.get("min_items") is not None:
            schema["minItems"] = field["min_items"]
        if field.get("max_items") is not None:
            schema["maxItems"] = field["max_items"]
        if field.get("unique_items") is not None:
            schema["uniqueItems"] = bool(field["unique_items"])
    return schema


def _tool_input_schema(tool: dict) -> dict:
    properties: dict[str, Any] = {}
    required: list[str] = []
    for field in tool.get("inputs", []):
        name = field.get("name")
        if not name:
            continue
        properties[name] = _schema_for_field(field)
        if field.get("required"):
            required.append(name)
    args = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        args["required"] = required
    return {
        "type": "object",
        "properties": {
            "args": args,
            "action_id": {"type": "string", "description": "Stable ID for one logical action; reuse on retry."},
            "job_id": {"type": "string", "description": "Owner-issued budget job shared by this workflow."},
            "approval_request_id": {
                "type": "string",
                "description": "Exact approved request to consume once.",
            },
        },
        "required": ["args"],
        "additionalProperties": False,
    }


def _visible_tools() -> list[dict]:
    return _request("GET", "/v2/agent/tools")


def _tool_to_mcp(tool: dict) -> dict:
    return {
        "name": _mcp_tool_name(tool["id"]),
        "description": (tool.get("description") or "Invoke a typed ToolGate tool.")
        + f" ToolGate id: {tool['id']}.",
        "inputSchema": _tool_input_schema(tool),
    }


def list_tools() -> list[dict]:
    return [_tool_to_mcp(tool) for tool in _visible_tools()] + [
        {
            "name": "toolgate_request_status",
            "description": "Check a request belonging to this execution key.",
            "inputSchema": {
                "type": "object",
                "properties": {"request_id": {"type": "string"}},
                "required": ["request_id"],
                "additionalProperties": False,
            },
        }
    ]


def _invoke(tool_name: str, arguments: dict) -> dict:
    if not isinstance(arguments, dict):
        raise TypeError("Tool arguments must be an object")
    if tool_name == "toolgate_request_status":
        return _request(
            "GET", "/v2/agent/requests/" + quote(str(arguments["request_id"]), safe="")
        )
    tool = next(
        (item for item in _visible_tools() if _mcp_tool_name(item["id"]) == tool_name),
        None,
    )
    if tool is None:
        raise RuntimeError(
            "Tool unavailable for this key; refresh tools/list or ask the owner for scope"
        )
    if set(arguments) - {"args", "approval_request_id", "action_id", "job_id"} or not isinstance(
        arguments.get("args"), dict
    ):
        raise RuntimeError(
            "Supply tool inputs inside args, with optional action_id, job_id and approval_request_id alongside"
        )
    return _request(
        "POST", "/v2/tools/" + quote(tool["id"], safe="") + "/invoke", arguments
    )


def respond(message_id: Any, result: Any = None, error: str | None = None) -> None:
    body = {"jsonrpc": "2.0", "id": message_id}
    if error is None:
        body["result"] = result
    else:
        body["error"] = {"code": -32000, "message": error}
    print(json.dumps(body), flush=True)


def _handle_request(request: dict) -> None:
    if "id" not in request:
        return
    method = request.get("method")
    params = request.get("params", {})
    if not isinstance(params, dict):
        raise TypeError("MCP params must be an object")
    if method == "initialize":
        _request("GET", "/v2/agent/status")
        respond(
            request["id"],
            {
                "protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )
    elif method == "tools/list":
        respond(request["id"], {"tools": list_tools()})
    elif method == "tools/call":
        try:
            value = _invoke(str(params["name"]), params.get("arguments", {}))
            result = {"content": [{"type": "text", "text": json.dumps(value)}]}
        except (RuntimeError, KeyError, TypeError) as exc:
            result = {"isError": True, "content": [{"type": "text", "text": str(exc)}]}
        respond(request["id"], result)
    elif method == "ping":
        respond(request["id"], {})
    else:
        respond(request["id"], error="Unsupported MCP method")


def main() -> int:
    try:
        _request("GET", "/v2/agent/status")
    except RuntimeError as exc:
        print(f"[toolgate-mcp] {exc}", file=sys.stderr)
        return 2
    for line in sys.stdin:
        request = None
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise TypeError("MCP request must be an object")
            _handle_request(request)
        except (RuntimeError, ValueError, KeyError, TypeError) as exc:
            respond(
                request.get("id") if isinstance(request, dict) else None, error=str(exc)
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
