"""Bounded external MCP tools over public HTTPS, without credential or grant discovery.

Supported input schemas use explicit types, bounded type lists or anyOf/oneOf:
object, array, string, integer, number, boolean or null. Objects support properties, required
and boolean additionalProperties; arrays support a single items schema; scalar
enum, const and size/range constraints are supported. Alternatives are limited to eight
branches, 128 schema nodes and 16,384 validation visits. References, other combinators,
regex, formats and remote schema resolution are rejected, never silently weakened.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from urllib.parse import urlsplit

import httpx

from toolgate.core import tool_settings, vault
from toolgate.core.public_https import public_client, public_url
from toolgate.executors.mcp_schema import (
    MCPError,
    _error,
    _header_value,
    bounded,
    parameter_headers,
    schema_hash,
    validate_arguments,
    validate_schema,
)

VERSION = "2025-11-25"
VERSIONS = {VERSION, "2025-06-18", "2025-03-26"}
MODERN_VERSION = "2026-07-28"
MODERN_ERRORS = {-32020, -32021, -32022}
MAX_BYTES = 1_048_576
MAX_TOTAL_BYTES = 2_097_152
MAX_TOOLS = 64
MAX_PAGES = 4
MAX_SECONDS = 30
NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
REFERENCE = re.compile(r"^[A-Z][A-Z0-9_]{0,99}$")


class CallOutcomeUnknown(RuntimeError):
    """The call may have reached the external server; ToolGate must not retry."""


class LegacyServer(MCPError):
    """Only discovery may fall back; tools/call is never a version probe."""


def destination(url):
    if not isinstance(url, str) or not 1 <= len(url) <= 2048 or any(ord(c) < 33 for c in url):
        _error("invalid_destination", "Use a fixed public HTTPS MCP endpoint.")
    try:
        parsed = urlsplit(url)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname
            and parsed.port in (None, 443)
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
            and "\\" not in url
        )
    except ValueError:
        valid = False
    if not valid:
        _error(
            "invalid_destination",
            "Use public HTTPS on port 443 without credentials, query or fragment.",
        )
    return url


def reference(value):
    if value is not None and (
        not isinstance(value, str) or not REFERENCE.fullmatch(value) or value in vault._CONFIG_KEYS
    ):
        _error(
            "invalid_secret_reference",
            "Use a provider vault reference, never a control credential.",
        )


def validate_execution(execution):
    required = {"type", "url", "tool_name", "input_schema", "schema_hash"}
    if (
        not isinstance(execution, dict)
        or not required <= set(execution)
        or set(execution) - required - {"secret_ref"}
    ):
        _error(
            "invalid_definition",
            "MCP execution requires a fixed endpoint, tool name and pinned input schema.",
        )
    if (
        execution["type"] != "mcp_http"
        or not isinstance(execution["tool_name"], str)
        or not NAME.fullmatch(execution["tool_name"])
    ):
        _error("invalid_definition", "Use a supported exact MCP tool name.")
    destination(execution["url"])
    reference(execution.get("secret_ref"))
    validate_schema(execution["input_schema"])
    if execution["schema_hash"] != schema_hash(execution["input_schema"]):
        _error("schema_hash_mismatch", "MCP input schema does not match its pinned hash.")


class Session:
    def __init__(self, url, secret_ref=None, seconds=MAX_SECONDS):
        self.url = destination(url)
        reference(secret_ref)
        self.secret = None
        if secret_ref:
            try:
                self.secret = vault.get_key(secret_ref)
            except KeyError:
                _error("secret_unavailable", "The referenced MCP credential is not available.", 503)
            if (
                not isinstance(self.secret, str)
                or not 8 <= len(self.secret) <= 8192
                or any(ord(c) < 33 or ord(c) > 126 for c in self.secret)
            ):
                _error("invalid_secret", "The MCP bearer credential must be bounded ASCII text.")
        self.deadline = time.monotonic() + min(seconds, MAX_SECONDS)
        self.total = 0
        self.session_id = None
        self.version = MODERN_VERSION
        self.modern = True
        self.client = None
        self.unsupported_tools = []

    def __enter__(self):
        if not public_url(self.url):
            _error(
                "destination_denied",
                "MCP endpoints must resolve entirely to public HTTPS addresses.",
            )
        self.client = public_client(timeout=10)
        try:
            try:
                result = self.rpc("server/discover", probe=True)
            except LegacyServer:
                self.modern, self.version = False, None
                result = self.rpc(
                    "initialize",
                    {
                        "protocolVersion": VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "Conker ToolGate", "version": "1"},
                    },
                )
                if result.get("protocolVersion") not in VERSIONS:
                    _error(
                        "unsupported_server",
                        "The server does not support a configured MCP protocol version.",
                    )
                self.version = result["protocolVersion"]
                info = result.get("serverInfo", {})
            else:
                versions = result.get("supportedVersions")
                if not isinstance(versions, list) or MODERN_VERSION not in versions:
                    _error("unsupported_server", "The server does not support MCP 2026-07-28.")
                metadata = result.get("_meta", {})
                if not isinstance(metadata, dict):
                    _error("invalid_server", "MCP server metadata is invalid.")
                info = metadata.get(
                    "io.modelcontextprotocol/serverInfo",
                    {"name": "MCP server", "version": "unspecified"},
                )
            if not isinstance(result.get("capabilities"), dict) or not isinstance(
                result["capabilities"].get("tools"), dict
            ):
                _error("unsupported_server", "The server does not advertise MCP tools.")
            if not isinstance(info, dict) or any(
                not isinstance(info.get(key), str) or not 1 <= len(info[key]) <= 200
                for key in ("name", "version")
            ):
                _error("invalid_server", "MCP server metadata is missing or too large.")
            self.server = {"url": self.url, "name": info["name"], "version": info["version"]}
            if not self.modern:
                self.rpc("notifications/initialized", notification=True)
        except Exception:
            self.client.close()
            raise
        return self

    def __exit__(self, *_args):
        try:
            # Legacy servers may retain a session. Disposal never calls a tool,
            # retries a request or changes an uncertain invocation receipt.
            remaining = self.deadline - time.monotonic()
            if self.session_id and not self.modern and remaining > 0:
                headers = {
                    "Mcp-Session-Id": self.session_id,
                    "MCP-Protocol-Version": self.version,
                    "Accept-Encoding": "identity",
                }
                if self.secret:
                    headers["Authorization"] = "Bearer " + self.secret
                try:
                    with self.client.stream(
                        "DELETE", self.url, headers=headers, timeout=min(2, remaining)
                    ):
                        pass
                except httpx.HTTPError:
                    pass
        finally:
            self.client.close()

    def _json(self, raw):
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("Duplicate JSON key")
                value[key] = item
            return value

        try:
            value = json.loads(raw, object_pairs_hook=unique)
        except (ValueError, UnicodeError, RecursionError):
            _error("invalid_response", "The MCP server returned invalid JSON.", 502)
        bounded(value, maximum=MAX_BYTES)

        def contains_secret(item):
            if isinstance(item, str):
                return self.secret in item
            if isinstance(item, dict):
                return any(
                    self.secret in key or contains_secret(child) for key, child in item.items()
                )
            if isinstance(item, list):
                return any(contains_secret(child) for child in item)
            return False

        # Inspect decoded keys and values: JSON escaping can hide a raw bearer
        # containing quotes or backslashes from a serialized-string search.
        # bounded() above limits this traversal to 4096 nodes and depth 16.
        if self.secret and contains_secret(value):
            _error(
                "credential_echo",
                "The MCP server echoed its credential; the response was withheld.",
                502,
            )
        return value

    def _reply(self, value, identity, *, probe=False, status=200):
        if probe:
            error = value.get("error") if isinstance(value, dict) else None
            code = error.get("code") if isinstance(error, dict) else None
            if type(code) is int and code in MODERN_ERRORS:
                _error(
                    "modern_protocol_error",
                    "The server rejected modern MCP version, headers or capabilities; no legacy fallback was attempted.",
                    502,
                )
            if status in {400, 404, 405} or code == -32601:
                raise LegacyServer(
                    "legacy_server", "This server requires an initialization handshake."
                )
        if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
            _error("invalid_response", "The MCP server returned an invalid RPC envelope.", 502)
        if "method" in value:
            if "id" in value:
                _error(
                    "unsupported_server_request",
                    "Server-initiated MCP requests are unavailable.",
                    502,
                )
            return None  # Bounded notifications are not tool results or instructions.
        if value.get("id") != identity or ("result" in value) == ("error" in value):
            _error("invalid_response", "The MCP response identity or result is invalid.", 502)
        if "error" in value:
            _error("rpc_error", "The MCP server returned an RPC error.", 502)
        if not isinstance(value["result"], dict):
            _error("invalid_response", "The MCP result must be an object.", 502)
        if value["result"].get("resultType", "complete") != "complete":
            _error(
                "unsupported_input_request",
                "MCP sampling, elicitation and deferred results are unavailable; no follow-up call was sent.",
                502,
            )
        return value["result"]

    def rpc(self, method, params=None, *, notification=False, probe=False, extra_headers=None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            _error("timeout", "The MCP operation reached its time limit.", 504)
        identity = uuid.uuid4().hex
        body = {"jsonrpc": "2.0", "method": method}
        if not notification:
            body["id"] = identity
        if self.modern:
            params = {
                **(params or {}),
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": self.version,
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "Conker ToolGate",
                        "version": "1",
                    },
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            }
        if params is not None:
            body["params"] = params
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "Accept-Encoding": "identity",
        }
        if self.modern:
            headers["Mcp-Method"] = method
            if method == "tools/call":
                headers["Mcp-Name"] = _header_value(params["name"])
        if extra_headers:
            headers.update(extra_headers)
        if self.secret:
            headers["Authorization"] = "Bearer " + self.secret
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.version:
            headers["MCP-Protocol-Version"] = self.version
        try:
            with self.client.stream(
                "POST", self.url, json=body, headers=headers, timeout=min(10, remaining)
            ) as response:
                if response.status_code != (202 if notification else 200) and not (
                    probe and response.status_code in {400, 404, 405}
                ):
                    _error(
                        "upstream_http",
                        "The MCP server rejected the request; no retry was attempted.",
                        502,
                    )
                if notification:
                    return None
                if response.headers.get("content-encoding", "identity") != "identity":
                    _error("unsupported_encoding", "Compressed MCP responses are unavailable.", 502)
                supplied = response.headers.get("Mcp-Session-Id")
                if supplied and not self.modern:
                    if (
                        (method != "initialize" and supplied != self.session_id)
                        or not 1 <= len(supplied) <= 256
                        or any(not 33 <= ord(c) <= 126 for c in supplied)
                    ):
                        _error("invalid_session", "The MCP session header is invalid.", 502)
                    self.session_id = supplied
                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
                if content_type not in {"application/json", "text/event-stream"}:
                    if probe and response.status_code in {400, 404, 405}:
                        raise LegacyServer(
                            "legacy_server", "This server requires an initialization handshake."
                        )
                    _error("invalid_response", "MCP requires JSON or event-stream responses.", 502)
                received, buffer, event = 0, b"", []
                for chunk in response.iter_bytes():
                    received += len(chunk)
                    self.total += len(chunk)
                    if (
                        received > MAX_BYTES
                        or self.total > MAX_TOTAL_BYTES
                        or time.monotonic() > self.deadline
                    ):
                        _error(
                            "response_limit",
                            "The MCP response exceeded its byte or time limit.",
                            502,
                        )
                    buffer += chunk
                    if content_type == "text/event-stream":
                        while b"\n" in buffer:
                            line, buffer = buffer.split(b"\n", 1)
                            line = line.rstrip(b"\r")
                            if line.startswith(b"data:"):
                                event.append(line[5:].lstrip(b" "))
                            elif not line and event:
                                result = self._reply(
                                    self._json(b"\n".join(event)),
                                    identity,
                                    probe=probe,
                                    status=response.status_code,
                                )
                                event = []
                                if result is not None:
                                    return result
                if content_type == "application/json":
                    try:
                        value = self._json(buffer)
                    except MCPError as exc:
                        if (
                            probe
                            and response.status_code in {400, 404, 405}
                            and exc.code == "invalid_response"
                        ):
                            raise LegacyServer(
                                "legacy_server", "This server requires an initialization handshake."
                            ) from exc
                        raise
                    result = self._reply(value, identity, probe=probe, status=response.status_code)
                    if result is not None:
                        return result
                _error("incomplete_response", "No matching MCP result was received.", 502)
        except httpx.HTTPError:
            _error("transport_error", "The MCP connection failed; no retry was attempted.", 502)

    def tools(self):
        tools, names, cursors, cursor = [], set(), set(), None
        self.unsupported_tools = []
        for _ in range(MAX_PAGES):
            result = self.rpc("tools/list", {"cursor": cursor} if cursor else {})
            values = result.get("tools")
            if not isinstance(values, list) or len(names) + len(values) > MAX_TOOLS:
                _error("catalogue_limit", "MCP tool catalogues are limited to 64 tools.", 502)
            for value in values:
                if (
                    not isinstance(value, dict)
                    or not isinstance(value.get("name"), str)
                    or not NAME.fullmatch(value["name"])
                    or value["name"] in names
                ):
                    _error("invalid_catalogue", "MCP tools must have unique supported names.", 502)
                description = value.get("description", "")
                if not isinstance(description, str) or len(description) > 4000:
                    _error("invalid_catalogue", "MCP tool descriptions must be bounded text.", 502)
                schema = value.get("inputSchema")
                names.add(value["name"])
                try:
                    validate_schema(schema)
                except MCPError as exc:
                    self.unsupported_tools.append({"name": value["name"], "reason": str(exc)[:500]})
                    continue
                tools.append(
                    {
                        "name": value["name"],
                        "description": description,
                        "inputSchema": schema,
                        "schemaHash": schema_hash(schema),
                    }
                )
            cursor = result.get("nextCursor")
            if cursor is None:
                return tools
            if not isinstance(cursor, str) or not 1 <= len(cursor) <= 1024 or cursor in cursors:
                _error("invalid_catalogue", "The MCP catalogue cursor is invalid or repeated.", 502)
            cursors.add(cursor)
        _error("catalogue_limit", "MCP catalogue pagination exceeds four pages.", 502)


def discover(url, secret_ref=None):
    with Session(url, secret_ref) as session:
        result = {"schemaVersion": 1, "server": session.server, "tools": session.tools()}
        if session.unsupported_tools:
            result["unsupportedTools"] = session.unsupported_tools
        return result


def require_match(tools, execution, unsupported_tools=()):
    if any(tool["name"] == execution["tool_name"] for tool in unsupported_tools):
        _error("unsupported_schema", "The selected MCP tool's current input schema is unsupported.")
    matches = [tool for tool in tools if tool["name"] == execution["tool_name"]]
    if len(matches) != 1 or matches[0]["schemaHash"] != execution["schema_hash"]:
        _error(
            "schema_changed",
            "The MCP tool or input schema changed; rediscover and import a new reviewed tool.",
            409,
        )


def execute(execution, args):
    try:
        validate_execution(execution)
        if not isinstance(args, dict) or set(args) != {"arguments"}:
            _error("invalid_arguments", "Provide only the arguments object.")
        validate_arguments(execution["input_schema"], args["arguments"])
        # A tool call runs within the owner's tool time limit; discovery keeps MCP's own.
        with Session(
            execution["url"], execution.get("secret_ref"), tool_settings.seconds(MAX_SECONDS)
        ) as session:
            require_match(session.tools(), execution, session.unsupported_tools)
            try:
                result = session.rpc(
                    "tools/call",
                    {"name": execution["tool_name"], "arguments": args["arguments"]},
                    extra_headers=parameter_headers(execution["input_schema"], args["arguments"]),
                )
                content = result.get("content")
                if (
                    not isinstance(content, list)
                    or len(content) > 64
                    or any(
                        not isinstance(item, dict) or not isinstance(item.get("type"), str)
                        for item in content
                    )
                ):
                    _error(
                        "invalid_tool_result",
                        "The MCP tool returned an invalid content result.",
                        502,
                    )
                if "isError" in result and type(result["isError"]) is not bool:
                    _error("invalid_tool_result", "The MCP isError result must be boolean.", 502)
                # Never follow resource links or interpret server content as instructions.
                data = {"content": content, "isError": result.get("isError", False)}
                if "structuredContent" in result:
                    if not isinstance(result["structuredContent"], dict):
                        _error(
                            "invalid_tool_result", "MCP structuredContent must be an object.", 502
                        )
                    data["structuredContent"] = result["structuredContent"]
                if data["isError"]:
                    return {
                        "ok": False,
                        "error": "The MCP tool reported a failure.",
                        "error_code": "mcp_tool_error",
                        "result": data,
                    }
                return {"ok": True, "result": data}
            except MCPError as exc:
                raise CallOutcomeUnknown(
                    "The MCP call outcome is unknown; inspect it before retrying."
                ) from exc
    except MCPError as exc:
        return {"ok": False, "error": str(exc), "error_code": exc.code}
