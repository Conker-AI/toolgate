"""Bounded external MCP tools over public HTTPS, without credential or grant discovery.

Supported input schemas use explicit types, bounded type lists or anyOf/oneOf:
object, array, string, integer, number, boolean or null. Objects support properties, required
and boolean additionalProperties; arrays support a single items schema; scalar
enum, const and size/range constraints are supported. Alternatives are limited to eight
branches, 128 schema nodes and 16,384 validation visits. References, other combinators,
regex, formats and remote schema resolution are rejected, never silently weakened.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
import uuid
from urllib.parse import urlsplit

import httpx

from toolgate.core import vault
from toolgate.core.public_https import public_client, public_url

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


class MCPError(ValueError):
    def __init__(self, code, message, status=422):
        super().__init__(message)
        self.code, self.status = code, status


class CallOutcomeUnknown(RuntimeError):
    """The call may have reached the external server; ToolGate must not retry."""


class LegacyServer(MCPError):
    """Only discovery may fall back; tools/call is never a version probe."""


def _error(code, message, status=422):
    raise MCPError(code, message, status)


def _encoded(value):
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        _error("invalid_json", "Use bounded, finite UTF-8 JSON values.")


def schema_hash(schema):
    return hashlib.sha256(_encoded(schema)).hexdigest()


def _types(node):
    if "type" not in node and any(key in node for key in ("anyOf", "oneOf")):
        return set()
    value = node.get("type")
    kinds = [value] if isinstance(value, str) else value
    if (
        not isinstance(kinds, list)
        or not 1 <= len(kinds) <= 7
        or any(
            not isinstance(kind, str)
            or kind not in {"object", "array", "string", "integer", "number", "boolean", "null"}
            for kind in kinds
        )
        or len(set(kinds)) != len(kinds)
    ):
        _error(
            "unsupported_schema",
            "Every schema node needs explicit supported types or bounded anyOf/oneOf alternatives.",
        )
    return set(kinds)


def _comparable(value):
    # JSON Schema numeric equality treats 1 and 1.0 as equal, but not true and 1.
    if type(value) is float and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {key: _comparable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_comparable(item) for item in value]
    return value


def _value_key(value):
    return _encoded(_comparable(value))


def bounded(value, *, maximum=32768):
    count = 0

    def visit(item, depth=0):
        nonlocal count
        count += 1
        if count > 4096 or depth > 16:
            _error("value_too_complex", "MCP values exceed the supported nesting or node limit.")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 1024:
                    _error("invalid_json", "MCP object keys must be bounded strings.")
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
        elif not (
            item is None
            or type(item) in (str, int, bool)
            or (type(item) is float and math.isfinite(item))
        ):
            _error("invalid_json", "Use finite JSON values.")

    visit(value)
    if len(_encoded(value)) > maximum:
        _error("value_too_large", "MCP values exceed the supported byte limit.")


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


def validate_schema(schema):
    bounded(schema)
    if not isinstance(schema, dict) or schema.get("type") != "object":
        _error("unsupported_schema", "The MCP input schema must declare type object.")

    header_names = set()
    schema_nodes = 0

    def visit(node, depth=0, header_path=True):
        nonlocal schema_nodes
        schema_nodes += 1
        if not isinstance(node, dict) or depth > 10 or schema_nodes > 128:
            _error(
                "unsupported_schema",
                "Schemas must contain at most 128 schema nodes and ten nested levels.",
            )
        kinds = _types(node)
        fields = {
            "object": {
                "properties",
                "required",
                "additionalProperties",
                "minProperties",
                "maxProperties",
            },
            "array": {"items", "minItems", "maxItems", "uniqueItems"},
            "string": {"minLength", "maxLength"},
            "integer": {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"},
            "number": {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"},
            "boolean": set(),
            "null": set(),
        }
        common = {
            "type",
            "title",
            "description",
            "default",
            "examples",
            "enum",
            "const",
            "anyOf",
            "oneOf",
            "$schema",
            "x-mcp-header",
        }
        if set(node) - common - set().union(*(fields[kind] for kind in kinds)):
            _error(
                "unsupported_schema",
                "Schema contains unsupported constraints; references, other combinators, regex and formats are unavailable.",
            )
        for key in ("title", "description", "$schema"):
            if key in node and (not isinstance(node[key], str) or len(node[key]) > 4000):
                _error("unsupported_schema", "Schema annotations must be bounded text.")
        if "$schema" in node and node["$schema"].rstrip("#") not in {
            "https://json-schema.org/draft/2020-12/schema",
            "http://json-schema.org/draft-07/schema",
            "https://json-schema.org/draft-07/schema",
        }:
            _error("unsupported_schema", "This JSON Schema dialect is unsupported.")
        if "x-mcp-header" in node:
            name = node["x-mcp-header"]
            if (
                not header_path
                or depth == 0
                or len(kinds - {"null"}) != 1
                or not kinds - {"null"} <= {"string", "integer", "boolean"}
                or not isinstance(name, str)
                or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}", name)
                or name.casefold() in header_names
            ):
                _error(
                    "unsupported_schema",
                    "MCP header annotations must be unique primitive object properties.",
                )
            header_names.add(name.casefold())
        if "examples" in node and (
            not isinstance(node["examples"], list) or len(node["examples"]) > 20
        ):
            _error("unsupported_schema", "Schema examples must be a bounded list.")
        if "enum" in node and (
            not isinstance(node["enum"], list) or not 1 <= len(node["enum"]) <= 100
        ):
            _error("unsupported_schema", "Schema enum must contain one to 100 values.")
        for low, high in (
            ("minProperties", "maxProperties"),
            ("minItems", "maxItems"),
            ("minLength", "maxLength"),
        ):
            for key in (low, high):
                if key in node and (type(node[key]) is not int or not 0 <= node[key] <= 32768):
                    _error(
                        "unsupported_schema",
                        "Schema length constraints must be bounded nonnegative integers.",
                    )
            if low in node and high in node and node[low] > node[high]:
                _error("unsupported_schema", "Schema minimum length exceeds its maximum.")
        for key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
            if key in node and (
                type(node[key]) not in (int, float)
                or (type(node[key]) is float and not math.isfinite(node[key]))
            ):
                _error("unsupported_schema", "Schema numeric constraints must be finite numbers.")
        if "object" in kinds:
            props, required = node.get("properties", {}), node.get("required", [])
            if not isinstance(props, dict) or len(props) > 64 or not isinstance(required, list):
                _error(
                    "unsupported_schema",
                    "Object schemas require at most 64 properties and a required list.",
                )
            if any(not isinstance(key, str) or key not in props for key in required) or len(
                set(required)
            ) != len(required):
                _error("unsupported_schema", "Required properties must be unique declared names.")
            if "additionalProperties" in node and type(node["additionalProperties"]) is not bool:
                _error(
                    "unsupported_schema",
                    "additionalProperties currently supports only true or false.",
                )
            for child in props.values():
                visit(child, depth + 1, header_path)
        if "array" in kinds:
            if "items" not in node:
                _error("unsupported_schema", "Arrays require one typed items schema.")
            if "uniqueItems" in node and type(node["uniqueItems"]) is not bool:
                _error("unsupported_schema", "uniqueItems must be boolean.")
            visit(node["items"], depth + 1, False)
        for keyword in ("anyOf", "oneOf"):
            if keyword in node:
                branches = node[keyword]
                if not isinstance(branches, list) or not 1 <= len(branches) <= 8:
                    _error(
                        "unsupported_schema", "Schema alternatives require one to eight branches."
                    )
                for branch in branches:
                    # Conditional branches have no unambiguous static parameter-header path.
                    visit(branch, depth + 1, False)

    visit(schema)


def validate_arguments(schema, value):
    validate_schema(schema)
    bounded(value)
    visits = 0

    def visit(node, item):
        nonlocal visits
        visits += 1
        if visits > 16384:
            _error("value_too_complex", "Arguments exceed the bounded schema validation budget.")
        kinds = _types(node)
        matches = {
            "object": isinstance(item, dict),
            "array": isinstance(item, list),
            "string": isinstance(item, str),
            "integer": type(item) is int or (type(item) is float and item.is_integer()),
            "number": type(item) in (int, float),
            "boolean": type(item) is bool,
            "null": item is None,
        }
        kind = next(
            (kind for kind, matches_kind in matches.items() if matches_kind and kind in kinds), None
        )
        if kinds and kind is None:
            _error("invalid_arguments", "Arguments do not match the pinned MCP input schema.")
        if "enum" in node and not any(
            _value_key(item) == _value_key(choice) for choice in node["enum"]
        ):
            _error("invalid_arguments", "An argument is outside the schema's enum.")
        if "const" in node and _value_key(item) != _value_key(node["const"]):
            _error("invalid_arguments", "An argument does not match the schema's const value.")
        if kind in {"object", "array", "string"}:
            suffix = {"object": "Properties", "array": "Items", "string": "Length"}[kind]
            if len(item) < node.get("min" + suffix, 0) or len(item) > node.get(
                "max" + suffix, 32768
            ):
                _error("invalid_arguments", "An argument exceeds the schema's size constraints.")
        if kind == "object":
            props = node.get("properties", {})
            if set(node.get("required", [])) - set(item) or (
                node.get("additionalProperties") is False and set(item) - set(props)
            ):
                _error(
                    "invalid_arguments", "Arguments omit required or contain disallowed properties."
                )
            for key, child in item.items():
                if key in props:
                    visit(props[key], child)
        elif kind == "array":
            if node.get("uniqueItems") and len({_value_key(child) for child in item}) != len(item):
                _error("invalid_arguments", "Arguments require unique array items.")
            for child in item:
                visit(node["items"], child)
        elif kind in {"integer", "number"}:
            if (
                ("minimum" in node and item < node["minimum"])
                or ("maximum" in node and item > node["maximum"])
                or ("exclusiveMinimum" in node and item <= node["exclusiveMinimum"])
                or ("exclusiveMaximum" in node and item >= node["exclusiveMaximum"])
            ):
                _error("invalid_arguments", "A numeric argument is outside the schema's range.")
        for keyword in ("anyOf", "oneOf"):
            if keyword not in node:
                continue
            matched = 0
            for branch in node[keyword]:
                try:
                    visit(branch, item)
                except MCPError as exc:
                    if exc.code != "invalid_arguments":
                        raise
                else:
                    matched += 1
                    if keyword == "anyOf" or matched > 1:
                        break
            if matched == 0 or (keyword == "oneOf" and matched != 1):
                _error("invalid_arguments", "Arguments do not match the schema's alternatives.")

    visit(schema, value)
    parameter_headers(schema, value)


def _header_value(value):
    if type(value) is float and value.is_integer():
        value = int(value)
    if type(value) is int and abs(value) > 2**53 - 1:
        _error("invalid_arguments", "MCP header integers must be within the JavaScript safe range.")
    text = str(value).lower() if type(value) is bool else str(value)
    if (
        text != text.strip()
        or any(not (32 <= ord(char) <= 126 or char == "\t") for char in text)
        or (text.startswith("=?base64?") and text.endswith("?="))
    ):
        text = "=?base64?" + base64.b64encode(text.encode()).decode("ascii") + "?="
    if len(text) > 8192:
        _error("invalid_arguments", "An MCP parameter header exceeds its byte limit.")
    return text


def parameter_headers(schema, value):
    headers = {}

    def visit(node, item):
        if "x-mcp-header" in node and item is not None:
            headers["Mcp-Param-" + node["x-mcp-header"]] = _header_value(item)
        if "object" in _types(node) and isinstance(item, dict):
            for key, child in node.get("properties", {}).items():
                if key in item:
                    visit(child, item[key])

    visit(schema, value)
    if sum(len(key) + len(text) for key, text in headers.items()) > 16384:
        _error("invalid_arguments", "MCP parameter headers exceed their total byte limit.")
    return headers


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
    def __init__(self, url, secret_ref=None):
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
        self.deadline = time.monotonic() + MAX_SECONDS
        self.total = 0
        self.session_id = None
        self.version = MODERN_VERSION
        self.modern = True
        self.client = None

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
        if self.secret and self.secret in _encoded(value).decode("utf-8"):
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
        for _ in range(MAX_PAGES):
            result = self.rpc("tools/list", {"cursor": cursor} if cursor else {})
            values = result.get("tools")
            if not isinstance(values, list) or len(tools) + len(values) > MAX_TOOLS:
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
                validate_schema(schema)
                names.add(value["name"])
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
        return {"schemaVersion": 1, "server": session.server, "tools": session.tools()}


def require_match(tools, execution):
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
        with Session(execution["url"], execution.get("secret_ref")) as session:
            require_match(session.tools(), execution)
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
