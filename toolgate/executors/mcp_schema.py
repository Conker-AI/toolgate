"""The JSON Schema subset ToolGate accepts for external MCP tools: validation, exact argument checks, bounds and header encoding."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re


class MCPError(ValueError):
    def __init__(self, code, message, status=422):
        super().__init__(message)
        self.code, self.status = code, status


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
