"""The accepted JSON Schema subset for MCP tools: types, alternatives, const/enum, bounds and header encoding."""

import pytest

from toolgate.executors import mcp_http as mcp
from toolgate.tests.mcp_peer import execution


def test_nested_schema_constraints_are_enforced():
    schema = {
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {"type": "integer", "minimum": 1},
                "maxItems": 3,
                "uniqueItems": True,
            }
        },
        "required": ["items"],
        "additionalProperties": False,
    }
    mcp.validate_arguments(schema, {"items": [1, 2]})
    for value in ([1, 1], [0], [True], [1, 2, 3, 4]):
        with pytest.raises(mcp.MCPError):
            mcp.validate_arguments(schema, {"items": value})


def test_mcp_parameter_headers_encode_unicode_and_avoid_header_injection():
    schema = {
        "type": "object",
        "properties": {
            "settings": {
                "type": "object",
                "properties": {
                    "region": {"type": "string", "x-mcp-header": "Region"},
                    "count": {"type": "integer", "x-mcp-header": "Count"},
                    "enabled": {"type": "boolean", "x-mcp-header": "Enabled"},
                },
            }
        },
    }
    value = {
        "settings": {"region": "line1\n\u05e9\u05dc\u05d5\u05dd", "count": 42, "enabled": True}
    }
    mcp.validate_arguments(schema, value)
    headers = mcp.parameter_headers(schema, value)
    assert headers["Mcp-Param-Region"].startswith("=?base64?")
    assert "\n" not in headers["Mcp-Param-Region"]
    assert headers["Mcp-Param-Count"] == "42"
    assert headers["Mcp-Param-Enabled"] == "true"
    assert mcp._header_value("=?base64?literal?=") != "=?base64?literal?="
    value["settings"]["count"] = 2**53
    with pytest.raises(mcp.MCPError):
        mcp.validate_arguments(schema, value)


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "object", "properties": {"a": {"type": "string", "x-mcp-header": "Host\r\nBad"}}},
        {"type": "object", "properties": {"a": {"type": "number", "x-mcp-header": "Amount"}}},
        {
            "type": "object",
            "properties": {
                "a": {"type": "array", "items": {"type": "string", "x-mcp-header": "Item"}}
            },
        },
        {
            "type": "object",
            "properties": {
                "a": {"type": "string", "x-mcp-header": "Same"},
                "b": {"type": "string", "x-mcp-header": "SAME"},
            },
        },
        {"type": "object", "$schema": "https://unknown.example/schema"},
    ],
)
def test_unsupported_or_ambiguous_header_schemas_are_rejected(schema):
    with pytest.raises(mcp.MCPError) as exc:
        mcp.validate_schema(schema)
    assert exc.value.code == "unsupported_schema"


def test_schema_hash_failure_and_malformed_numbers_are_bounded():
    with pytest.raises(mcp.MCPError) as exc:
        mcp.validate_execution({**execution(), "schema_hash": "0" * 64})
    assert exc.value.code == "schema_hash_mismatch"
    schema = {"type": "object", "properties": {"big": {"type": "number", "minimum": 10**400}}}
    mcp.validate_schema(schema)
    with pytest.raises(mcp.MCPError):
        mcp.validate_arguments(schema, {"big": float("inf")})


def test_nullable_types_and_const_match_microsoft_catalogue_shape():
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": ["string", "null"], "default": None},
            "SessionId": {
                "type": ["string", "null"],
                "default": "opaque-session",
                "const": "opaque-session",
            },
        },
    }
    mcp.validate_schema(schema)
    mcp.validate_arguments(schema, {"query": None})
    mcp.validate_arguments(schema, {"query": "Azure", "SessionId": "opaque-session"})
    for value in (False, 4, {}):
        with pytest.raises(mcp.MCPError):
            mcp.validate_arguments(schema, {"query": value})
    for value in (None, "other-session"):
        with pytest.raises(mcp.MCPError):
            mcp.validate_arguments(schema, {"SessionId": value})


def test_type_unions_apply_only_constraints_for_the_actual_value_type():
    schema = {
        "type": "object",
        "properties": {
            "value": {
                "type": ["object", "array", "string", "number", "null"],
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
                "additionalProperties": False,
                "items": {"type": "integer"},
                "minLength": 2,
                "minimum": 1,
                "maxItems": 2,
            }
        },
    }
    for value in (None, "ab", 2, {"name": "A"}, [1, 2]):
        mcp.validate_arguments(schema, {"value": value})
    for value in (False, "a", 0, {}, [1, 2, 3], [None]):
        with pytest.raises(mcp.MCPError):
            mcp.validate_arguments(schema, {"value": value})


@pytest.mark.parametrize("types", [[], ["string", "string"], ["string", {}], ["string", "unknown"]])
def test_invalid_type_unions_are_rejected(types):
    with pytest.raises(mcp.MCPError) as exc:
        mcp.validate_schema({"type": "object", "properties": {"value": {"type": types}}})
    assert exc.value.code == "unsupported_schema"


def test_const_and_enum_distinguish_boolean_but_equate_json_numbers():
    schema = {
        "type": "object",
        "properties": {"n": {"type": ["integer", "boolean"], "const": 1, "enum": [1.0]}},
    }
    mcp.validate_arguments(schema, {"n": 1.0})
    with pytest.raises(mcp.MCPError):
        mcp.validate_arguments(schema, {"n": True})
    array = {
        "type": "object",
        "properties": {"list": {"type": "array", "items": {"type": "number"}, "uniqueItems": True}},
    }
    with pytest.raises(mcp.MCPError):
        mcp.validate_arguments(array, {"list": [1, 1.0]})


def test_nullable_header_is_omitted_for_null():
    schema = {
        "type": "object",
        "properties": {"name": {"type": ["string", "null"], "x-mcp-header": "Name"}},
    }
    mcp.validate_arguments(schema, {"name": None})
    assert mcp.parameter_headers(schema, {"name": None}) == {}


def test_anyof_and_oneof_preserve_overlapping_branch_semantics():
    alternatives = [{"type": "integer"}, {"type": "number", "minimum": 0}]
    for keyword in ("anyOf", "oneOf"):
        schema = {"type": "object", "properties": {"value": {keyword: alternatives}}}
        mcp.validate_arguments(schema, {"value": -1})
        mcp.validate_arguments(schema, {"value": 0.5})
        if keyword == "anyOf":
            mcp.validate_arguments(schema, {"value": 1})
        else:
            with pytest.raises(mcp.MCPError):
                mcp.validate_arguments(schema, {"value": 1})
        with pytest.raises(mcp.MCPError):
            mcp.validate_arguments(schema, {"value": False})


def test_alternatives_apply_sibling_constraints_and_validate_every_branch():
    value_schema = {
        "type": "string",
        "maxLength": 4,
        "anyOf": [{"type": "string", "const": "hello"}, {"type": "string", "const": "hi"}],
    }
    schema = {"type": "object", "properties": {"value": value_schema}}
    mcp.validate_arguments(schema, {"value": "hi"})
    for value in ("hello", "no", 4):
        with pytest.raises(mcp.MCPError):
            mcp.validate_arguments(schema, {"value": value})
    value_schema["anyOf"].append({"$ref": "https://schema.example/ref"})
    with pytest.raises(mcp.MCPError) as exc:
        mcp.validate_schema(schema)
    assert exc.value.code == "unsupported_schema"


@pytest.mark.parametrize(
    "alternatives",
    [[], {}, [True], [{"type": "string"}] * 9, [{"type": "string", "x-mcp-header": "Branch"}]],
)
def test_schema_alternatives_are_bounded_and_cannot_add_conditional_headers(alternatives):
    schema = {"type": "object", "properties": {"value": {"anyOf": alternatives}}}
    with pytest.raises(mcp.MCPError) as exc:
        mcp.validate_schema(schema)
    assert exc.value.code == "unsupported_schema"


def test_schema_alternative_work_is_bounded():
    schema = {
        "type": "object",
        "properties": {
            "values": {
                "type": "array",
                "items": {"oneOf": [{"type": "number"}] * 7 + [{"type": "string"}]},
            }
        },
    }
    mcp.validate_arguments(schema, {"values": ["x"] * 100})
    with pytest.raises(mcp.MCPError) as exc:
        mcp.validate_arguments(schema, {"values": ["x"] * 2300})
    assert exc.value.code == "value_too_complex"
