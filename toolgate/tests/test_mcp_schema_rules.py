"""One test per refusal in the MCP schema checker, each with the nearest valid input passing."""

import base64
import re
from pathlib import Path

import pytest

from toolgate.executors import mcp_schema as ms

UNSUPPORTED = "Schema contains unsupported constraints; references, other combinators, regex and formats are unavailable."
SIZE = "An argument exceeds the schema's size constraints."
RANGE = "A numeric argument is outside the schema's range."
ALTS = "Arguments do not match the schema's alternatives."
BRANCHES = "Schema alternatives require one to eight branches."
MIN_MAX = "Schema minimum length exceeds its maximum."
OBJECT_RULE = "Object schemas require at most 64 properties and a required list."
REQ_EXTRA = "Arguments omit required or contain disallowed properties."
NUMERIC = "Schema numeric constraints must be finite numbers."
ENUM_OUT = "An argument is outside the schema's enum."
CONST_OUT = "An argument does not match the schema's const value."
TOO_COMPLEX = "MCP values exceed the supported nesting or node limit."
HDR_INT = "MCP header integers must be within the JavaScript safe range."
REQUIRED = "Required properties must be unique declared names."
ADDL = "additionalProperties currently supports only true or false."
SCHEMA_DEPTH = "Schemas must contain at most 128 schema nodes and ten nested levels."
HEADER_RULE = "MCP header annotations must be unique primitive object properties."
LENGTHS = "Schema length constraints must be bounded nonnegative integers."
BAD_TYPES = "Every schema node needs explicit supported types or bounded anyOf/oneOf alternatives."


def obj(**props):
    return {"type": "object", "properties": props}


def one(node):
    return obj(v=node)


def refuses(code, message, fn, *args, **kwargs):
    with pytest.raises(ms.MCPError, match=re.escape(message)) as exc:
        fn(*args, **kwargs)
    assert exc.value.code == code
    assert exc.value.status == 422
    assert str(exc.value) == message


def array_chain(levels):
    node = {"type": "string"}
    for _ in range(levels):
        node = {"type": "array", "items": node}
    return obj(a=node)


def nested(depth):
    value = {}
    for _ in range(depth):
        value = {"n": value}
    return value


def test_every_refusal_message_has_a_test():
    source = Path(ms.__file__).read_text(encoding="utf-8")
    found = re.findall(r'_error\(\s*"([^"]+)"\s*,\s*"([^"]+)"', source)
    assert len(found) >= 35, "the _error pattern no longer matches the module"
    mine = Path(__file__).read_text(encoding="utf-8")
    missing = [message for _, message in found if message not in mine]
    assert not missing, f"refusals without a test: {missing}"


# bounded, schema_hash -------------------------------------------------------------------


def test_bounded_depth_16_passes_and_17_fails():
    ms.bounded(nested(16))
    refuses(
        "value_too_complex",
        TOO_COMPLEX,
        ms.bounded,
        nested(17),
    )


def test_bounded_node_count_limit():
    ms.bounded(list(range(4095)))
    refuses(
        "value_too_complex",
        TOO_COMPLEX,
        ms.bounded,
        list(range(4096)),
    )


@pytest.mark.parametrize("key", [123, None, "x" * 1025])
def test_bounded_rejects_bad_object_keys(key):
    refuses("invalid_json", "MCP object keys must be bounded strings.", ms.bounded, {key: 1})


def test_bounded_accepts_a_1024_char_key():
    ms.bounded({"k" * 1024: 1})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), (1,), object()])
def test_bounded_rejects_non_finite_and_non_json_values(value):
    refuses("invalid_json", "Use finite JSON values.", ms.bounded, value)


def test_bounded_accepts_plain_json_scalars():
    for value in (None, True, 1, 42.5, "text", [], {}):
        ms.bounded(value)


def test_bounded_byte_limit():
    ms.bounded("x" * 100, maximum=102)
    refuses(
        "value_too_large",
        "MCP values exceed the supported byte limit.",
        ms.bounded,
        "x" * 100,
        maximum=101,
    )
    refuses(
        "value_too_large",
        "MCP values exceed the supported byte limit.",
        ms.bounded,
        "x" * 32769,
    )


def test_schema_hash_ignores_key_order_and_tracks_values():
    one = {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "integer"}}}
    two = {"properties": {"b": {"type": "integer"}, "a": {"type": "string"}}, "type": "object"}
    changed = {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "number"}}}
    assert ms.schema_hash(one) == ms.schema_hash(two)
    assert ms.schema_hash(one) != ms.schema_hash(changed)
    assert re.fullmatch(r"[0-9a-f]{64}", ms.schema_hash(one))


def test_schema_hash_refuses_values_json_cannot_hold():
    refuses(
        "invalid_json",
        "Use bounded, finite UTF-8 JSON values.",
        ms.schema_hash,
        {"a": float("nan")},
    )
    refuses("invalid_json", "Use bounded, finite UTF-8 JSON values.", ms.schema_hash, {"a": b"x"})
    refuses(
        "invalid_json", "Use bounded, finite UTF-8 JSON values.", ms.schema_hash, {"a": "\ud800"}
    )


# validate_schema ------------------------------------------------------------------------

SCHEMA_REFUSALS = [
    ({"type": "string"}, "The MCP input schema must declare type object."),
    ({"properties": {}}, "The MCP input schema must declare type object."),
    (["object"], "The MCP input schema must declare type object."),
    (obj(a={"type": "bogus"}), BAD_TYPES),
    (obj(a={}), BAD_TYPES),
    (obj(a={"type": []}), BAD_TYPES),
    (obj(a={"type": 5}), BAD_TYPES),
    (obj(a={"type": ["string", "string"]}), BAD_TYPES),
    (obj(a={"type": [*"abcdefgh"]}), BAD_TYPES),
    (obj(a="not a dict"), SCHEMA_DEPTH),
    (obj(**{f"p{i}": obj(x={"type": "string"}) for i in range(64)}), SCHEMA_DEPTH),
    (array_chain(10), SCHEMA_DEPTH),
    ({"type": "object", "pattern": "^a$"}, UNSUPPORTED),
    (obj(a={"type": "string", "minimum": 1}), UNSUPPORTED),
    (obj(a={"type": "string", "$ref": "#/x"}), UNSUPPORTED),
    (obj(a={"type": "string", "allOf": []}), UNSUPPORTED),
    ({"type": "object", "title": "x" * 4001}, "Schema annotations must be bounded text."),
    ({"type": "object", "title": 123}, "Schema annotations must be bounded text."),
    ({"type": "object", "description": ["x"]}, "Schema annotations must be bounded text."),
    ({"type": "object", "$schema": 7}, "Schema annotations must be bounded text."),
    (
        {"type": "object", "$schema": "https://example.test/schema"},
        "This JSON Schema dialect is unsupported.",
    ),
    ({"type": "object", "examples": ["e"] * 21}, "Schema examples must be a bounded list."),
    ({"type": "object", "examples": "no"}, "Schema examples must be a bounded list."),
    ({"type": "object", "enum": ["v"] * 101}, "Schema enum must contain one to 100 values."),
    ({"type": "object", "enum": []}, "Schema enum must contain one to 100 values."),
    ({"type": "object", "enum": "no"}, "Schema enum must contain one to 100 values."),
    ({"type": "object", "minProperties": "1"}, LENGTHS),
    ({"type": "object", "minProperties": -1}, LENGTHS),
    ({"type": "object", "maxProperties": 32769}, LENGTHS),
    ({"type": "object", "maxProperties": True}, LENGTHS),
    ({"type": "object", "maxProperties": 1.0}, LENGTHS),
    (obj(a={"type": "array", "items": {"type": "string"}, "minItems": -1}), LENGTHS),
    (obj(a={"type": "string", "maxLength": "5"}), LENGTHS),
    ({"type": "object", "minProperties": 2, "maxProperties": 1}, MIN_MAX),
    (obj(a={"type": "array", "items": {"type": "string"}, "minItems": 3, "maxItems": 2}), MIN_MAX),
    (obj(a={"type": "string", "minLength": 3, "maxLength": 2}), MIN_MAX),
    (obj(a={"type": "number", "minimum": "1"}), NUMERIC),
    (obj(a={"type": "integer", "exclusiveMaximum": True}), NUMERIC),
    (obj(a={"type": "number", "maximum": None}), NUMERIC),
    (
        {"type": "object", "properties": {f"p{i}": {"type": "string"} for i in range(65)}},
        OBJECT_RULE,
    ),
    ({"type": "object", "properties": []}, OBJECT_RULE),
    ({"type": "object", "required": "a"}, OBJECT_RULE),
    ({"type": "object", "required": ["missing"]}, REQUIRED),
    (obj(a={"type": "string"}) | {"required": ["a", "a"]}, REQUIRED),
    (obj(a={"type": "string"}) | {"required": [1]}, REQUIRED),
    ({"type": "object", "additionalProperties": {"type": "string"}}, ADDL),
    ({"type": "object", "additionalProperties": 1}, ADDL),
    (obj(a={"type": "array"}), "Arrays require one typed items schema."),
    (
        obj(a={"type": "array", "items": {"type": "string"}, "uniqueItems": "yes"}),
        "uniqueItems must be boolean.",
    ),
    (obj(a={"anyOf": [{"type": "string"}] * 9}), BRANCHES),
    (obj(a={"oneOf": []}), BRANCHES),
    (obj(a={"anyOf": "no"}), BRANCHES),
]


@pytest.mark.parametrize(("schema", "message"), SCHEMA_REFUSALS)
def test_validate_schema_refuses(schema, message):
    refuses("unsupported_schema", message, ms.validate_schema, schema)


def test_validate_schema_surfaces_bounded_errors_first():
    refuses(
        "value_too_complex",
        TOO_COMPLEX,
        ms.validate_schema,
        nested(17),
    )
    refuses(
        "invalid_json",
        "Use finite JSON values.",
        ms.validate_schema,
        obj(a={"type": "number", "minimum": float("inf")}),
    )


def test_validate_schema_accepts_the_nearest_valid_forms():
    limits = {f"p{i}": {"type": "string"} for i in range(64)}
    valid = [
        {"type": "object"},
        {"type": "object", "properties": limits, "required": ["p0"], "additionalProperties": False},
        obj(**{f"p{i}": obj(x={"type": "string"}) for i in range(63)}),
        array_chain(9),
        obj(a={"type": ["string", "null"], "minLength": 0, "maxLength": 32768}),
        obj(a={"type": "number", "minimum": 1.5, "exclusiveMaximum": 9}),
        obj(
            a={
                "type": "array",
                "items": {"type": "integer"},
                "minItems": 1,
                "maxItems": 1,
                "uniqueItems": True,
            }
        ),
        obj(a={"anyOf": [{"type": "string"}] * 8}),
        obj(a={"oneOf": [{"type": "string"}, {"type": "null"}]}),
        {"type": "object", "title": "x" * 4000, "examples": [1] * 20, "enum": [1] * 100},
        {"type": "object", "minProperties": 1, "maxProperties": 1},
    ]
    valid += [
        {"type": "object", "$schema": url}
        for url in (
            "https://json-schema.org/draft/2020-12/schema",
            "http://json-schema.org/draft-07/schema#",
            "https://json-schema.org/draft-07/schema",
        )
    ]
    for schema in valid:
        ms.validate_schema(schema)


HEADER_REFUSALS = [
    {"type": "object", "x-mcp-header": "Root"},
    obj(a={"type": "object", "x-mcp-header": "A"}),
    obj(a={"type": "array", "items": {"type": "string"}, "x-mcp-header": "A"}),
    obj(a={"type": "number", "x-mcp-header": "A"}),
    obj(a={"type": ["string", "integer"], "x-mcp-header": "A"}),
    obj(a={"type": "null", "x-mcp-header": "A"}),
    obj(a={"type": "string", "x-mcp-header": 5}),
    obj(a={"type": "string", "x-mcp-header": ""}),
    obj(a={"type": "string", "x-mcp-header": "Bad Name"}),
    obj(a={"type": "string", "x-mcp-header": "N" * 65}),
    obj(a={"type": "string", "x-mcp-header": "Same"}, b={"type": "string", "x-mcp-header": "SAME"}),
    obj(a={"type": "array", "items": {"type": "string", "x-mcp-header": "A"}}),
    obj(a={"anyOf": [{"type": "string", "x-mcp-header": "A"}]}),
]


@pytest.mark.parametrize("schema", HEADER_REFUSALS)
def test_header_annotation_refusals(schema):
    refuses("unsupported_schema", HEADER_RULE, ms.validate_schema, schema)


def test_header_annotation_accepts_primitives_and_nested_objects():
    ms.validate_schema(
        obj(
            s={"type": "string", "x-mcp-header": "Good-Name_1.~"},
            i={"type": ["integer", "null"], "x-mcp-header": "Int"},
            b={"type": "boolean", "x-mcp-header": "Flag"},
            inner=obj(deep={"type": "string", "x-mcp-header": "Deep"}),
        )
    )


# validate_arguments ---------------------------------------------------------------------

MISMATCH = "Arguments do not match the pinned MCP input schema."
ARG_REFUSALS = [
    (one({"type": "string"}), {"v": 1}, MISMATCH),
    (one({"type": "integer"}), {"v": True}, MISMATCH),
    (one({"type": "number"}), {"v": True}, MISMATCH),
    (one({"type": "integer"}), {"v": 2.5}, MISMATCH),
    (one({"type": "boolean"}), {"v": 1}, MISMATCH),
    (one({"type": "null"}), {"v": 0}, MISMATCH),
    (one({"type": "array", "items": {"type": "string"}}), {"v": "a"}, MISMATCH),
    (one({"type": "array", "items": {"type": "string"}}), {"v": [1]}, MISMATCH),
    (obj(v=obj(w={"type": "string"})), {"v": {"w": 1}}, MISMATCH),
    (one({"type": "string", "enum": ["a", "b"]}), {"v": "c"}, ENUM_OUT),
    (one({"type": ["integer", "boolean"], "enum": [1]}), {"v": True}, ENUM_OUT),
    (one({"type": "string", "const": "x"}), {"v": "y"}, CONST_OUT),
    (one({"type": ["integer", "boolean"], "const": 1}), {"v": True}, CONST_OUT),
    (one({"type": "string", "minLength": 3}), {"v": "ab"}, SIZE),
    (one({"type": "string", "maxLength": 2}), {"v": "abc"}, SIZE),
    (one({"type": "array", "items": {"type": "integer"}, "minItems": 2}), {"v": [1]}, SIZE),
    (one({"type": "array", "items": {"type": "integer"}, "maxItems": 1}), {"v": [1, 2]}, SIZE),
    (one({"type": "object", "minProperties": 1}), {"v": {}}, SIZE),
    (one({"type": "object", "maxProperties": 1}), {"v": {"a": 1, "b": 2}}, SIZE),
    (one({"type": "string"}) | {"required": ["v"]}, {}, REQ_EXTRA),
    (one({"type": "string"}) | {"additionalProperties": False}, {"v": "a", "x": "b"}, REQ_EXTRA),
    (
        one({"type": "array", "items": {"type": "integer"}, "uniqueItems": True}),
        {"v": [1, 1.0]},
        "Arguments require unique array items.",
    ),
    (one({"type": "number", "minimum": 10}), {"v": 9}, RANGE),
    (one({"type": "number", "maximum": 10}), {"v": 11}, RANGE),
    (one({"type": "number", "exclusiveMinimum": 10}), {"v": 10}, RANGE),
    (one({"type": "integer", "exclusiveMaximum": 10}), {"v": 10}, RANGE),
    (one({"oneOf": [{"type": "string"}, {"type": "integer"}]}), {"v": True}, ALTS),
    (one({"oneOf": [{"type": "number"}, {"type": "integer"}]}), {"v": 5}, ALTS),
    (one({"anyOf": [{"type": "string"}, {"type": "integer"}]}), {"v": None}, ALTS),
]


@pytest.mark.parametrize(("schema", "value", "message"), ARG_REFUSALS)
def test_validate_arguments_refuses(schema, value, message):
    refuses("invalid_arguments", message, ms.validate_arguments, schema, value)


def test_validate_arguments_accepts_the_nearest_valid_forms():
    cases = [
        (one({"type": "integer"}), {"v": 2.0}),
        (one({"type": "integer"}), {"v": 42}),
        (one({"type": "number"}), {"v": 2}),
        (one({"type": ["string", "null"]}), {"v": None}),
        (one({"type": "string", "enum": ["a", "b"]}), {"v": "a"}),
        (one({"type": "integer", "enum": [1]}), {"v": 1.0}),
        (one({"type": "string", "const": "x"}), {"v": "x"}),
        (one({"type": "string", "minLength": 2, "maxLength": 2}), {"v": "ab"}),
        (
            one({"type": "array", "items": {"type": "string"}, "uniqueItems": True}),
            {"v": ["a", "b"]},
        ),
        (one({"type": "number", "minimum": 5, "maximum": 5}), {"v": 5}),
        (one({"type": "number", "exclusiveMinimum": 5, "exclusiveMaximum": 6}), {"v": 5.5}),
        (one({"anyOf": [{"type": "number"}, {"type": "integer"}]}), {"v": 5}),
        (one({"oneOf": [{"type": "string"}, {"type": "integer"}]}), {"v": 5}),
        (
            one({"type": "string"}) | {"required": ["v"], "additionalProperties": False},
            {"v": "a"},
        ),
        (one({"type": "string"}), {"undeclared": 1}),
    ]
    for schema, value in cases:
        ms.validate_arguments(schema, value)


def test_validate_arguments_reports_bounded_and_schema_errors():
    refuses(
        "invalid_json",
        "Use finite JSON values.",
        ms.validate_arguments,
        one({"type": "number"}),
        {"v": float("nan")},
    )
    refuses(
        "unsupported_schema",
        "The MCP input schema must declare type object.",
        ms.validate_arguments,
        {"type": "string"},
        "x",
    )


def test_validate_arguments_visit_budget():
    schema = obj(
        v={"type": "array", "items": {"anyOf": [*[{"type": "string"}] * 7, {"type": "integer"}]}}
    )
    ms.validate_arguments(schema, {"v": list(range(1000))})
    refuses(
        "value_too_complex",
        "Arguments exceed the bounded schema validation budget.",
        ms.validate_arguments,
        schema,
        {"v": list(range(2000))},
    )


# parameter_headers ----------------------------------------------------------------------


def wrapped(text):
    return "=?base64?" + base64.b64encode(text.encode()).decode("ascii") + "?="


def header_for(kind, value):
    schema = one({"type": kind, "x-mcp-header": "H"})
    return ms.parameter_headers(schema, {"v": value})["Mcp-Param-H"]


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        ("string", "plain ascii~", "plain ascii~"),
        ("string", "tab\tinside", "tab\tinside"),
        ("string", " leading", wrapped(" leading")),
        ("string", "trailing ", wrapped("trailing ")),
        ("string", "héllo", wrapped("héllo")),
        ("string", "new\nline", wrapped("new\nline")),
        ("string", "del\x7f", wrapped("del\x7f")),
        ("string", "=?base64?dGVzdA==?=", wrapped("=?base64?dGVzdA==?=")),
        ("string", "=?base64?no end", "=?base64?no end"),
        ("boolean", True, "true"),
        ("boolean", False, "false"),
        ("integer", 7, "7"),
        ("integer", 3.0, "3"),
        ("integer", -(2**53 - 1), str(-(2**53 - 1))),
        ("integer", 2**53 - 1, str(2**53 - 1)),
    ],
)
def test_parameter_header_encoding(kind, value, expected):
    assert header_for(kind, value) == expected


@pytest.mark.parametrize("value", [2**53, -(2**53), float(2**60)])
def test_header_integer_range(value):
    refuses(
        "invalid_arguments",
        HDR_INT,
        ms.parameter_headers,
        one({"type": "integer", "x-mcp-header": "H"}),
        {"v": value},
    )


def test_header_value_byte_limit():
    assert header_for("string", "x" * 8192) == "x" * 8192
    refuses(
        "invalid_arguments",
        "An MCP parameter header exceeds its byte limit.",
        ms.parameter_headers,
        one({"type": "string", "x-mcp-header": "H"}),
        {"v": "x" * 8193},
    )


def test_header_total_byte_limit():
    def many(count):
        schema = obj(**{f"v{i}": {"type": "string", "x-mcp-header": f"H{i}"} for i in range(count)})
        return schema, {f"v{i}": "x" * 8000 for i in range(count)}

    assert len(ms.parameter_headers(*many(2))) == 2
    refuses(
        "invalid_arguments",
        "MCP parameter headers exceed their total byte limit.",
        ms.parameter_headers,
        *many(3),
    )


def test_parameter_headers_skip_null_missing_and_follow_nested_objects():
    schema = obj(
        a={"type": ["string", "null"], "x-mcp-header": "A"},
        b={"type": "string", "x-mcp-header": "B"},
        inner=obj(c={"type": "string", "x-mcp-header": "C"}),
    )
    assert ms.parameter_headers(schema, {"a": None, "inner": {"c": "deep"}}) == {
        "Mcp-Param-C": "deep"
    }
    assert ms.parameter_headers(schema, {}) == {}
