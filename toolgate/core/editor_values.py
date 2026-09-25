"""Strict value semantics shared by editor graph execution and its receipts."""
from __future__ import annotations

import copy
import json
import math


class GraphValueError(ValueError):
    pass


def bounded(value):
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > 12000 or depth > 20:
            raise GraphValueError("Value structure exceeds the execution limit.")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise GraphValueError("Object keys must be strings.")
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif type(item) in (int, float):
            if (isinstance(item, float) and not math.isfinite(item)) or abs(item) > 9007199254740991:
                raise GraphValueError("Number cannot be represented safely in the editor.")
        elif not isinstance(item, (str, bool, type(None))):
            raise GraphValueError("Only JSON values are supported.")
    try:
        if len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")) > 65536:
            raise GraphValueError("Value exceeds the execution byte limit.")
    except (ValueError, UnicodeError, RecursionError) as error:
        raise GraphValueError("Value cannot be encoded as bounded JSON.") from error
    return copy.deepcopy(value)


def matches(value, field_type):
    return {"string": isinstance(value, str), "number": type(value) in (int, float),
            "boolean": type(value) is bool, "array": isinstance(value, list),
            "object": isinstance(value, dict)}.get(field_type, False)


def inputs(fields, supplied):
    if not isinstance(supplied, dict):
        raise GraphValueError("Inputs must be an object.")
    bounded(supplied)
    if set(supplied) - {field.name for field in fields}:
        raise GraphValueError("An input is not declared in the schema.")
    result = copy.deepcopy(supplied)
    for field in fields:
        if field.name not in result and "default" in field.model_fields_set:
            result[field.name] = copy.deepcopy(field.default)
        if field.name not in result:
            if field.required:
                raise GraphValueError(f"Missing required input: {field.name}.")
        elif not matches(result[field.name], field.type):
            raise GraphValueError(f"Input type does not match: {field.name}.")
    return bounded(result)


def resolve(value, supplied, steps, last, *, allow_missing=False):
    if isinstance(value, list):
        return [resolve(item, supplied, steps, last, allow_missing=allow_missing) for item in value]
    if isinstance(value, dict):
        return {key: resolve(item, supplied, steps, last, allow_missing=allow_missing) for key, item in value.items()}
    if not isinstance(value, str) or not value.startswith("$"):
        return value
    if value.startswith("$$"):
        return value[1:]
    root, *parts = value[1:].split(".")
    if root not in {"input", "steps", "last"} or any(part in {"", "__proto__", "constructor", "prototype"} for part in parts):
        raise GraphValueError("Invalid value reference.")
    current = {"input": supplied, "steps": steps, "last": last}[root]
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isascii() and part.isdigit() and str(int(part)) == part and int(part) < len(current):
            current = current[int(part)]
        else:
            if allow_missing:
                return None
            raise GraphValueError("Referenced value is unavailable on this execution path.")
    return copy.deepcopy(current)


def equal(left, right):
    # Python bool is an int subclass; JSON booleans must never equal numbers here.
    if type(left) in (int, float) and type(right) in (int, float):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(equal(a, b) for a, b in zip(left, right, strict=True))
    return left == right


def compare(operator, left, right):
    if operator == "exists":
        return left is not None
    if operator == "equals":
        return equal(left, right)
    if operator in {"greater", "less"}:
        if type(left) not in (int, float) or type(right) not in (int, float):
            raise GraphValueError("Ordered comparisons require numbers.")
        return left > right if operator == "greater" else left < right
    if operator == "contains":
        if isinstance(left, str) and isinstance(right, str):
            return right in left
        return isinstance(left, list) and any(equal(item, right) for item in left)
    raise GraphValueError("Unsupported comparison operator.")
