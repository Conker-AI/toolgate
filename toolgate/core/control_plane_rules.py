"""Stateless control-plane rules: agent scope matching, tool argument validation, default limits.

Nothing here touches storage. control_plane re-exports these names for its callers.
"""

from __future__ import annotations

import json
import re


def is_scoped(agent: dict, capability: str) -> bool:
    # An agent identity is always capped by the key that presents it.
    if "ceiling" in agent and not _scoped(agent["ceiling"], capability):
        return False
    return _scoped(agent.get("scopes", []), capability)


def _scoped(scopes: list, capability: str) -> bool:
    if "*" in scopes or capability in scopes:
        return True
    if any(
        isinstance(scope, str) and scope.endswith("*") and capability.startswith(scope[:-1])
        for scope in scopes
    ):
        return True
    if capability.startswith("automation:"):
        return "automation:*" in scopes
    tool_id = capability.removeprefix("tool:")
    return (
        "tool:*" in scopes
        or f"tool:{tool_id}" in scopes
        or tool_id in scopes
        or any(
            isinstance(scope, str) and scope.endswith("*") and tool_id.startswith(scope[:-1])
            for scope in scopes
        )
        or any(
            isinstance(scope, str)
            and scope.startswith("tool:")
            and scope.endswith("*")
            and tool_id.startswith(scope[5:-1])
            for scope in scopes
        )
    )


def validate_inputs(schema: list[dict], args: dict) -> list[str]:
    errors: list[str] = []
    known = {field.get("name") for field in schema}
    for key in args:
        if key not in known:
            errors.append(f"'{key}' is not an allowed argument")
    for field in schema:
        name, value = field.get("name"), args.get(field.get("name"))
        # A required field sent as null is as missing as one left out.
        if field.get("required") and value is None:
            errors.append(f"'{name}' is required")
            continue
        if value is None:
            continue
        kind = field.get("type", "string")
        if kind == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
            errors.append(f"'{name}' must be an integer")
        elif kind == "number" and (isinstance(value, bool) or not isinstance(value, (int, float))):
            errors.append(f"'{name}' must be a number")
        elif kind == "boolean" and not isinstance(value, bool):
            errors.append(f"'{name}' must be true or false")
        elif kind == "string" and not isinstance(value, str):
            errors.append(f"'{name}' must be text")
        elif kind == "array" and not isinstance(value, list):
            errors.append(f"'{name}' must be an array")
        elif kind == "object" and not isinstance(value, dict):
            errors.append(f"'{name}' must be an object")
        if isinstance(value, (int, float)):
            if field.get("minimum") is not None and value < field["minimum"]:
                errors.append(f"'{name}' must be at least {field['minimum']}")
            if field.get("maximum") is not None and value > field["maximum"]:
                errors.append(f"'{name}' must be at most {field['maximum']}")
        if isinstance(value, str):
            if field.get("min_length") is not None and len(value) < field["min_length"]:
                errors.append(f"'{name}' is too short")
            if field.get("max_length") is not None and len(value) > field["max_length"]:
                errors.append(f"'{name}' is too long")
            if field.get("pattern") and not re.search(field["pattern"], value):
                errors.append(f"'{name}' does not match the required format")
        if isinstance(value, list):
            if field.get("min_items") is not None and len(value) < field["min_items"]:
                errors.append(f"'{name}' must contain at least {field['min_items']} items")
            if field.get("max_items") is not None and len(value) > field["max_items"]:
                errors.append(f"'{name}' must contain at most {field['max_items']} items")
            if field.get("unique_items") and len(
                {json.dumps(item, sort_keys=True) for item in value}
            ) != len(value):
                errors.append(f"'{name}' must not contain duplicate items")
            if field.get("item_type") == "string" and any(
                not isinstance(item, str) for item in value
            ):
                errors.append(f"'{name}' items must be text")
            pattern = field.get("item_pattern")
            if pattern and any(
                not isinstance(item, str) or not re.fullmatch(pattern, item) for item in value
            ):
                errors.append(f"'{name}' contains an invalid item")
        allowed = field.get("allowed_values") or []
        if allowed and value not in allowed:
            errors.append(f"'{name}' must be one of: {', '.join(map(str, allowed))}")
    return errors


# A tool with no ceiling is a tool that can run until something else breaks -
# the disk, the rate limit of an upstream provider, or the owner's credit. The
# enforcement has always been here; what was missing was that an absent limit
# read as "unlimited" rather than as "nobody said, so be careful".
#
# Deliberately conservative. A tool that genuinely needs more says so
# explicitly, which makes it a decision someone made rather than an oversight.
DEFAULT_USAGE_LIMITS = {
    "max_per_minute": 6,
    "max_per_hour": 60,
    "max_runtime_seconds": 30,
    "cooldown_seconds": 0,
}


def with_default_limits(policy: dict | None) -> dict:
    """Fill in any ceiling the caller did not set.

    An explicit value always wins, including a deliberately high one - the
    point is not to cap what the owner chose, it is that nothing arrives
    uncapped by accident. `cooldown_seconds` is the exception that may legally
    be zero, so only genuinely missing keys are filled.
    """
    policy = dict(policy or {})
    limits = dict(policy.get("usage_limits") or {})
    for name, fallback in DEFAULT_USAGE_LIMITS.items():
        if limits.get(name) is None:
            limits[name] = fallback
    policy["usage_limits"] = limits
    return policy
