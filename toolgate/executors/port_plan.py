"""Exact port-binding change previews. No Docker calls or effect execution."""

import hashlib
import ipaddress
import json
import re


class PlanError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(
            {
                "invalid": "Port mapping data is invalid.",
                "missing": "The original mapping is no longer present.",
                "conflict": "The host address, port and protocol conflict.",
                "unsupported": "This container needs a different port reconfiguration path.",
            }[code]
        )


def _mapping(value, *, editable=False):
    keys = {"hostAddress", "hostPort", "containerPort", "protocol"}
    if not isinstance(value, dict) or set(value) != keys:
        raise PlanError("invalid")
    if value["protocol"] not in ("tcp", "udp"):
        raise PlanError("invalid")
    for key in ("hostPort", "containerPort"):
        if type(value[key]) is not int or not 1 <= value[key] <= 65535:
            raise PlanError("invalid")
    try:
        address = str(ipaddress.ip_address(value["hostAddress"]))
    except (ValueError, TypeError):
        raise PlanError("invalid") from None
    if not isinstance(value["hostAddress"], str):
        raise PlanError("invalid")
    if editable and address not in ("127.0.0.1", "0.0.0.0"):
        raise PlanError("invalid")
    return {**value, "hostAddress": address}


def _identity(value):
    return tuple(
        value[key] for key in ("protocol", "hostAddress", "hostPort", "containerPort")
    )


def _conflicts(first, second):
    if (
        first["protocol"] != second["protocol"]
        or first["hostPort"] != second["hostPort"]
    ):
        return False
    a, b = (
        ipaddress.ip_address(first["hostAddress"]),
        ipaddress.ip_address(second["hostAddress"]),
    )
    # IPv6 wildcard can bind IPv4 too; do not promise coexistence without a daemon check.
    return a == b or a.is_unspecified or b.is_unspecified


def plan(
    container_id,
    current,
    operation,
    *,
    mapping=None,
    original=None,
    running=False,
    network_mode="bridge",
    publish_all=False,
    auto_remove=False,
):
    """Preview one container's exact binding delta; no cross-host availability claim."""
    if (
        not isinstance(container_id, str)
        or not re.fullmatch(r"[a-f0-9]{64}", container_id)
        or not isinstance(current, list)
        or len(current) > 200
        or operation not in ("create", "edit", "remove")
        or type(running) is not bool
        or type(publish_all) is not bool
        or type(auto_remove) is not bool
    ):
        raise PlanError("invalid")
    if (
        not isinstance(network_mode, str)
        or network_mode in ("host", "none")
        or network_mode.startswith("container:")
        or publish_all
        or auto_remove
    ):
        raise PlanError("unsupported")
    before = [_mapping(item) for item in current]
    if len({_identity(item) for item in before}) != len(before):
        raise PlanError("invalid")
    before.sort(key=_identity)
    after = [dict(item) for item in before]
    if operation in ("edit", "remove"):
        old = _mapping(original)
        if old not in after:
            raise PlanError("missing")
        after.remove(old)
    elif original is not None:
        raise PlanError("invalid")
    if operation in ("create", "edit"):
        new = _mapping(mapping, editable=True)
        if any(_conflicts(item, new) for item in after):
            raise PlanError("conflict")
        after.append(new)
    elif mapping is not None:
        raise PlanError("invalid")
    if len(after) > 200:
        raise PlanError("invalid")
    after.sort(key=_identity)
    changed = before != after
    result = {
        "containerId": container_id,
        "operation": operation,
        "before": before,
        "after": after,
        "changed": changed,
        "requiresReplacement": changed,
        "downtimeExpected": changed and running,
        "hostAvailability": "not_checked",
        "execution": "not_implemented",
        "networkMode": network_mode,
    }
    result["bindingsDigest"] = hashlib.sha256(
        json.dumps(
            {"containerId": container_id, "bindings": before},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return result
