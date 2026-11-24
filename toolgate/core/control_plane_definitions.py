"""Owner definitions: services, verification methods, tools and automations (create and update).

Split from control_plane.py (a move): every call into the store goes through the `cp` module, so a
test that patches control_plane._put still reaches it. Import control_plane, not this module; it
re-exports these names."""

from __future__ import annotations

import uuid
from typing import Literal, overload

from toolgate.core import control_plane as cp
from toolgate.core.control_plane_rules import with_default_limits

_FIXED = {"id", "created_at", "updated_at"}


def create_service(body: dict) -> dict:
    service_id = body.get("id") or body["name"].lower().replace(" ", "-")
    return cp._put(
        "service",
        service_id,
        {
            "name": body["name"],
            "description": body.get("description", ""),
            "secret_refs": body.get("secret_refs", []),
            "health": body.get("health", "unknown"),
            "destination_policy": body.get("destination_policy", {}),
            "status": body.get("status", "active"),
        },
    )


def update_service(service_id: str, changes: dict) -> dict | None:
    allowed = {key: value for key, value in changes.items() if key not in _FIXED}
    return cp._change("service", service_id, lambda service: {**service, **allowed})


def create_verification_method(body: dict) -> dict:
    method_id = body.get("id") or str(uuid.uuid4())
    return cp._put(
        "verification_method",
        method_id,
        {
            "name": body.get("name", "Verification adapter"),
            "method_type": body.get("method_type", "signed_callback"),
            "secret_ref": body.get("secret_ref"),
            "status": body.get("status", "active"),
            "last_seen_at": body.get("last_seen_at"),
        },
    )


def update_verification_method(method_id: str, changes: dict) -> dict | None:
    allowed = {key: value for key, value in changes.items() if key not in _FIXED}
    return cp._change("verification_method", method_id, lambda method: {**method, **allowed})


@overload
def create_tool(
    body: dict, *, require_existing: Literal[False] = False, require_absent: bool = False
) -> dict: ...


@overload
def create_tool(
    body: dict, *, require_existing: bool, require_absent: bool = False
) -> dict | None: ...


def create_tool(
    body: dict, *, require_existing: bool = False, require_absent: bool = False
) -> dict | None:
    tool_id = body["id"]
    return cp._put(
        "tool",
        tool_id,
        {
            "name": body.get("name", tool_id),
            "description": body.get("description", ""),
            "service_id": body.get("service_id"),
            "category": body.get("category", "controlled"),
            "inputs": body.get("inputs", []),
            "outputs": body.get("outputs", []),
            "execution": body.get("execution", {}),
            "policy": with_default_limits(body.get("policy")),
            "authorization": body.get("authorization", "auto"),
            "version": body.get("version", 1),
            "status": body.get("status", "active"),
        },
        expected_version=body.get("expected_version"),
        require_existing=require_existing,
        require_absent=require_absent,
    )


def update_tool(tool_id: str, body: dict) -> dict | None:
    return create_tool({**body, "id": tool_id}, require_existing=True)


@overload
def create_automation(
    body: dict, *, require_existing: Literal[False] = False, require_absent: bool = False
) -> dict: ...


@overload
def create_automation(
    body: dict, *, require_existing: bool, require_absent: bool = False
) -> dict | None: ...


def create_automation(
    body: dict, *, require_existing: bool = False, require_absent: bool = False
) -> dict | None:
    automation_id = body["id"]
    return cp._put(
        "automation",
        automation_id,
        {
            "name": body.get("name", automation_id),
            "description": body.get("description", ""),
            "inputs": body.get("inputs", []),
            "workflow": body.get("workflow", []),
            "policy": with_default_limits(body.get("policy")),
            "authorization": body.get("authorization", "auto"),
            "schedule": body.get("schedule"),
            "version": body.get("version", 1),
            "status": body.get("status", "draft"),
        },
        expected_version=body.get("expected_version"),
        require_existing=require_existing,
        require_absent=require_absent,
    )


def update_automation(automation_id: str, body: dict) -> dict | None:
    return create_automation({**body, "id": automation_id}, require_existing=True)
