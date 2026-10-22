"""Agent-facing system routes: port reviews and finalization, targets, services and file roots."""

import json
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from toolgate.api.deps import deny, require_agent
from toolgate.api.invocation import enforce_usage_limits, require_current_dispatch_authority
from toolgate.api.models import PortFinalizationRequest, PortReviewRequest
from toolgate.core import approvals, control_plane, port_finalization, port_reviews
from toolgate.core import execution_journal as journal
from toolgate.executors import (
    container_control,
    filesystem_inventory,
    port_control,
    port_recovery,
    process_control,
)
from toolgate.executors.port_plan import PlanError

router = APIRouter()


def _port_review_authority(agent):
    tool = control_plane.get("tool", "system.port-control")
    if (
        not control_plane.is_scoped(agent, "system.port-control")
        or not tool
        or tool.get("status") != "active"
        or tool.get("authorization") != "owner_confirmation"
        or tool.get("execution") != {"type": "port_control"}
    ):
        deny("POLICY_DENIED", "Active port replacement scope is required", 403)
    with control_plane._conn() as conn:
        require_current_dispatch_authority(conn, agent["id"], "system.port-control")
    return tool


@router.post("/v2/agent/system/port-reviews")
def create_port_review(payload: PortReviewRequest, agent: dict = Depends(require_agent)):
    tool = _port_review_authority(agent)
    enforce_usage_limits("tool", tool, "port_review_created")
    try:
        replacement = port_control.inspect_review(
            payload.container_id,
            payload.operation,
            mapping=payload.mapping.model_dump() if payload.mapping else None,
            original=payload.original.model_dump() if payload.original else None,
        )
        _port_review_authority(agent)
        result = port_reviews.create(agent["id"], replacement)
    except (container_control.ControlError, PlanError, port_reviews.ReviewError) as exc:
        deny("REVIEW_UNAVAILABLE", str(exc), 422)
    control_plane.event("port_review_created", "info", "tool", "system.port-control", agent["name"])
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@router.get("/v2/agent/system/port-reviews/{review_id}")
def get_port_review(review_id: str, agent: dict = Depends(require_agent)):
    _port_review_authority(agent)
    try:
        result = port_reviews.get(review_id, agent["id"])
    except port_reviews.ReviewError:
        deny("REVIEW_UNAVAILABLE", "Port review is unavailable", 404)
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@router.get("/v2/agent/system/port-recovery/{action_id:path}")
def inspect_port_recovery(action_id: str, agent: dict = Depends(require_agent)):
    _port_review_authority(agent)
    try:
        result = port_recovery.inspect(action_id, agent["id"])
        _port_review_authority(agent)
    except (port_recovery.RecoveryError, ValueError):
        deny("RECOVERY_UNAVAILABLE", "Replacement recovery evidence is unavailable", 409)
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@router.post("/v2/agent/system/port-finalizations")
def finalize_port_recovery(
    payload: PortFinalizationRequest, agent: Annotated[dict, Depends(require_agent)]
):
    tool = _port_review_authority(agent)
    parent = journal.get(payload.action_id)
    if (
        not parent
        or parent["actor_id"] != agent["id"]
        or parent["subject_type"] != "tool"
        or parent["subject_id"] != "system.port-control"
    ):
        deny("RECOVERY_UNAVAILABLE", "Replacement recovery is unavailable", 409)
    # Lost recovery acknowledgements read the immutable receipt without another effect.
    if parent["status"] == "completed":
        return JSONResponse(journal.response(parent), headers={"Cache-Control": "no-store"})
    args = {
        "operation": "recover_verified_receipt",
        "action_id": payload.action_id,
        "fingerprint": parent["fingerprint"],
    }
    try:
        receipt = port_finalization.preview(payload.action_id, agent["id"])
        if not payload.approval_request_id:
            enforce_usage_limits("tool", tool, "port_finalization_requested")
            request = approvals.create_verification_request(
                "Recover verified port replacement receipt",
                "Restore the recorded successful result and release its reservation. "
                "No container changes will run. Recovery may recheck Docker inspection. "
                + json.dumps(receipt),
                agent["name"],
                "tool",
                "system.port-control",
                args,
                tool.get("version"),
                60,
                agent["id"],
            )
            control_plane.event(
                "port_finalization_requested", "info", "tool", "system.port-control", agent["name"]
            )
            return JSONResponse(
                {
                    "code": "CONFIRMATION_REQUIRED",
                    "request_id": request["id"],
                    "expires_at": request["payload"]["binding"]["expires_at"],
                },
                headers={"Cache-Control": "no-store"},
            )

        def authorize(conn):
            require_current_dispatch_authority(conn, agent["id"], "system.port-control")
            row = conn.execute(
                "SELECT * FROM v2_objects WHERE kind='tool' AND id='system.port-control'"
            ).fetchone()
            current = control_plane._row(row) if row else {}
            if (
                current.get("version") != tool.get("version")
                or current.get("status") != "active"
                or current.get("authorization") != "owner_confirmation"
                or current.get("execution") != {"type": "port_control"}
            ):
                deny("POLICY_DENIED", "Port replacement policy changed", 403)
            approved, reason = approvals.consume_verification_in_transaction(
                conn,
                payload.approval_request_id,
                "tool",
                "system.port-control",
                args,
                tool.get("version"),
                agent["name"],
                agent["id"],
            )
            if not approved:
                deny("APPROVAL_INVALID", reason, 409)

        record = port_finalization.finalize(payload.action_id, agent["id"], authorize=authorize)
    except (ValueError, container_control.ControlError):
        deny("RECOVERY_UNAVAILABLE", "Replacement recovery is unavailable", 409)
    return JSONResponse(journal.response(record), headers={"Cache-Control": "no-store"})


@router.get("/v2/agent/system/targets")
def agent_system_targets(agent: dict = Depends(require_agent)):
    tool_id = "system.container-control"
    if not control_plane.is_scoped(agent, tool_id):
        deny("POLICY_DENIED", "Managed container scope is required", 403)
    result = {
        "kind": "configured-targets",
        "status": "configured",
        "containers": [],
        "actions": [],
        "requiresApproval": True,
        "observed": False,
        "source": "toolgate/container-control",
    }
    tool = control_plane.get("tool", tool_id)
    if control_plane.settings().get("lockdown"):
        result["status"] = "locked_down"
    elif (
        not tool
        or tool.get("status") != "active"
        or tool.get("authorization") != "owner_confirmation"
        or tool.get("execution") != {"type": "container_control"}
    ):
        result["status"] = "disabled"
    else:
        try:
            result["containers"] = container_control.targets()
            result["actions"] = ["start", "stop", "restart"]
        except container_control.ControlError as exc:
            result["status"] = exc.code
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@router.get("/v2/agent/system/services")
def agent_system_services(agent: dict = Depends(require_agent)):
    tool_id = "system.process-control"
    if not control_plane.is_scoped(agent, tool_id):
        deny("POLICY_DENIED", "Managed service scope is required", 403)
    result = {
        "kind": "configured-targets",
        "status": "configured",
        "services": [],
        "actions": [],
        "requiresApproval": True,
        "observed": False,
        "source": "toolgate/process-control",
    }
    tool = control_plane.get("tool", tool_id)
    if control_plane.settings().get("lockdown"):
        result["status"] = "locked_down"
    elif (
        not tool
        or tool.get("status") != "active"
        or tool.get("authorization") != "owner_confirmation"
        or tool.get("execution") != {"type": "process_control"}
    ):
        result["status"] = "disabled"
    else:
        try:
            result["services"] = process_control.targets()
            result["actions"] = ["start", "stop", "restart"]
        except process_control.ControlError as exc:
            result["status"] = exc.code
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@router.get("/v2/agent/system/file-roots")
def agent_file_roots(agent: dict = Depends(require_agent)):
    tool_id = "system.files-list"
    if not control_plane.is_scoped(agent, tool_id):
        deny("POLICY_DENIED", "Directory listing scope is required", 403)
    tool = control_plane.get("tool", tool_id)
    if (
        control_plane.settings().get("lockdown")
        or not tool
        or tool.get("status") != "active"
        or tool.get("authorization") == "blocked"
        or tool.get("execution") != {"type": "filesystem_inventory"}
    ):
        return JSONResponse(
            {"mode": "unavailable", "code": "disabled", "roots": []},
            headers={"Cache-Control": "no-store"},
        )
    try:
        result = filesystem_inventory.roots()
    except filesystem_inventory.FileError as exc:
        result = {"mode": "unavailable", "code": exc.code, "roots": []}
    return JSONResponse(result, headers={"Cache-Control": "no-store"})
