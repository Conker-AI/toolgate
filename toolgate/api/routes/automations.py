"""Owner automation catalogue and the agent's automation run route."""

import time

from fastapi import APIRouter, Depends, HTTPException

from toolgate.api.definitions import require_valid_automation_definition, workflow_tool_ids
from toolgate.api.deps import deny, require_admin, require_agent
from toolgate.api.invocation import (
    enforce_dispatch_usage_limits,
    require_current_dispatch_authority,
)
from toolgate.api.models import V2Automation, V2Invoke
from toolgate.api.routes.publications import _requested_publication
from toolgate.api.workflows import _automation_input_errors, _run_workflow_steps
from toolgate.core import approvals, control_plane, publications
from toolgate.core import execution_journal as journal

router = APIRouter()


@router.get("/v2/automations")
def list_automations(_tier: str = Depends(require_admin)):
    return control_plane.list_objects("automation")


@router.get("/v2/automations/{automation_id}")
def get_automation(automation_id: str, _tier: str = Depends(require_admin)):
    automation = control_plane.get("automation", automation_id)
    if not automation:
        raise HTTPException(404, "automation not found")
    return automation


@router.post("/v2/automations")
def create_automation(payload: V2Automation, _tier: str = Depends(require_admin)):
    body = payload.model_dump()
    require_valid_automation_definition(body)
    # Creating needs no version; replacing an existing workflow needs the one the caller saw.
    automation = control_plane.create_automation(
        body, require_absent=body.get("expected_version") is None
    )
    control_plane.event("automation_saved", "info", "automation", automation["id"], "admin")
    return automation


@router.put("/v2/automations/{automation_id}")
def update_automation(
    automation_id: str, payload: V2Automation, _tier: str = Depends(require_admin)
):
    body = payload.model_dump()
    require_valid_automation_definition(body)
    automation = control_plane.update_automation(automation_id, body)
    if not automation:
        raise HTTPException(404, "automation not found")
    control_plane.event(
        "automation_updated",
        "info",
        "automation",
        automation_id,
        "admin",
        {"version": automation["version"]},
    )
    return automation


@router.delete("/v2/automations/{automation_id}")
def delete_automation(automation_id: str, _tier: str = Depends(require_admin)):
    if not control_plane.remove("automation", automation_id):
        raise HTTPException(404, "automation not found")
    control_plane.event("automation_deleted", "warning", "automation", automation_id, "admin")
    return {"deleted": True, "id": automation_id}


@router.post("/v2/automations/{automation_id}/run")
def run_automation(automation_id: str, payload: V2Invoke, agent: dict = Depends(require_agent)):
    publication = _requested_publication("automation", automation_id, payload)
    publication_digest = publication["digest"] if publication else None
    automation = (
        publication["definition"] if publication else control_plane.get("automation", automation_id)
    )
    if not automation or automation.get("status") != "active":
        deny("TOOL_UNAVAILABLE", "Automation is not active", 404)
    if not control_plane.is_scoped(agent, f"automation:{automation_id}"):
        deny("POLICY_DENIED", "Your agent key is not allowed to run this automation")
    if not publication and any(
        step.get("type") == "editor_graph" for step in automation.get("workflow", [])
    ):
        deny("PUBLICATION_REQUIRED", "Editor graphs require an immutable published version", 422)
    if not publication and workflow_tool_ids(automation.get("workflow", []), "automation_call"):
        deny(
            "PUBLICATION_REQUIRED",
            "Nested automation calls require an explicit published root version",
            422,
        )
    authority_scope = (
        tuple(
            dict.fromkeys(
                f"automation:{member['id']}" for member in publications.members(publication)
            )
        )
        if publication
        else (f"automation:{automation_id}",)
    )
    if not all(control_plane.is_scoped(agent, scope) for scope in authority_scope):
        deny("POLICY_DENIED", "The agent needs every pinned nested automation scope", 403)
    if not payload.action_id:
        deny("ACTION_ID_REQUIRED", "Supply a stable action_id for this workflow run", 422)
    try:
        previous = journal.existing(
            payload.action_id,
            "automation",
            automation_id,
            payload.args,
            agent["id"],
            payload.job_id,
            publication_digest=publication_digest,
        )
    except (journal.ExecutionConflict, ValueError) as exc:
        deny("ACTION_CONFLICT", str(exc), 409)
    if previous:
        return journal.response(previous)
    if control_plane.settings().get("lockdown"):
        deny("LOCKED_DOWN", "ToolGate is in lockdown mode", 423)
    errors = _automation_input_errors(automation, payload.args)
    if errors:
        deny("VALIDATION_ERROR", "; ".join(errors), 422)
    authorization = automation.get("authorization", "auto")
    if authorization == "blocked":
        control_plane.event(
            "execution_blocked",
            "warning",
            "automation",
            automation_id,
            agent["name"],
            {"code": "POLICY_DENIED"},
        )
        deny("POLICY_DENIED", "This automation is permanently blocked by its owner policy")
    approval_granted = False
    tool_snapshot = {}
    if authorization != "auto" and not payload.approval_request_id:
        expiry = int(control_plane.settings().get("default_confirmation_expiry_seconds", 60))
        request = approvals.create_verification_request(
            f"Run {automation['name']}",
            "Owner confirmation is required for this exact immutable automation run.",
            agent["name"],
            "automation",
            automation_id,
            payload.args,
            automation.get("version"),
            expiry,
            agent["id"],
            publication_digest=publication_digest,
        )
        return {
            "code": "CONFIRMATION_REQUIRED",
            "message": "Automation queued for owner review",
            "request_id": request["id"],
            "expires_at": request["payload"]["binding"]["expires_at"],
            "next_action": f"After approval, retry with --approval-request-id {request['id']}",
        }
    limits = automation.get("policy", {}).get("usage_limits", {})

    def authorize(conn):
        nonlocal approval_granted, tool_snapshot
        require_current_dispatch_authority(conn, agent["id"], authority_scope)
        if publication:
            tool_snapshot = publications.for_execution(
                conn, "automation", automation_id, publication["version"]
            )["tools"]
        else:
            tool_snapshot = approvals.automation_tool_snapshot(
                conn, automation_id, automation.get("version")
            )
        enforce_dispatch_usage_limits(conn, "automation", automation, "automation_executed")
        if authorization != "auto":
            approval_granted, reason = approvals.consume_verification_in_transaction(
                conn,
                payload.approval_request_id,
                "automation",
                automation_id,
                payload.args,
                automation.get("version"),
                agent["name"],
                agent["id"],
                publication_digest=publication_digest,
            )
            if not approval_granted:
                deny("APPROVAL_INVALID", reason, 409)

    try:
        record, dispatch = journal.begin(
            payload.action_id,
            "automation",
            automation_id,
            payload.args,
            agent["id"],
            automation.get("version"),
            job_id=payload.job_id,
            authorize=authorize,
            publication_digest=publication_digest,
        )
    except (journal.ExecutionConflict, ValueError) as exc:
        deny("ACTION_CONFLICT", str(exc), 409)
    if not dispatch:
        return journal.response(record)
    state = {
        "automation_id": automation_id,
        "tool_snapshot": tool_snapshot,
        "action_id": payload.action_id,
        "publication": publication,
        "authority_scope": authority_scope,
        "job_id": payload.job_id,
        "actor_id": agent["id"],
        "args": payload.args,
        "vars": {},
        "last": None,
        "results": [],
        "count": 0,
        "max_steps": int(limits.get("max_steps", 100)),
        "started_at": time.monotonic(),
        "runtime_ceiling": min(int(limits.get("max_runtime_seconds", 30) or 30), 120),
    }
    try:
        final = _run_workflow_steps(
            automation.get("workflow", []), state, agent["name"], approval_granted
        )
    except Exception:
        journal.unknown(payload.action_id)
        return journal.response(journal.get(payload.action_id))
    failed = isinstance(final, dict) and final.get("code") == "WORKFLOW_FAILED"
    envelope = {
        "code": "WORKFLOW_FAILED" if failed else "OK",
        "message": "Workflow failed" if failed else "Automation completed",
        "result": final,
        "steps": state["results"],
        "variables": state["vars"],
    }
    if publication:
        envelope["publication"] = {
            "kind": "automation",
            "id": automation_id,
            "version": publication["version"],
            "digest": publication_digest,
        }
    record = journal.finish(payload.action_id, envelope)
    control_plane.event(
        "automation_executed",
        "info",
        "automation",
        automation_id,
        agent["name"],
        {
            "steps": state["count"],
            "version": automation.get("version"),
            "action_id": payload.action_id,
        },
    )
    return journal.response(record)
