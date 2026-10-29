"""Owner workflow editor: drafts, validation, access, test runs and publishing."""

from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from toolgate.api.definitions import (
    capability_metadata_errors,
    require_valid_automation_definition,
    require_valid_tool_definition,
    tool_definition_errors,
)
from toolgate.api.deps import require_agent, require_owner, require_owner_or_agent
from toolgate.api.models import V2Invoke
from toolgate.api.routes.automations import run_automation
from toolgate.core import (
    control_plane,
    editor_catalogue,
    editor_check,
    editor_drafts,
    editor_graph,
    editor_publication,
    editor_runs,
)

router = APIRouter()


@router.get("/v2/owner/editor-capabilities", dependencies=[Depends(require_owner)])
def owner_editor_capabilities(
    kind: Literal["tool", "workflow"] = "tool",
    q: str = Query(default="", max_length=100),
    after: str | None = Query(default=None, max_length=80, pattern=r"^[a-z0-9][a-z0-9.-]{1,79}$"),
    limit: int = Query(default=50, ge=1, le=100),
):
    return editor_catalogue.list_capabilities(kind, q, after, limit)


@router.get("/v2/owner/editor-drafts", dependencies=[Depends(require_owner)])
def owner_editor_drafts(
    limit: int = Query(default=50, ge=1, le=100),
    after: str | None = Query(default=None, max_length=64),
):
    return editor_drafts.list_drafts(limit, after)


@router.get("/v2/owner/editor-drafts/{draft_id}", dependencies=[Depends(require_owner)])
def owner_editor_draft(draft_id: str):
    return editor_drafts.get(draft_id)


@router.get("/v2/owner/editor-drafts/{draft_id}/validation", dependencies=[Depends(require_owner)])
def validate_owner_editor_draft(draft_id: str):
    record = editor_drafts.get(draft_id)
    document = editor_drafts.EditorDocument.model_validate(record["document"])
    issues = editor_graph.validate_graph(document)
    return {
        "id": draft_id,
        "revision": record["revision"],
        "graph_valid": not issues,
        "issues": issues,
        "execution_ready": False,
    }


@router.post("/v2/editor/check", dependencies=[Depends(require_owner_or_agent)])
def check_editor_document(payload: editor_check.Check):
    """Check a document by the rules publishing applies. Saves, grants and runs nothing."""
    return editor_check.check(
        payload.document,
        metadata_errors=capability_metadata_errors,
        tool_errors=tool_definition_errors,
    )


@router.post("/v2/owner/editor-drafts/{draft_id}", dependencies=[Depends(require_owner)])
def save_owner_editor_draft(draft_id: str, payload: editor_drafts.SaveDraft):
    return editor_drafts.save(draft_id, payload)


@router.get("/v2/owner/editor-drafts/{draft_id}/publications", dependencies=[Depends(require_owner)])
def owner_editor_publications(draft_id: str):
    return {"items": editor_publication.history(draft_id)}


@router.get("/v2/owner/editor-drafts/{draft_id}/access", dependencies=[Depends(require_owner)])
def editor_access(
    draft_id: str,
    version: int = Query(ge=1),
    digest: str = Query(pattern=r"^[a-f0-9]{64}$"),
    agent: dict = Depends(require_agent),
):
    return editor_runs.access(draft_id, editor_runs.Target(version=version, digest=digest), agent)


@router.post("/v2/owner/editor-drafts/{draft_id}/access", dependencies=[Depends(require_owner)])
def change_editor_access(
    draft_id: str, payload: editor_runs.Access, agent: dict = Depends(require_agent)
):
    return editor_runs.access(draft_id, payload, agent, enabled=payload.enabled)


@router.get("/v2/owner/editor-drafts/{draft_id}/runs", dependencies=[Depends(require_owner)])
def owner_editor_runs(draft_id: str, agent: dict = Depends(require_agent)):
    return editor_runs.history(draft_id, agent)


@router.post("/v2/owner/editor-drafts/{draft_id}/runs", dependencies=[Depends(require_owner)])
def run_owner_editor_draft(
    draft_id: str, payload: editor_runs.Run, agent: dict = Depends(require_agent)
):
    publication, previous, dispatch = editor_runs.begin(draft_id, payload, agent)
    if not dispatch:
        return editor_runs._response(previous)
    try:
        result = run_automation(
            publication["id"],
            V2Invoke(
                args=payload.args,
                action_id=payload.action_id,
                approval_request_id=payload.approval_request_id,
                published_version=payload.version,
                expected_publication_digest=payload.digest,
            ),
            agent,
        )
    except HTTPException as exc:
        # A policy rejection is a known response. Any uncertain child dispatch is
        # already held by run_automation's journal; never try an alternate path.
        result = {
            "code": exc.detail.get("code", "REQUEST_REJECTED")
            if isinstance(exc.detail, dict)
            else "REQUEST_REJECTED",
            "message": "Run was rejected. Check publication availability, access and approval before creating another run.",
        }
        request = (
            control_plane.get("request", payload.approval_request_id)
            if payload.approval_request_id
            else None
        )
        if result["code"] == "APPROVAL_INVALID" and request and request.get("status") == "pending":
            result = {
                "code": "CONFIRMATION_REQUIRED",
                "request_id": payload.approval_request_id,
                "message": "Approval is still pending in Inbox. Resume this same run after approval.",
            }
    result = {**result, "action_id": payload.action_id}
    return editor_runs.finish(payload.action_id, result)


@router.post("/v2/owner/editor-drafts/{draft_id}/publish", dependencies=[Depends(require_owner)])
def publish_owner_editor_draft(
    draft_id: str,
    payload: editor_publication.PublishDraft,
    x_toolgate_execution_key: str | None = Header(None, alias="X-ToolGate-Execution-Key"),
    x_toolgate_agent: str | None = Header(None, alias="X-ToolGate-Agent"),
):
    # "Let Conker use this tool" grants the chat's own key, so that key comes with the request.
    agent = (
        require_agent(x_toolgate_execution_key, x_toolgate_agent) if payload.conkerMayUse else None
    )
    publication = editor_publication.publish_draft(
        draft_id,
        payload,
        validate=require_valid_automation_definition,
        validate_tool=require_valid_tool_definition,
        agent=agent,
    )
    return {
        "draft_id": draft_id,
        "revision": payload.expected_revision,
        "automation_id": publication["id"],
        "version": publication["version"],
        "digest": publication["digest"],
        "published_at": publication["published_at"],
        "toolId": editor_catalogue.workflow_tool_id(publication),
        "conkerMayUse": payload.conkerMayUse,
    }
