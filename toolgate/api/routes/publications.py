"""Publishing tool and automation definitions, and reading their published versions."""

import secrets

from fastapi import APIRouter, Depends, HTTPException

from toolgate.api.definitions import (
    require_valid_automation_definition,
    require_valid_tool_definition,
)
from toolgate.api.deps import deny, require_admin
from toolgate.api.models import V2Invoke, V2Publish
from toolgate.core import control_plane, publications

router = APIRouter()


def _requested_publication(kind: str, obj_id: str, payload: V2Invoke) -> dict | None:
    if payload.published_version is None:
        if payload.expected_publication_digest is not None:
            deny("PUBLICATION_REQUIRED", "A publication digest requires published_version", 422)
        return None
    if not payload.action_id:
        deny("ACTION_ID_REQUIRED", "Published runs require a stable action_id", 422)
    with control_plane._conn() as conn:
        publication = publications.for_execution(conn, kind, obj_id, payload.published_version)
        if payload.expected_publication_digest is not None and not secrets.compare_digest(
            payload.expected_publication_digest, publication["digest"]
        ):
            deny(
                "PUBLICATION_MISMATCH",
                "The selected publication does not match the expected digest",
                409,
            )
        return publication


def _publish_definition(kind: str, obj_id: str, payload: V2Publish):
    validator = (
        require_valid_tool_definition if kind == "tool" else require_valid_automation_definition
    )
    try:
        result = publications.publish(
            kind,
            obj_id,
            payload.expected_version,
            validate=validator,
            validate_tool=require_valid_tool_definition,
        )
    except publications.PublicationInvalid as exc:
        raise HTTPException(422, {"code": "INVALID_PUBLICATION", "message": str(exc)}) from exc
    if result is None:
        raise HTTPException(404, "definition not found")
    return result


@router.post("/v2/tools/{tool_id}/publish", dependencies=[Depends(require_admin)])
def publish_tool(tool_id: str, payload: V2Publish):
    return _publish_definition("tool", tool_id, payload)


@router.post("/v2/automations/{automation_id}/publish", dependencies=[Depends(require_admin)])
def publish_automation(automation_id: str, payload: V2Publish):
    return _publish_definition("automation", automation_id, payload)


@router.get("/v2/tools/{tool_id}/versions", dependencies=[Depends(require_admin)])
def tool_versions(tool_id: str):
    return publications.history("tool", tool_id)


@router.get("/v2/automations/{automation_id}/versions", dependencies=[Depends(require_admin)])
def automation_versions(automation_id: str):
    return publications.history("automation", automation_id)


def _definition_version(kind: str, obj_id: str, version: int, published: bool):
    result = publications.get(kind, obj_id, version, published=published)
    if result is None:
        raise HTTPException(404, "definition version not found")
    return result


@router.get("/v2/tools/{tool_id}/versions/{version}", dependencies=[Depends(require_admin)])
def tool_version(tool_id: str, version: int, published: bool = False):
    return _definition_version("tool", tool_id, version, published)


@router.get(
    "/v2/automations/{automation_id}/versions/{version}", dependencies=[Depends(require_admin)]
)
def automation_version(automation_id: str, version: int, published: bool = False):
    return _definition_version("automation", automation_id, version, published)
