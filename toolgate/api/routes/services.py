"""Registered external services and their health checks."""

from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException

from toolgate.api.deps import deny, require_admin
from toolgate.api.models import V2Service
from toolgate.core import control_plane
from toolgate.core.public_https import public_client, public_url

router = APIRouter()


@router.get("/v2/services")
def list_services(_tier: str = Depends(require_admin)):
    tools = control_plane.list_objects("tool")
    automations = control_plane.list_objects("automation")
    return [
        {
            **service,
            "linked_tools": [
                tool["id"] for tool in tools if tool.get("service_id") == service["id"]
            ],
            "linked_automations": [
                item["id"]
                for item in automations
                if any(
                    step.get("tool_id")
                    in {tool["id"] for tool in tools if tool.get("service_id") == service["id"]}
                    for step in item.get("workflow", [])
                    if isinstance(step, dict)
                )
            ],
        }
        for service in control_plane.list_objects("service")
    ]


@router.post("/v2/services")
def create_service(payload: V2Service, _tier: str = Depends(require_admin)):
    service = control_plane.create_service(payload.model_dump())
    control_plane.event("service_saved", "info", "service", service["id"], "admin")
    return service


@router.post("/v2/services/{service_id}/check")
def check_service(service_id: str, _tier: str = Depends(require_admin)):
    service = control_plane.get("service", service_id)
    if not service:
        raise HTTPException(404, "service not found")
    health_url = service.get("destination_policy", {}).get("health_url")
    if not isinstance(health_url, str):
        raise HTTPException(422, "service has no health_url")
    parsed = urlsplit(health_url)
    allowed_internal = (
        parsed.hostname in {"memorygate-api", "memorygate-ollama"} and parsed.scheme == "http"
    )
    allowed_public = public_url(health_url)
    if not (allowed_internal or allowed_public):
        deny("DESTINATION_DENIED", "Service health destination is not allowed")
    try:
        if allowed_public:
            with public_client(timeout=10) as client:
                response = client.get(health_url)
        else:
            response = httpx.get(health_url, timeout=10, follow_redirects=False)
        healthy = 200 <= response.status_code < 300
    except httpx.HTTPError:
        healthy = False
    updated = control_plane.update_service(
        service_id,
        {
            "health": "healthy" if healthy else "unhealthy",
            "last_health_check_at": datetime.now(UTC).isoformat(),
        },
    )
    control_plane.event(
        "service_health_checked",
        "info" if healthy else "warning",
        "service",
        service_id,
        "admin",
        {"healthy": healthy},
    )
    return updated
