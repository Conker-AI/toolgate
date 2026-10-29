"""Gateway status, lockdown, settings, the owner's tool settings, verification methods and the AI
archive export."""

import hashlib
import hmac
import json
import re
import time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import JSONResponse

from toolgate.api.deps import deny, require_admin, require_owner
from toolgate.api.models import (
    DEFAULT_CONFIRMATION_EXPIRY_SECONDS,
    V2Settings,
    VerificationCallback,
    VerificationMethodCreate,
)
from toolgate.core import approvals, control_plane, legacy_archive, tool_settings, vault

router = APIRouter()


@router.get("/v2/status")
def status(_tier: str = Depends(require_admin)):
    requests = control_plane.list_objects("request")
    return {
        "lockdown": control_plane.settings().get("lockdown", False),
        "tools": len(control_plane.list_objects("tool")),
        "automations": len(control_plane.list_objects("automation")),
        "services": len(control_plane.list_objects("service")),
        "pending_requests": sum(r.get("status") == "pending" for r in requests),
    }


@router.post("/v2/settings/lockdown")
def set_lockdown(enabled: bool, reason: str = "", _tier: str = Depends(require_admin)):
    return control_plane.set_lockdown(enabled, "admin", reason)


@router.get("/v2/settings")
def get_settings(_tier: str = Depends(require_admin)):
    return {
        "generation_model": "qwen3:4b",
        "event_retention_days": 90,
        "default_confirmation_expiry_seconds": DEFAULT_CONFIRMATION_EXPIRY_SECONDS,
        "producthunt_commercial_use_approved": False,
        **control_plane.settings(),
    }


@router.put("/v2/settings")
def update_settings(payload: V2Settings, _tier: str = Depends(require_admin)):
    return control_plane.update_settings(payload.model_dump(), "admin")


@router.get("/v2/owner/settings", dependencies=[Depends(require_owner)])
def owner_settings():
    """How tools run (time limits, the Terminal's resources, web search) and the revision a save
    must name. Null numbers keep today's limits."""
    return JSONResponse(tool_settings.load(), headers={"Cache-Control": "no-store"})


@router.put("/v2/owner/settings", dependencies=[Depends(require_owner)])
def save_owner_settings(payload: tool_settings.Update):
    """Replace them. A stale revision is refused (409); a value past its ceiling is refused (422)."""
    return JSONResponse(tool_settings.save(payload), headers={"Cache-Control": "no-store"})


@router.get("/v2/verification-methods")
def list_verification_methods(_tier: str = Depends(require_admin)):
    return control_plane.list_objects("verification_method")


@router.post("/v2/verification-methods")
def create_verification_method(
    payload: VerificationMethodCreate, _tier: str = Depends(require_admin)
):
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", payload.secret_ref):
        raise HTTPException(422, "secret_ref must be a vault reference name")
    try:
        vault.get_key(payload.secret_ref)
    except KeyError:
        raise HTTPException(422, "secret_ref is not configured in ToolGate") from None
    method = control_plane.create_verification_method(payload.model_dump())
    control_plane.event(
        "verification_method_created", "info", "verification_method", method["id"], "admin"
    )
    return method


@router.delete("/v2/verification-methods/{method_id}")
def delete_verification_method(method_id: str, _tier: str = Depends(require_admin)):
    if not control_plane.remove("verification_method", method_id):
        raise HTTPException(404, "verification method not found")
    control_plane.event(
        "verification_method_deleted", "warning", "verification_method", method_id, "admin"
    )
    return {"deleted": True, "id": method_id}


@router.post("/v2/verification/callback")
def verification_callback(
    payload: VerificationCallback,
    x_toolgate_timestamp: str | None = Header(None, alias="X-ToolGate-Timestamp"),
    x_toolgate_signature: str | None = Header(None, alias="X-ToolGate-Signature"),
):
    if control_plane.settings().get("lockdown"):
        deny("LOCKED_DOWN", "ToolGate is in lockdown mode", 423)
    method = control_plane.get("verification_method", payload.method_id)
    if (
        not method
        or method.get("status") != "active"
        or method.get("method_type") != "signed_callback"
    ):
        deny("VERIFICATION_METHOD_INVALID", "Verification method is unavailable", 401)
    try:
        timestamp = int(x_toolgate_timestamp or "")
    except ValueError:
        timestamp = 0
    canonical = json.dumps(
        payload.model_dump(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    try:
        secret = vault.get_key(method["secret_ref"])
    except KeyError:
        deny("VERIFICATION_METHOD_INVALID", "Verification method secret is unavailable", 503)
    expected = hmac.new(
        secret.encode(), f"{timestamp}.{canonical}".encode(), hashlib.sha256
    ).hexdigest()
    valid = (
        abs(int(time.time()) - timestamp) <= 60
        and bool(x_toolgate_signature)
        and hmac.compare_digest(x_toolgate_signature.removeprefix("sha256="), expected)
    )
    if not valid:
        control_plane.event(
            "verification_callback_rejected",
            "critical",
            "verification_method",
            method["id"],
            "callback",
            {"reason": "invalid signature or timestamp"},
        )
        failures = control_plane.event_count_since(
            "verification_callback_rejected", "verification_method", method["id"], 300
        )
        if failures >= 5:
            control_plane.set_lockdown(True, "system", "repeated invalid verification callbacks")
        deny("CALLBACK_SIGNATURE_INVALID", "Callback signature or timestamp is invalid", 401)
    request = control_plane.get("request", payload.request_id)
    binding = request.get("payload", {}).get("binding", {}) if request else {}
    if not request or request.get("kind") != "verification" or request.get("status") != "pending":
        deny("REQUEST_NOT_PENDING", "Verification request is not pending", 409)
    if not hmac.compare_digest(str(binding.get("nonce", "")), payload.nonce):
        deny("CALLBACK_NONCE_INVALID", "Callback nonce does not match this request", 409)
    if payload.decision not in {"approved", "rejected"}:
        raise HTTPException(422, "decision must be approved or rejected")
    try:
        record = approvals.decide_request(
            payload.request_id, payload.decision, f"callback:{method['name']}"
        )
    except ValueError as exc:
        deny(
            "REQUEST_NOT_PENDING",
            str(exc),
            409,
            "Refresh the request; do not retry a decided or expired approval",
        )
    if not record:
        deny(
            "REQUEST_NOT_PENDING",
            "Verification request no longer exists",
            409,
            "Request fresh confirmation",
        )
    control_plane.update_verification_method(
        method["id"], {"last_seen_at": datetime.now(UTC).isoformat()}
    )
    control_plane.event(
        "verification_callback_accepted",
        "info",
        "verification_method",
        method["id"],
        "callback",
        {"request_id": payload.request_id, "decision": payload.decision},
    )
    return {"status": record["status"], "request_id": record["id"]}


@router.get("/v2/archives/ai")
def export_ai_archive(_tier: str = Depends(require_admin)):
    return legacy_archive.export()
