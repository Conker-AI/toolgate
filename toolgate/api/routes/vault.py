"""Owner vault secrets, admin key check and control-key rotation."""

from fastapi import APIRouter, Depends, HTTPException

from toolgate.api.deps import require_admin
from toolgate.api.models import SecretCreate, SecretUpdate
from toolgate.core import control_plane, vault

router = APIRouter()


@router.get("/auth/check")
def auth_check(_tier: str = Depends(require_admin)):
    return {"tier": "admin"}


@router.get("/vault/secrets")
def list_secrets(_tier: str = Depends(require_admin)):
    return vault.list_placeholders()


@router.post("/vault/secrets")
def create_secret(payload: SecretCreate, _tier: str = Depends(require_admin)):
    try:
        vault.set_secret(payload.name, payload.value, allow_existing=False)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    control_plane.event("secret_created", "info", "secret", payload.name, "admin")
    return {"name": payload.name}


@router.put("/vault/secrets/{name}")
def update_secret(name: str, payload: SecretUpdate, _tier: str = Depends(require_admin)):
    try:
        vault.set_secret(name, payload.value, allow_existing=True)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    control_plane.event("secret_updated", "warning", "secret", name, "admin")
    return {"name": name}


@router.delete("/vault/secrets/{name}")
def delete_secret(name: str, _tier: str = Depends(require_admin)):
    try:
        vault.delete_secret(name)
    except KeyError:
        raise HTTPException(404, "secret not found") from None
    control_plane.event("secret_deleted", "warning", "secret", name, "admin")
    return {"name": name}


@router.post("/settings/keys/admin/rotate")
def rotate_control_key(_tier: str = Depends(require_admin)):
    return {"which": "admin", "key": vault.rotate_control_key("TOOLGATE_ADMIN_KEY")}
