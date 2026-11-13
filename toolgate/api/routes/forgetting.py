"""Forgetting a chat's tool records: the agent's own (Pi) and the owner's admin reach."""

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from toolgate.api.deps import deny, require_admin, require_agent
from toolgate.core import forgetting

router = APIRouter()

RecordId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:/-]{1,160}$")]


class ForgetRecords(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_ids: list[RecordId] = Field(default_factory=list, max_length=200)
    action_ids: list[RecordId] = Field(default_factory=list, max_length=200)


def _forget(payload: ForgetRecords, by: str, agent_id: str | None) -> dict:
    try:
        return forgetting.forget(payload.request_ids, payload.action_ids, by, agent_id)
    except forgetting.RecoveryHeld as exc:
        deny("RECOVERY_HELD", str(exc), 409, "Reconcile the recovery, then send the same ids again")


@router.post("/v2/agent/forget")
def forget_own_records(payload: ForgetRecords, agent: dict = Depends(require_agent)):
    """Blank this key's own requests and actions of a forgotten chat. Allowed in lockdown: it
    only removes. Another key's ids and unknown ids both come back as `unknown`."""
    return _forget(payload, agent["name"], agent["id"])


@router.post("/v2/admin/forget")
def forget_any_records(payload: ForgetRecords, _tier: str = Depends(require_admin)):
    return _forget(payload, "admin", None)
