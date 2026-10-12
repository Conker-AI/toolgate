import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, StrictBool, StrictInt

from toolgate.api.deps import deny, require_admin, require_agent
from toolgate.core import control_plane, spending, spending_allowances

router = APIRouter()


class SpendPolicy(BaseModel):
    enabled: StrictBool
    cumulative_cap: StrictInt
    max_job_cap: StrictInt


class SpendPrice(BaseModel):
    input_per_million: StrictInt
    output_per_million: StrictInt
    valid_until: float
    source: str


class SpendJob(BaseModel):
    actor_id: str
    root_action_id: str
    cap: StrictInt


@router.get("/v2/spending")
def spending_status(_tier: str = Depends(require_admin)):
    return spending.status()


@router.put("/v2/spending/policy")
def spending_policy(payload: SpendPolicy, _tier: str = Depends(require_admin)):
    try:
        return spending.configure(**payload.model_dump())
    except spending.BudgetDenied as exc:
        deny("BUDGET_DENIED", str(exc), 422)


@router.put("/v2/spending/prices/{model}")
def spending_price(model: str, payload: SpendPrice, _tier: str = Depends(require_admin)):
    try:
        spending.set_price(model, **payload.model_dump())
        return {"model": model, **payload.model_dump()}
    except spending.BudgetDenied as exc:
        deny("BUDGET_DENIED", str(exc), 422)


@router.post("/v2/spending/jobs")
def spending_job(payload: SpendJob, _tier: str = Depends(require_admin)):
    try:
        return spending.create_job(**payload.model_dump())
    except (spending.BudgetDenied, sqlite3.IntegrityError) as exc:
        deny("BUDGET_DENIED", str(exc), 422)


class SpendAllowance(BaseModel):
    model_config = {"extra": "forbid"}
    actor_id: str
    target: dict
    per_run_cap: StrictInt
    total_cap: StrictInt
    max_runs: StrictInt
    expires_at: float


class AllowanceAllocation(BaseModel):
    model_config = {"extra": "forbid"}
    root_action_id: str
    target: dict


@router.post("/v2/spending/allowances")
def create_spending_allowance(payload: SpendAllowance, _tier: str = Depends(require_admin)):
    try:
        return JSONResponse(
            spending_allowances.create(**payload.model_dump()),
            headers={"Cache-Control": "no-store"},
        )
    except spending.BudgetDenied as exc:
        deny("BUDGET_DENIED", str(exc), 422)


@router.get("/v2/spending/allowances/{allowance_id}")
def get_spending_allowance(allowance_id: str, _tier: str = Depends(require_admin)):
    value = spending_allowances.get(allowance_id)
    if value is None:
        deny("NOT_FOUND", "Allowance not found", 404)
    return JSONResponse(value, headers={"Cache-Control": "no-store"})


@router.post("/v2/spending/allowances/{allowance_id}/revoke")
def revoke_spending_allowance(allowance_id: str, _tier: str = Depends(require_admin)):
    try:
        return JSONResponse(
            spending_allowances.revoke(allowance_id), headers={"Cache-Control": "no-store"}
        )
    except spending.BudgetDenied as exc:
        deny("BUDGET_DENIED", str(exc), 422)


@router.post("/v2/agent/spending/allowances/{allowance_id}/allocate")
def allocate_spending_allowance(
    allowance_id: str, payload: AllowanceAllocation, agent: dict = Depends(require_agent)
):
    kind, identity = payload.target.get("kind"), payload.target.get("id")
    scope = f"automation:{identity}" if kind == "automation" else identity
    if not isinstance(scope, str) or not control_plane.is_scoped(agent, scope):
        deny("FORBIDDEN", "Target is outside this agent's scope", 403)
    try:
        value = spending_allowances.allocate(
            allowance_id, agent["id"], payload.root_action_id, payload.target
        )
        return JSONResponse(value, headers={"Cache-Control": "no-store"})
    except spending.BudgetDenied as exc:
        deny("BUDGET_DENIED", str(exc), 422)


class ReservationRelease(BaseModel):
    confirmed_not_executed: StrictBool
    evidence: str


@router.post("/v2/spending/releases/{action_id:path}")
def release_reservation(
    action_id: str, payload: ReservationRelease, _tier: str = Depends(require_admin)
):
    try:
        return spending.release_hold(action_id, payload.evidence, payload.confirmed_not_executed)
    except spending.BudgetDenied as exc:
        deny("RELEASE_DENIED", str(exc), 409)


@router.get("/v2/agent/spending/jobs/{job_id}")
def agent_spending_job(job_id: str, agent: dict = Depends(require_agent)):
    result = spending.agent_job(job_id, agent["id"])
    if result is None:
        raise HTTPException(404, "budget not found")
    return result
