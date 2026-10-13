"""Owner views of the action journal and the event log."""

from fastapi import APIRouter, Depends

from toolgate.api.deps import require_admin
from toolgate.core import control_plane
from toolgate.core import execution_journal as journal

router = APIRouter()


@router.get("/v2/actions")
def list_actions(_tier: str = Depends(require_admin)):
    return {"results": journal.list_actions()}


@router.get("/v2/events")
def list_events(limit: int = 100, _tier: str = Depends(require_admin)):
    return control_plane.events(limit)
