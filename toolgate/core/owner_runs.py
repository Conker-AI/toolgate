"""The owner runs one tool by hand, and reads its recent runs.

A run takes the same path as an agent's invoke. The owner key says it is him; the chat's own
execution key is the identity the run is recorded under (its journal row, its Terminal workspace,
its spending), as when Conker runs the tool. He may run any active tool, whether or not Conker may
use it, but nothing about asking changes: a tool that asks still makes an approval request he
answers in his Inbox, a tool on his floor always asks, and blocked stays blocked. His runs carry no
AI decision. Repeating an action_id never runs it twice: the journal answers with its receipt.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from . import access_policy, recovery_journal
from . import control_plane as cp
from . import execution_journal as journal
from .editor_values import bounded
from .owner_channel import OwnerError

ACTOR = "owner"
TOOL_ID = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
MAX_RUNS = 50
# The floor keeps asking him even when he presses Run: tightening is open to anyone.
FLOOR = access_policy.Decision(
    outcome="ask", decided_by="tool_default", reason="On the owner's floor, so it always asks."
)


class ToolRun(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)

    action_id: Annotated[str, Field(pattern=r"^owner_[a-f0-9]{32}$")]
    args: dict[str, JsonValue] = Field(default_factory=dict)
    approval_request_id: Annotated[str, Field(max_length=100)] | None = None

    @model_validator(mode="after")
    def bounded_args(self):
        bounded(self.args)
        if len(json.dumps(self.args, ensure_ascii=False).encode("utf-8")) > 32768:
            raise ValueError("Tool arguments exceed the owner review limit.")
        return self


def own_key(agent: dict) -> None:
    """Runs by hand use the chat's own key, never a key acting as one agent or bound to one."""
    if agent.get("identity"):
        raise OwnerError("execution_unavailable", "Run tools by hand on the chat's own key.", 403)


def decision(tool: dict) -> access_policy.Decision | None:
    return FLOOR if access_policy.on_floor(tool) else None


def _when(value) -> str:
    return datetime.fromtimestamp(float(value), UTC).isoformat()


def history(tool_id: str, limit: int) -> dict:
    """The newest runs of one tool from the journal, by any key: what the journal stores, no more."""
    if not re.fullmatch(TOOL_ID, tool_id):
        raise OwnerError("tool_not_found", "Tool not found.", 404)
    with cp._conn() as conn:
        journal.initialize(conn)
        ids = [
            row["action_id"]
            for row in conn.execute(
                "SELECT action_id FROM v2_actions WHERE subject_type='tool' AND subject_id=? "
                "ORDER BY created_at DESC LIMIT ?",
                (tool_id, limit),
            )
        ]
        ids += [
            row["action_id"]
            for row in conn.execute(
                "SELECT action_id FROM v2_recovery_receipts WHERE "
                "json_extract(record,'$.subject_type')='tool' AND json_extract(record,'$.subject_id')=? "
                "ORDER BY json_extract(record,'$.created_at') DESC LIMIT ?",
                (tool_id, limit),
            )
        ]
        # A recovery receipt stands in for the journal row with the same action_id.
        records = [
            journal._row(recovery_journal.lookup(conn, identity)) for identity in dict.fromkeys(ids)
        ]
    records.sort(key=lambda record: record["created_at"], reverse=True)
    return {
        "items": [
            {
                "action_id": record["action_id"],
                "actor_id": record["actor_id"],
                "parent_action_id": record["parent_action_id"],
                "version": record["version"],
                "status": record["status"],
                "created_at": _when(record["created_at"]),
                "args": record["args"],
                "response": journal.response(record),
            }
            for record in records[:limit]
        ]
    }
