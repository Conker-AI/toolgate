"""Which buttons the owner's Inbox card shows for a tool: one template from a fixed list.

He picks a template per tool (Send it / Don't send, Publish / Not yet, ...). It is an owner setting
kept beside the floor, not part of the tool definition, so changing it never changes a tool's
version or an approval bound to it. Each request copies the template when it is made. The list is
fixed on purpose: no tool, and no AI drafting one, can label the approve button "Cancel". Labels
are cosmetic; approving still approves only the exact action shown.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from toolgate.core import control_plane

TEMPLATES = ("do", "send", "publish", "ship", "run", "delete", "pay", "save")
DEFAULT = "do"
# Built-in tools whose template is known before he picks one.
BUILT_IN = {"sandbox.run": "run"}
# A published workflow has no template of its own: it shows the strongest one among the tools it
# runs, so a workflow that sends through his "send" tool is still a send. Strongest first.
STRONGEST = ("pay", "delete", "ship", "publish", "send", "save", "run")


class Card(BaseModel):
    model_config = ConfigDict(extra="forbid")
    template: Literal["do", "send", "publish", "ship", "run", "delete", "pay", "save"]


def _table(conn) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS v2_tool_cards ("
        "tool_id TEXT PRIMARY KEY, template TEXT NOT NULL, updated_at TEXT NOT NULL)"
    )


def chosen() -> dict[str, str]:
    """Every template that is not the default: his choices over the built-in ones."""
    with control_plane._conn() as conn:
        _table(conn)
        rows = conn.execute("SELECT tool_id, template FROM v2_tool_cards").fetchall()
    cards = {**BUILT_IN, **{row["tool_id"]: row["template"] for row in rows}}
    return {tool_id: value for tool_id, value in cards.items() if value != DEFAULT}


def card_for(tool_id: str) -> str:
    return chosen().get(tool_id, DEFAULT)


def for_workflow(tool_ids, cards: dict[str, str]) -> str:
    """The strongest template among a workflow's tools (`cards` from `chosen()`), else the default."""
    present = {cards.get(tool_id, DEFAULT) for tool_id in tool_ids}
    return next((template for template in STRONGEST if template in present), DEFAULT)


def set_card(tool_id: str, template: str, actor: str = "owner") -> str:
    if template not in TEMPLATES:
        raise ValueError("Unknown card template")
    with control_plane._conn() as conn:
        _table(conn)
        conn.execute(
            "INSERT INTO v2_tool_cards VALUES (?, ?, ?) ON CONFLICT(tool_id) DO UPDATE SET "
            "template=excluded.template, updated_at=excluded.updated_at",
            (tool_id, template, control_plane._now()),
        )
    control_plane.event("tool_card_changed", "info", "tool", tool_id, actor, {"template": template})
    return template


def valid(value) -> str:
    """A request's stored template, or the default when it is missing or unknown."""
    return value if isinstance(value, str) and value in TEMPLATES else DEFAULT
