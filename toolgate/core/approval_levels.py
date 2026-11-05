"""How much the owner's approval of a request must prove. Decided here when the request is made,
stored with it, and enforced by the gateway, never chosen by the page or the asking agent.

Level 1, normal (do, run, save): his signed-in session and one tap.
Level 2, outward (send, publish, ship): the same, after an "Are you sure?" naming what goes where.
Level 3, serious (delete, pay, or changing the host): a fresh password proof for that decision.

A request's level is the strongest of every tool it may run: a published workflow counts each
tool and nested workflow it pins. For each tool the strongest of: the Inbox card he chose for it;
words in its id or name (a "delete_file" he never labelled is still a delete); and what it runs
(host controls are serious, a call to an external MCP server or an HTTP POST leaves the house).
Anything that cannot be read is serious, so a doubt asks for the password.
"""

from __future__ import annotations

import re

from toolgate.core import ask_cards

NORMAL, OUTWARD, SERIOUS = 1, 2, 3
LEVELS = (NORMAL, OUTWARD, SERIOUS)
CARD_LEVELS = {
    "do": NORMAL,
    "run": NORMAL,
    "save": NORMAL,
    "send": OUTWARD,
    "publish": OUTWARD,
    "ship": OUTWARD,
    "delete": SERIOUS,
    "pay": SERIOUS,
}
SERIOUS_WORDS = frozenset({
    "delete", "del", "remove", "rm", "unlink", "destroy", "drop", "purge", "wipe", "erase",
    "truncate", "uninstall", "revoke", "forget", "shred", "reset", "overwrite",
    "pay", "payment", "payout", "purchase", "buy", "checkout", "charge", "transfer",
    "withdraw", "refund", "donate",
})
OUTWARD_WORDS = frozenset({
    "send", "post", "publish", "email", "mail", "message", "reply", "tweet", "share", "upload",
    "push", "deploy", "ship", "release", "invite", "comment", "notify", "sms",
})
# Host controls carry their own exact review and change the machine Conker runs on.
SERIOUS_EXECUTIONS = frozenset({"port_control", "container_control", "process_control"})


def words(text: object) -> set[str]:
    """The lower-case words of an id or name: split at non-letters and at camelCase."""
    if not isinstance(text, str):
        return set()
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    return {word for word in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if word}


def _named(definition: dict) -> int:
    found = words(definition.get("id")) | words(definition.get("name"))
    if found & SERIOUS_WORDS:
        return SERIOUS
    return OUTWARD if found & OUTWARD_WORDS else NORMAL


def for_tool(tool: object, cards: dict[str, str]) -> int:
    """One tool definition's level; `cards` from `ask_cards.chosen()`."""
    if not isinstance(tool, dict):
        return SERIOUS
    identity = tool.get("id")
    if not isinstance(identity, str):
        return SERIOUS
    execution = tool.get("execution")
    execution = execution if isinstance(execution, dict) else {}
    kind = execution.get("type")
    card = cards.get(identity, ask_cards.DEFAULT)
    level = max(CARD_LEVELS.get(card, SERIOUS), _named(tool))
    if kind in SERIOUS_EXECUTIONS:
        return SERIOUS
    if kind == "mcp_http" or (
        kind == "http_json" and str(execution.get("method", "GET")).upper() != "GET"
    ):
        level = max(level, OUTWARD)
    return level


def for_publication(publication: object, cards: dict[str, str]) -> int:
    """The strongest level among a publication's own definition, its tools and nested workflows."""
    if not isinstance(publication, dict):
        return SERIOUS
    from toolgate.core import publications

    level = NORMAL
    for member in publications.members(publication):
        definition = member.get("definition")
        if member.get("kind") == "tool":
            level = max(level, for_tool(definition, cards))
        else:
            level = max(level, _named(definition) if isinstance(definition, dict) else SERIOUS)
        for tool in member.get("tools", {}).values():
            level = max(level, for_tool(tool, cards))
    return level


def for_automation(automation: object, tools: dict, cards: dict[str, str]) -> int:
    """An unpublished automation run: its own name and the tools it may call."""
    level = _named(automation) if isinstance(automation, dict) else SERIOUS
    return max([level, *(for_tool(tool, cards) for tool in tools.values())])


def stored(value: object) -> int:
    """A request's stored level; a missing or odd one (older requests) is serious."""
    return value if type(value) is int and value in LEVELS else SERIOUS
