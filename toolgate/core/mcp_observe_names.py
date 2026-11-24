"""How an MCP tool name is read: a shape, not a word list (says_act_outward, names_act).

Split from mcp_observe.py (a pure move); mcp_observe re-exports every name that was public there."""

from __future__ import annotations

import re
import unicodedata

from . import approval_levels

# How a name is read (says_act_outward): a shape, not a word list. Only a name led by one of
# these can be Observe.
READ_VERBS = frozenset(
    {
        "browse",
        "count",
        "describe",
        "fetch",
        "find",
        "get",
        "inspect",
        "list",
        "lookup",
        "preview",
        "read",
        "search",
        "show",
        "stat",
        "status",
        "summarise",
        "summarize",
        "view",
    }
)


# Verbs that commonly execute what they are given (raw SQL): they lead a name that reads only
# when the server's own annotations say read-only.
HINTED_READ_VERBS = frozenset({"query"})


# A name that joins its read to something else asks: get_and_message_user, getThenChatUser.
CONNECTORS = frozenset({"after", "also", "and", "or", "plus", "then", "to", "via", "with"})


# Words that act. No part after the read verb may hold one: a word of four letters or more
# anywhere in the part (get_quicksend), a shorter one at its start or end (get_setvalue,
# get_rerun). Every word that makes an approval serious is here too. Each reviewed list of
# names that acted added its verbs; the shape rule, not these lists, is what keeps the rest out.
ACTS = approval_levels.SERIOUS_WORDS | frozenset(
    {
        "accept",
        "ack",
        "acknowledge",
        "add",
        "alert",
        "announce",
        "append",
        "apply",
        "approve",
        "archive",
        "assign",
        "authorize",
        "backup",
        "ban",
        "bid",
        "block",
        "broadcast",
        "build",
        "burn",
        "cancel",
        "checkin",
        "claim",
        "cleanup",
        "clear",
        "clone",
        "compile",
        "complete",
        "compose",
        "confirm",
        "connect",
        "copy",
        "create",
        "decline",
        "deploy",
        "deposit",
        "dial",
        "disable",
        "discard",
        "dismiss",
        "dispatch",
        "edit",
        "emit",
        "enable",
        "enroll",
        "escalate",
        "eval",
        "exec",
        "execute",
        "export",
        "extend",
        "fire",
        "flag",
        "follow",
        "fork",
        "forward",
        "generate",
        "grant",
        "halt",
        "hide",
        "import",
        "init",
        "insert",
        "install",
        "invite",
        "invoke",
        "join",
        "kick",
        "kill",
        "launch",
        "lease",
        "leave",
        "like",
        "login",
        "logout",
        "mark",
        "merge",
        "mint",
        "modify",
        "move",
        "mute",
        "notify",
        "page",
        "pause",
        "persist",
        "pin",
        "post",
        "poweroff",
        "provision",
        "publish",
        "push",
        "put",
        "rate",
        "react",
        "reboot",
        "redo",
        "refresh",
        "register",
        "reject",
        "reload",
        "remember",
        "rename",
        "renew",
        "rent",
        "replace",
        "reply",
        "reserve",
        "resize",
        "respond",
        "restart",
        "restore",
        "resume",
        "retry",
        "revert",
        "rollback",
        "rotate",
        "rsvp",
        "run",
        "save",
        "scale",
        "seed",
        "sell",
        "send",
        "set",
        "share",
        "shutdown",
        "sign",
        "spawn",
        "spend",
        "sql",
        "stake",
        "star",
        "store",
        "submit",
        "subscribe",
        "swap",
        "terminate",
        "toggle",
        "trade",
        "train",
        "transact",
        "trash",
        "trigger",
        "undo",
        "unenroll",
        "unhide",
        "unlock",
        "update",
        "upload",
        "upsert",
        "verify",
        "vote",
        "write",
    }
)


# Verbs that act but also hide inside common nouns: they count only when a part is, starts with
# or ends with one (get_ring, get_playmusic, get_doorlock), so a noun that merely holds one
# inside still reads (lend in calendar, lock in clockwise).
ACTS_AT_EDGES = frozenset(
    {
        "attach",
        "authenticate",
        "award",
        "beep",
        "bet",
        "bind",
        "borrow",
        "buzz",
        "capture",
        "change",
        "chmod",
        "chown",
        "click",
        "close",
        "congratulate",
        "detach",
        "done",
        "drag",
        "ensure",
        "exit",
        "favorite",
        "favourite",
        "fill",
        "finish",
        "fix",
        "gamble",
        "gift",
        "greet",
        "hold",
        "ingest",
        "invest",
        "learn",
        "lend",
        "lock",
        "mkdir",
        "navigate",
        "nudge",
        "offer",
        "open",
        "pair",
        "paste",
        "play",
        "poke",
        "populate",
        "press",
        "print",
        "quit",
        "raise",
        "reindex",
        "remind",
        "resolve",
        "reward",
        "ring",
        "say",
        "scroll",
        "snooze",
        "speak",
        "stop",
        "sync",
        "tap",
        "thank",
        "throw",
        "touch",
        "vibrate",
        "wager",
        "wake",
        "watch",
        "wave",
        "welcome",
    }
)


# Words that name what a read returns as often as an act on it: one is the read's object only
# as the last part and exactly (messages, email, chat); anywhere else, or with more glued to it
# (get_message_user, get_messageuser, get_start_instance), it asks.
LEADS = frozenset(
    {
        "book",
        "call",
        "chat",
        "comment",
        "commit",
        "dm",
        "draft",
        "email",
        "mail",
        "message",
        "order",
        "patch",
        "release",
        "report",
        "request",
        "schedule",
        "ship",
        "sms",
        "start",
        "text",
        "tweet",
    }
)


# Every word the approval level calls outward or serious is one of these (a test holds it).
ACT_OUTWARD_WORDS = ACTS | ACTS_AT_EDGES | LEADS


_ENDINGS = ("", "s", "es", "d", "ed", "ing")


# Short words and ACTS_AT_EDGES count at a part's edges, never inside it.
_AT_EDGES = frozenset(word for word in ACTS if len(word) < 4) | ACTS_AT_EDGES


# A long word and the forms of it that do not contain it whole (updating, replied).
_STEMS = frozenset(
    stem
    for word in ACTS
    if len(word) >= 4
    for stem in (
        word,
        *((word[:-1] + "ing",) if word.endswith("e") else ()),
        *((word[:-1] + "ied",) if word.endswith("y") else ()),
    )
)


def _forms(word: str) -> tuple[str, ...]:
    """A word with its endings: adds, added, pinned, updating, queries."""
    forms = [word + ending for ending in (*_ENDINGS, word[-1] + "ed", word[-1] + "ing")]
    if word.endswith("e"):
        forms.append(word[:-1] + "ing")
    if word.endswith("y"):
        forms += [word[:-1] + "ies", word[:-1] + "ied"]
    return tuple(forms)


def _holds(part: str, word: str) -> bool:
    """Whether a part is, starts with, or ends with the word (with an ending): rerun, setvalue."""
    return part.startswith(word) or any(part.endswith(form) for form in _forms(word))


def _acts(part: str) -> bool:
    if any(stem in part for stem in _STEMS):
        return True
    return any(_holds(part, word) for word in _AT_EDGES)


def _leads(part: str) -> bool:
    return any(_holds(part, word) for word in LEADS)


def _is_object(part: str) -> bool:
    """Exactly a LEADS word with an ending, and nothing glued to it: messages, email, chats."""
    return any(part in _forms(word) for word in LEADS)


def _parts(text: str) -> list[str]:
    """The lower-case parts of a name in order: split at anything that is not a letter (digits
    too) and at camelCase (sendMessage, HTTPRequest)."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", text)
    return [part for part in re.split(r"[^a-z]+", spaced.lower()) if part]


def says_act_outward(name: object, read_only_hint: bool = False) -> bool:
    """Whether a tool name says it acts: every name does unless it has the shape of a read.

    Words before a dot are a namespace (mcp.list-events, social.list_chats); none may act or
    lead. The name itself must start with a READ_VERB and be at most that verb and one part
    (get_weather, list_emails, read_chat). Only when the server's annotations say read-only
    (`read_only_hint`, see hints_act) may it be longer, or start with a HINTED_READ_VERB.
    No part after the verb may be a connector or hold a word that acts, and a LEADS word may only
    be the last part, exactly. Fail closed: anything that is not printable text, or still holds a
    character outside ASCII after NFKC (a Cyrillic letter that looks Latin, an invisible one),
    acts."""
    if not isinstance(name, str):
        return True
    text = unicodedata.normalize("NFKC", name)
    if not text.isascii() or not text.isprintable():
        return True
    *namespace, own = text.split(".")
    if any(_acts(part) or _leads(part) for segment in namespace for part in _parts(segment)):
        return True
    parts = _parts(own)
    verbs = READ_VERBS | HINTED_READ_VERBS if read_only_hint else READ_VERBS
    if not parts or parts[0] not in verbs:
        return True
    if len(parts) > 2 and not read_only_hint:
        return True
    rest = parts[1:]
    for index, part in enumerate(rest):
        if part in CONNECTORS:
            return True
        if _acts(part):
            return True
        if _leads(part) and not (index == len(rest) - 1 and _is_object(part)):
            return True
    return False


def names_act(names: tuple, read_only_hint: bool = False) -> bool:
    """Whether any of a tool's names (its id, display name and MCP tool name) acts."""
    return any(says_act_outward(name, read_only_hint) for name in names)
