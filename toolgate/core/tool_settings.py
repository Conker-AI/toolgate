"""The owner's settings for how tools run: a time limit, the Terminal's resources, web search and
how long an approved action has to start.

These are control-plane settings: only the owner credential reads or changes them, and every save
names the revision it replaces, so a stale screen is refused instead of overwriting a newer change.
Each value has a hard ceiling at today's limit. A setting can make tools stricter or put them back,
never give them more than ToolGate allows. A number left empty (null) keeps today's limit.

What each one changes:

- `tool_seconds`: the most one tool call may take. It lowers every limit ToolGate sets for a call:
  web, MCP, MemoryGate and AI requests, research searches and fetches, workflow runs, Terminal
  commands and installs. The server tools (files, inventory, containers, services, ports) keep
  their own short fixed limits.
- `terminal_seconds`: the most one Terminal command may run (a command may ask for less).
- `terminal_memory_mb`, `terminal_cpus`: memory and processors for one Terminal command.
- `terminal_workspace_mb`: how much an agent's workspace may hold; installs obey it too. Lowered
  below what a workspace already holds, it stops the workspace growing; nothing is deleted.
  The runner applies all three from the next command (no restart) and keeps its own configured
  limit when that is lower.
- `web_safe_search`, `web_region`: the safe search level and region of web searches (SearXNG).
- `web_skip_sites`: sites never used as sources, added to the built-in ones; their pages are not
  fetched either.
- `web_page_characters`: the most text one fetched page gives the model.
- `run_window_minutes`: once the owner approves a request that waited for them, how long that
  exact action has to start; it still runs once. Only shorter than today's 15 minutes. It applies
  to approvals decided after the change: each approval keeps the window recorded when it was
  decided (core/approvals.py).
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from toolgate.sandbox import spec

from . import approvals
from . import control_plane as cp
from .owner_channel import OwnerError

KIND, IDENTITY = "settings", "tools"
TOOL_SECONDS = 180  # the longest ToolGate waits on any tool today: AI text through Pi or Ollama
TERMINAL_SECONDS = 100  # the most one Terminal command may run
PAGE_CHARACTERS = 20000  # the most text one fetched page gives the model
SKIP_SITES = 50
RUN_WINDOW_MINUTES = approvals.MAX_RUN_WINDOW_MINUTES  # an approved action has 15 minutes today
SAFE_SEARCH = {"off": 0, "moderate": 1, "strict": 2}  # SearXNG's levels
SITE = r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"


class StrictDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class Settings(StrictDocument):
    tool_seconds: Annotated[int, Field(ge=5, le=TOOL_SECONDS)] | None = None
    terminal_seconds: Annotated[int, Field(ge=5, le=TERMINAL_SECONDS)] | None = None
    terminal_memory_mb: Annotated[int, Field(ge=64, le=spec.MEMORY_MB)] | None = None
    terminal_cpus: Annotated[float, Field(ge=0.1, le=spec.CPUS_MILLI / 1000)] | None = None
    terminal_workspace_mb: Annotated[int, Field(ge=16, le=spec.WORKSPACE_MB)] | None = None
    web_safe_search: Literal["off", "moderate", "strict"] = "moderate"
    # A two-letter country code such as us or il; empty searches with no region, as today.
    web_region: Annotated[str, Field(pattern=r"^(?:[a-z]{2})?$")] = ""
    web_skip_sites: Annotated[list[str], Field(max_length=SKIP_SITES)] = []
    web_page_characters: Annotated[int, Field(ge=1000, le=PAGE_CHARACTERS)] | None = None
    run_window_minutes: Annotated[int, Field(ge=1, le=RUN_WINDOW_MINUTES)] | None = None

    @field_validator("web_region", mode="before")
    @classmethod
    def region_code(cls, region):
        return region.strip().lower() if isinstance(region, str) else region

    @field_validator("web_skip_sites")
    @classmethod
    def site_names(cls, sites: list[str]) -> list[str]:
        named = []
        for site in sites:
            name = site.strip().lower().removeprefix("www.")
            if not re.fullmatch(SITE, name):
                raise ValueError(f"{site[:80]!r} is not a site name such as example.com")
            if name not in named:
                named.append(name)
        return named


class Update(StrictDocument):
    expected_revision: Annotated[int, Field(ge=0)]
    settings: Settings


def _stored(row) -> dict:
    return json.loads(row["body"]) if row else {}


def _read() -> dict:
    """The saved document, read-only: reading the settings never creates or changes the database.
    No database or no saved settings yet reads as nothing saved. A database that is there but
    cannot be read refuses, so no tool runs past limits or onto sites the owner set."""
    path = Path(cp.DB_PATH).resolve()
    if not path.exists():
        return {}
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            db.row_factory = sqlite3.Row
            if not db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='v2_objects'"
            ).fetchone():
                return {}
            row = db.execute(
                "SELECT body FROM v2_objects WHERE kind=? AND id=?", (KIND, IDENTITY)
            ).fetchone()
    except sqlite3.Error as exc:
        raise OwnerError(
            "settings_unreadable", "Tool settings could not be read; try again shortly.", 503
        ) from exc
    return _stored(row)


def load() -> dict:
    """The saved settings and their revision (0 and today's limits before the first save)."""
    stored = _read()
    return {"settings": current(stored).model_dump(), "revision": stored.get("revision", 0)}


def save(update: Update, actor: str = "owner") -> dict:
    """Replace the settings when the caller saw the latest revision; a field left out goes back
    to today's limit."""
    values = update.settings.model_dump()
    with cp._conn() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT body FROM v2_objects WHERE kind=? AND id=?", (KIND, IDENTITY)
        ).fetchone()
        stored = _stored(row)
        revision = stored.get("revision", 0)
        if revision != update.expected_revision:
            raise OwnerError(
                "settings_revision_conflict", "Settings changed; reload before saving.", 409
            )
        cp._put(KIND, IDENTITY, {"settings": values, "revision": revision + 1}, connection=db)
        before = current(stored).model_dump()
        changed = sorted(key for key in values if values[key] != before[key])
        # In the same transaction: a save is never applied without its event, nor refused after.
        cp.event(
            "tool_settings_updated", "info", "settings", IDENTITY, actor, {"keys": changed},
            connection=db,
        )
    return {"settings": values, "revision": revision + 1}


def current(stored: dict | None = None) -> Settings:
    """The settings tools run by now. A stored value this version no longer allows (or a name it
    does not know) is ignored, which falls back to today's limit rather than past it; the other
    values still apply."""
    if stored is None:
        stored = _read()
    saved = stored.get("settings", {})
    if not isinstance(saved, dict):
        return Settings()
    kept = {}
    for name, value in saved.items():
        try:  # one value at a time; a name this version does not know is refused too
            Settings.model_validate({name: value})
        except ValidationError:
            continue
        kept[name] = value
    return Settings.model_validate(kept)


# --- what tools read ---------------------------------------------------------------------------


def seconds(own):
    """A tool's own time limit, lowered to the owner's limit for one tool call when that is less."""
    most = current().tool_seconds
    return own if most is None else min(own, most)


def call_seconds() -> int | None:
    """The owner's limit for one tool call, or None for each tool's own limit."""
    return current().tool_seconds


def terminal_seconds() -> int:
    """The most one Terminal command may run: the least of the Terminal's own most and the
    owner's two limits."""
    chosen = current()
    limits = (TERMINAL_SECONDS, chosen.terminal_seconds, chosen.tool_seconds)
    return min(value for value in limits if value is not None)


def terminal_limits(install: bool = False) -> dict:
    """The lower limits the sandbox runner applies to one command; only those the owner set.
    Memory and processors shape Terminal commands; the workspace size is the folder's, so an
    install obeys it too."""
    chosen = current()
    limits = {"workspace_mb": chosen.terminal_workspace_mb}
    if not install:
        limits["memory_mb"] = chosen.terminal_memory_mb
        if chosen.terminal_cpus is not None:
            limits["cpus_milli"] = round(chosen.terminal_cpus * 1000)
    return {name: value for name, value in limits.items() if value is not None}


def safe_search() -> int:
    return SAFE_SEARCH[current().web_safe_search]


def search_language() -> str:
    """SearXNG's language: English as today, with the owner's region when one is set."""
    region = current().web_region
    return f"en-{region.upper()}" if region else "en"


def skip_sites() -> list[str]:
    return current().web_skip_sites


def skipped(url: str, sites: list[str] | None = None) -> bool:
    """Whether `url` is on a site the owner never wants used as a source. Pass `sites` (from
    `skip_sites`) when checking many URLs, so the settings are read once."""
    host = (urlsplit(str(url)).hostname or "").lower().rstrip(".")
    sites = skip_sites() if sites is None else sites
    return any(host == site or host.endswith("." + site) for site in sites)


def page_characters() -> int:
    return current().web_page_characters or PAGE_CHARACTERS


def run_window(connection) -> int:
    """Minutes an approval given now leaves its action to start. Read inside the caller's deciding
    transaction, so the window recorded is the one in force at the decision."""
    row = connection.execute(
        "SELECT body FROM v2_objects WHERE kind=? AND id=?", (KIND, IDENTITY)
    ).fetchone()
    return current(_stored(row)).run_window_minutes or RUN_WINDOW_MINUTES
