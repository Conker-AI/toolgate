"""The install guard: what ToolGate checks about a package before an agent may install it.

For every package named in an install, before any approval is asked for and again just before the
install is sent to the runner:

- a name that looks like a popular package without being it (`reqeusts`, `crossenv`) is refused,
  naming the package that was probably meant (lookalike.py);
- a package OSV lists as malware (a `MAL-` advisory) is refused, always, even one the owner
  trusts: for the whole package, or for the exact version asked for when only some versions were;
- the registry must know the name, its first release must be at least MIN_AGE_DAYS old and, on
  npm, it must get at least MIN_WEEKLY_DOWNLOADS a week. The owner can trust a package by name
  (`install_trusted_packages` in the tool settings), which skips these and the lookalike check.

A lookup that fails refuses the install: the guard fails closed. Answers are kept for an hour.
Dependencies are not looked up one by one here; the package proxy hides every version younger
than its cooldown (cooldown.py), for dependencies too, and pip installs wheels only while npm runs
no install scripts (conker-install).
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable
from datetime import datetime
from functools import partial
from typing import TypeVar
from urllib.parse import quote

import httpx

from toolgate.core import public_https
from toolgate.sandbox import lookalike
from toolgate.sandbox.validation import Refused

MIN_AGE_DAYS = 30
MIN_WEEKLY_DOWNLOADS = 1000
KEEP_SECONDS = 3600
MAX_BODY = 64 * 1024 * 1024  # the largest npm documents (@types/node) are tens of MB
TIMEOUT = 20.0
OSV = "https://api.osv.dev/v1/query"
ECOSYSTEM = {"pip": "PyPI", "npm": "npm"}
PIP_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
PIP_PIN = re.compile(r"===?([A-Za-z0-9.!+_-]+)\Z")
NPM_PIN = re.compile(r"[0-9][A-Za-z0-9.+-]*\Z")

_kept: dict[tuple, tuple[float, object]] = {}
_lock = threading.Lock()
T = TypeVar("T")


class Unknown(LookupError):
    """The registry has no package by that name."""


def split(manager: str, spec: str) -> tuple[str, str | None]:
    """The bare name and the exact version a validated spec pins, if it pins one."""
    if manager == "pip":
        found = PIP_NAME.match(spec)
        name = found.group(0) if found else spec
        pin = PIP_PIN.search(spec[len(name) :].split("]")[-1])
        return name, pin.group(1) if pin and "," not in spec else None
    at = spec.find("@", 1)  # a scoped name starts with @
    if at == -1:
        return spec, None
    version = spec[at + 1 :]
    return spec[:at], version if NPM_PIN.fullmatch(version) else None


def _get(url: str, body: dict | None = None):
    """One JSON answer from a public HTTPS service; None for a 404."""
    with public_https.public_client(timeout=TIMEOUT) as client:
        request = client.build_request(
            "POST" if body is not None else "GET",
            url,
            json=body,
            headers={"Accept": "application/json", "User-Agent": "conker-toolgate-install-guard"},
        )
        response = client.send(request, stream=True)
        try:
            if response.status_code == 404:
                return None
            if response.status_code != 200:
                raise OSError(f"status {response.status_code}")
            data = bytearray()
            for chunk in response.iter_bytes():
                data += chunk
                if len(data) > MAX_BODY:
                    raise OSError("answer too large")
        finally:
            response.close()
    return json.loads(data)


def _kept_or(key: tuple, look: Callable[[], T]) -> T:
    now = time.monotonic()
    with _lock:
        hit = _kept.get(key)
        if hit and now - hit[0] < KEEP_SECONDS:
            return hit[1]  # type: ignore[return-value]
    value = look()
    with _lock:
        _kept[key] = (now, value)
    return value


def _malware(manager: str, name: str) -> tuple[bool, set[str], str]:
    """(whole package malicious, malicious versions, advisory id) from OSV's MAL- advisories."""
    whole, versions, first = False, set(), ""
    body = {"package": {"name": name, "ecosystem": ECOSYSTEM[manager]}}
    for _ in range(10):
        answer = _get(OSV, body) or {}
        for vuln in answer.get("vulns", []):
            ids = [vuln.get("id", ""), *vuln.get("aliases", [])]
            if not any(str(i).startswith("MAL-") for i in ids):
                continue
            first = first or next(i for i in ids if str(i).startswith("MAL-"))
            for affected in vuln.get("affected", []) or [{}]:
                listed = affected.get("versions") or []
                versions.update(str(v) for v in listed)
                ranges = affected.get("ranges") or []
                bounded = any(
                    "fixed" in event or "last_affected" in event
                    for one in ranges
                    for event in one.get("events", [])
                )
                if not listed and not bounded:
                    whole = True  # no versions and no end: every version, the usual typosquat
        token = answer.get("next_page_token")
        if not token:
            return whole, versions, first
        body = {**body, "page_token": token}
    raise OSError("too many advisories")


def _when(value) -> float | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _first_release(manager: str, name: str) -> float:
    """When the registry first published the package, as a Unix time. Raises Unknown."""
    if manager == "pip":
        doc = _get(f"https://pypi.org/pypi/{quote(name, safe='')}/json")
        if doc is None:
            raise Unknown(name)
        times = [
            _when(file.get("upload_time_iso_8601"))
            for files in (doc.get("releases") or {}).values()
            for file in files
        ]
    else:
        doc = _get(f"https://registry.npmjs.org/{quote(name, safe='@')}")
        if doc is None or not doc.get("versions"):
            raise Unknown(name)
        stamps = doc.get("time") or {}
        times = [_when(stamps.get("created"))] + [_when(stamps.get(v)) for v in doc["versions"]]
    known = [t for t in times if t is not None]
    if not known:
        raise OSError("no release dates")
    return min(known)


def _weekly_downloads(name: str) -> int:
    answer = _get(f"https://api.npmjs.org/downloads/point/last-week/{quote(name, safe='@/')}")
    return int((answer or {}).get("downloads") or 0)


def check(manager: str, packages: list[str], trusted: list[str]) -> None:
    """Raise Refused for the first package that may not be installed. `packages` are validated
    specs (validation.packages); `trusted` holds the owner's "pip:name" / "npm:name" entries."""
    allowed = {entry.lower() for entry in trusted}
    for spec in packages:
        name, pin = split(manager, spec)
        shown = name[:100]
        key = lookalike.normalize(manager, name)
        owner_trusts = f"{manager}:{key}" in allowed
        meant = None if owner_trusts else lookalike.resemble(manager, name)
        if meant:
            raise Refused(
                "package_lookalike",
                f"'{shown}' looks like the popular package '{meant}' but is not it. "
                f"Did you mean '{meant}'? Lookalike names are a common way to spread malware.",
            )
        # Refused is a ValueError: raise it outside this try, or it would read as a failed lookup.
        try:
            whole, bad, advisory = _kept_or(("osv", manager, key), partial(_malware, manager, name))
            malware = whole or bool(pin and pin in bad)
            first = weekly = None
            if not malware and not owner_trusts:
                first = _kept_or(("age", manager, key), partial(_first_release, manager, name))
                if manager == "npm":
                    weekly = _kept_or(("downloads", key), partial(_weekly_downloads, name))
        except Unknown:
            raise Refused(
                "package_unknown", f"The {manager} registry has no package named '{shown}'."
            ) from None
        except (OSError, ValueError, KeyError, TypeError, AttributeError, httpx.HTTPError):
            raise Refused(
                "package_check_failed",
                f"Could not check '{shown}' right now, so it was not installed. Try again later.",
            ) from None
        if malware:
            raise Refused(
                "package_malware",
                f"'{shown}' is listed as malware ({advisory}). It will not be installed.",
            )
        if first is None:  # the owner trusts it
            continue
        days = (time.time() - first) / 86400
        if days < MIN_AGE_DAYS:
            raise Refused(
                "package_too_new",
                f"'{shown}' was first published {int(days)} days ago; new packages are refused "
                f"for {MIN_AGE_DAYS} days unless the owner trusts them.",
            )
        if weekly is not None and weekly < MIN_WEEKLY_DOWNLOADS:
            raise Refused(
                "package_rarely_used",
                f"'{shown}' had {weekly} downloads last week; packages under "
                f"{MIN_WEEKLY_DOWNLOADS} are refused unless the owner trusts them.",
            )
