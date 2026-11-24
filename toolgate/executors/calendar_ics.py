"""The owner's calendar, read only: the next events of one private iCalendar (ICS) address.

The address is the owner's "secret address" from Google, Outlook, Apple or Fastmail: whoever
holds it can read the calendar. It lives in the vault as `CALENDAR_ICS_URL`, which only this
executor reads (`vault.builtin_secret`); no route returns it, and no failure, event, log line or
result carries it or any part of it: every failure is one of the fixed sentences in `WORDS`.

Fetching: https only (a `webcal://` address, as Apple gives it, is read as `https://`), port 443,
no user name or password in it; the host must resolve to public addresses only, checked before
the request and again for the address the socket uses (`core.public_https`, which refuses
private, loopback, link-local, carrier-grade NAT and tailnet ranges). At most `REDIRECTS`
redirects, each target checked the same way. `SECONDS` for the whole fetch, at most `LIMIT_BYTES`,
never compressed. Requests go straight to the transport, so no client logs the address.

Parsing runs `calendar_parse.py` in a child process with nothing but the file's bytes, killed
after `PARSE_SECONDS` (see that module for why).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urljoin
from zoneinfo import ZoneInfo

import httpx

from toolgate.core import vault
from toolgate.core.public_https import DestinationDenied, PublicTransport, public_url
from toolgate.core.untrusted_text import strip_invisible

SECRET = "CALENDAR_ICS_URL"
LIMIT_BYTES = 2 * 1024 * 1024
SECONDS = 5.0
REDIRECTS = 3
PARSE_SECONDS = 15.0
MAX_EVENTS = 200
TEXT_CHARS = 200
PARSER = Path(__file__).with_name("calendar_parse.py")
REDIRECT_CODES = {301, 302, 303, 307, 308}
HEADERS = {
    "Accept": "text/calendar, text/plain;q=0.8, */*;q=0.1",
    "Accept-Encoding": "identity",
    "User-Agent": "ToolGateCalendar/1.0",
}
WORDS = {
    "calendar_not_configured": "No calendar address is set.",
    "calendar_address_refused": "The calendar address must be a public https:// address.",
    "calendar_unavailable": "The calendar could not be fetched.",
    "calendar_too_large": "The calendar is larger than 2 MB.",
    "calendar_unreadable": "The calendar is not a readable iCalendar file.",
    "calendar_too_busy": "The calendar took too long to read.",
}


class CalendarError(Exception):
    """A known failure, named by its code; its message is fixed and names no address."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code
        self.message = WORDS[code]


def address() -> str:
    """The stored address. KeyError when none is set or the vault cannot read it (fail closed)."""
    value = vault.builtin_secret(SECRET).strip()
    if not value:
        raise KeyError(SECRET)
    return value


def _https(url: str) -> str:
    if url[:9].lower() == "webcal://":
        url = "https://" + url[9:]
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, ValueError, TypeError):
        raise CalendarError("calendar_address_refused") from None
    # public_url: https on port 443, a host, no user name or password, every address public.
    if not public_url(str(parsed)):
        raise CalendarError("calendar_address_refused")
    return str(parsed)


def _body(response: httpx.Response, deadline: float) -> bytes:
    if response.headers.get("content-encoding", "identity").strip().lower() not in ("", "identity"):
        raise CalendarError("calendar_unavailable")
    length = response.headers.get("content-length", "")
    if length.isdigit() and int(length) > LIMIT_BYTES:
        raise CalendarError("calendar_too_large")
    body = bytearray()
    for chunk in response.iter_raw():
        body.extend(chunk)
        if len(body) > LIMIT_BYTES:
            raise CalendarError("calendar_too_large")
        if time.monotonic() > deadline:
            raise CalendarError("calendar_unavailable")
    return bytes(body)


def fetch(url: str, transport: httpx.BaseTransport | None = None) -> bytes:
    """The file at `url`, under every rule above."""
    target = _https(url)
    deadline = time.monotonic() + SECONDS
    own = transport is None
    sender = PublicTransport() if transport is None else transport
    try:
        for _hop in range(REDIRECTS + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CalendarError("calendar_unavailable")
            request = httpx.Request(
                "GET",
                target,
                headers=HEADERS,
                extensions={"timeout": httpx.Timeout(remaining).as_dict()},
            )
            response = sender.handle_request(request)
            try:
                if response.status_code in REDIRECT_CODES:
                    target = _https(urljoin(target, response.headers.get("location", "")))
                    continue
                if response.status_code != 200:
                    raise CalendarError("calendar_unavailable")
                return _body(response, deadline)
            finally:
                response.close()
        raise CalendarError("calendar_unavailable")
    except CalendarError:
        raise
    except DestinationDenied:
        # The socket's own address was not public (a DNS answer that changed since the check).
        raise CalendarError("calendar_address_refused") from None
    except Exception:
        # Transport errors can carry the address; none of it leaves this function.
        raise CalendarError("calendar_unavailable") from None
    finally:
        if own:
            sender.close()


def _environment() -> dict[str, str]:
    """Nothing of ToolGate's environment (its keys) reaches the child; Windows needs its root."""
    root = os.environ.get("SYSTEMROOT")
    return {"SYSTEMROOT": root} if root else {}


def parse(body: bytes, days: int, zone: str, today: date) -> list[dict]:
    """Run the parser on `body`; the events it found, checked and cleaned."""
    try:
        done = subprocess.run(
            [sys.executable, "-I", "-B", str(PARSER), str(days), zone, today.isoformat()],
            input=body,
            capture_output=True,
            timeout=PARSE_SECONDS,
            env=_environment(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise CalendarError("calendar_too_busy") from None
    except OSError:
        raise CalendarError("calendar_unreadable") from None
    if done.returncode != 0:
        raise CalendarError("calendar_unreadable")
    try:
        events = json.loads(done.stdout)["events"]
        if not isinstance(events, list) or len(events) > MAX_EVENTS:
            raise ValueError("events")
        return [_checked(event) for event in events]
    except (ValueError, KeyError, TypeError):
        raise CalendarError("calendar_unreadable") from None


def _clean(value) -> str:
    if not isinstance(value, str):
        raise TypeError("text")
    return " ".join(strip_invisible(value).split())[:TEXT_CHARS]


def _checked(event) -> dict:
    """One event from the child in the output's exact shape; anything else is refused."""
    if not isinstance(event, dict) or set(event) != {
        "start",
        "end",
        "all_day",
        "title",
        "location",
    }:
        raise ValueError("event")
    all_day = event["all_day"]
    if type(all_day) is not bool:
        raise TypeError("all_day")
    for key in ("start", "end"):
        value = event[key]
        if not isinstance(value, str) or len(value) > 40:
            raise TypeError(key)
        if all_day:
            date.fromisoformat(value)  # a plain date: it has no time and no offset
        elif datetime.fromisoformat(value).tzinfo is None:
            raise ValueError(key)
    location = event["location"]
    return {
        "start": event["start"],
        "end": event["end"],
        "all_day": all_day,
        "title": _clean(event["title"]),
        "location": None if location is None else (_clean(location) or None),
    }


def known_zone(name: str) -> bool:
    try:
        ZoneInfo(name)
    except (KeyError, ValueError):
        return False
    return True


def read(
    days: int, zone: str = "UTC", now: datetime | None = None, transport=None
) -> dict[str, object]:
    """The events overlapping `days` days from the start of today in `zone` (a known zone), by
    start. KeyError when no address is set; CalendarError for every other failure."""
    url = address()
    tz = ZoneInfo(zone)
    today = (now or datetime.now(tz)).astimezone(tz).date()
    events = parse(fetch(url, transport), days, zone, today)
    return {"events": events, "source": "ics"}
