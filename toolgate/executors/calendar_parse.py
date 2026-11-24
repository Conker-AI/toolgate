"""The events of one iCalendar file in a window of days, repeating events expanded.

Run by `calendar_ics` in a child process of its own (`python -I -B calendar_parse.py DAYS ZONE
TODAY`, the file's bytes on stdin, JSON on stdout), because the repetition engine can be made to
spin: a rule that never matches walks the calendar to the year 9999, one that repeats every second
builds millions of times. The parent kills the child after `calendar_ics.PARSE_SECONDS`; inside,
each series gets `SERIES_SECONDS` and is left out when it runs past them, so one hostile
invitation costs that series and not the whole calendar. The child imports nothing from ToolGate,
reads no environment and never sees the calendar's address.

Times: a timed event is given in ZONE with its offset; a floating time (no zone of its own) is
read in ZONE; an all-day event is a date, its end the day after it ends (as iCalendar writes it).
Cancelled occurrences are left out. Titles and places come back as the file wrote them, cut to
`TEXT_CHARS`; the parent cleans them.
"""

from __future__ import annotations

import _thread
import json
import sys
import threading
import time as clock
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

import icalendar
import recurring_ical_events

LIMIT_BYTES = 2 * 1024 * 1024
SERIES_SECONDS = 0.5
MAX_PER_SERIES = 1000
MAX_EVENTS = 200
TEXT_CHARS = 1000
MEMORY_BYTES = 512 * 1024 * 1024
UNREADABLE = 2


class Unreadable(Exception):
    """Not an iCalendar file this parser can read."""


class _Budget:
    """Interrupts the main thread (KeyboardInterrupt) when one series runs past its seconds."""

    def __init__(self, seconds: float) -> None:
        self.lock = threading.Lock()
        self.armed = True
        self.fired = False
        self.timer = threading.Timer(seconds, self._fire)
        self.timer.daemon = True

    def _fire(self) -> None:
        with self.lock:
            if self.armed:
                self.armed, self.fired = False, True
                _thread.interrupt_main()

    def __enter__(self) -> _Budget:
        self.timer.start()
        return self

    def __exit__(self, *_exc) -> None:
        with self.lock:
            self.armed = False
        self.timer.cancel()


def _expand(series, start: datetime, end: datetime, seconds: float) -> list:
    """The occurrences of one series in the window, or [] when it is malformed, too many or late."""
    found = []
    try:
        with _Budget(seconds) as budget:
            for occurrence in series.between(start, end):
                found.append(occurrence.as_component(False))
                if len(found) > MAX_PER_SERIES:
                    raise Unreadable("too many occurrences")
        while budget.fired:  # its interrupt is on the way: take it here, not later
            clock.sleep(0.001)
    except (KeyboardInterrupt, Exception):
        return []
    return found


def _moment(value, zone: ZoneInfo) -> datetime | date:
    if isinstance(value, datetime):
        moment = value if value.tzinfo is not None else value.replace(tzinfo=zone)
        return moment.astimezone(zone)
    if isinstance(value, date):
        return value
    raise Unreadable("not a time")


def _text(value) -> str:
    return str(value)[:TEXT_CHARS] if value is not None else ""


def _event(component, zone: ZoneInfo) -> dict | None:
    if str(component.get("STATUS", "")).upper() == "CANCELLED":
        return None
    start = _moment(component.decoded("DTSTART"), zone)
    all_day = not isinstance(start, datetime)
    try:
        end = _moment(component.decoded("DTEND"), zone)
    except KeyError:
        end = start + timedelta(days=1) if all_day else start
    if all_day and isinstance(end, datetime):
        end = end.date()
    elif not all_day and not isinstance(end, datetime):
        end = datetime.combine(end, time(), zone)
    location = component.get("LOCATION")
    return {
        "start": start.isoformat(),
        "end": end.isoformat(),
        "all_day": all_day,
        "title": _text(component.get("SUMMARY")),
        "location": _text(location) if location is not None else None,
    }


def _order(event: dict, zone: ZoneInfo) -> tuple:
    """By start (an all-day event at the start of its day), all-day first, then by title."""
    if event["all_day"]:
        moment = datetime.combine(date.fromisoformat(event["start"]), time(), zone)
    else:
        moment = datetime.fromisoformat(event["start"])
    return (moment, not event["all_day"], event["title"])


def expand(
    body: bytes, days: int, zone: ZoneInfo, today: date, seconds: float = SERIES_SECONDS
) -> list[dict]:
    """The events overlapping `days` days from the start of `today` in `zone`, by start."""
    if len(body) > LIMIT_BYTES or not body.lstrip(b"\xef\xbb\xbf \t\r\n")[:15].upper().startswith(
        b"BEGIN:VCALENDAR"
    ):
        raise Unreadable("not an iCalendar file")
    try:
        calendar = icalendar.Calendar.from_ical(body)
        if getattr(calendar, "name", None) != "VCALENDAR":
            raise Unreadable("not a calendar")
        query = recurring_ical_events.of(calendar, skip_bad_series=True)
    except Unreadable:
        raise
    except Exception as exc:
        raise Unreadable("unparsable") from exc
    start = datetime.combine(today, time(), zone)
    end = datetime.combine(today + timedelta(days=days), time(), zone)
    events = []
    for series in query.series:
        for component in _expand(series, start, end, seconds):
            try:
                event = _event(component, zone)
            except (KeyError, ValueError, TypeError, Unreadable):
                continue
            if event is not None:
                events.append(event)
    events.sort(key=lambda event: _order(event, zone))
    return events[:MAX_EVENTS]


def _limit_memory() -> None:
    try:
        import resource
    except ImportError:  # not on Windows; the parent's timeout still applies
        return
    try:
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    except (ValueError, OSError):
        return


def main(argv: list[str]) -> int:
    _limit_memory()
    try:
        days, zone, today = int(argv[1]), ZoneInfo(argv[2]), date.fromisoformat(argv[3])
        events = expand(sys.stdin.buffer.read(LIMIT_BYTES + 1), days, zone, today)
    except (Unreadable, ValueError, IndexError, KeyError, MemoryError):
        return UNREADABLE
    sys.stdout.write(json.dumps({"events": events}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
