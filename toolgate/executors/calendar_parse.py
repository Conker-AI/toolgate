"""The events of one iCalendar file in a window of days, repeating events expanded.

Run by `calendar_ics` in a child process of its own (`python -I -B calendar_parse.py DAYS ZONE
TODAY`, the file's bytes on stdin, JSON on stdout), because the repetition engine can be made to
spin: a rule that never matches walks the calendar to the year 9999, one that repeats every second
builds millions of times. The parent kills the child after `calendar_ics.PARSE_SECONDS`. The
child keeps its own clock from the moment it starts (`STARTED`, before the iCalendar libraries
load): reading the file, building its series and expanding them all fit in `TOTAL_SECONDS`, at
least 3 s inside the parent's limit (a test holds this), and running out of time before the
series are built is its own exit, `BUSY`, not the parent's kill.

What is read, so that the time holds whatever the file holds:
- At most `MAX_READ` events (VEVENT components) and `MAX_LINES` lines in all, the first ones in
  the file, with the calendar's own properties and up to `MAX_ZONES` time zones (VTIMEZONE).
  Tasks, journal entries and other components are not read.
- Each series gets `SERIES_SECONDS` and `MAX_PER_SERIES` occurrences and is left out past them;
  single events are expanded before repeating ones (the only kind that can spin), so they are
  never the ones the time runs out on.
- A zone name the zone database cannot load (folders such as `America` included) is an unknown
  zone, whose times float; an X-WR-TIMEZONE it cannot load is ignored.
- When the file cannot be read as a whole (one event with an UNTIL that is no date, or one zone
  without its offsets, fails them all), each event is tried on its own and those that read are
  kept, with the file's zones or else without them.
Whatever is left out, cut or skipped as broken (an event the engine did not return in any series)
makes the answer `partial`. The child imports nothing from ToolGate, reads no environment and never sees
the calendar's address.

Times: a timed event is given in ZONE with its offset; a floating time (no zone of its own) is
read in ZONE; an all-day event is a date, its end the day after it ends (as iCalendar writes it).
Cancelled occurrences are left out. Titles and places come back as the file wrote them, cut to
`TEXT_CHARS`; the parent cleans them.
"""

from __future__ import annotations

import _thread
import json
import re
import sys
import threading
import time as clock
from datetime import date, datetime, time, timedelta
from itertools import chain
from zoneinfo import ZoneInfo

# The child's own clock starts before the libraries below load: their import is part of the time.
STARTED = clock.monotonic()

import icalendar  # noqa: E402
import recurring_ical_events  # noqa: E402
from icalendar.timezone import tzp  # noqa: E402
from icalendar.timezone.zoneinfo import ZONEINFO  # noqa: E402

LIMIT_BYTES = 2 * 1024 * 1024
SERIES_SECONDS = 0.5
TOTAL_SECONDS = 10.0
MAX_READ = 2000
MAX_LINES = 40000
MAX_ZONES = 20
MAX_PER_SERIES = 1000
MAX_EVENTS = 200
TEXT_CHARS = 1000
MEMORY_BYTES = 512 * 1024 * 1024
UNREADABLE = 2
BUSY = 3
LF = bytes([10])
SPACE = b"\xef\xbb\xbf \t\r\n"
# As icalendar unfolds and splits (icalendar.parser.content_line), on bytes.
UNFOLD = re.compile(rb"(?:(?<!\n)\r\n|(?<![\r\n])\n)(?:\r?\n)*[ \t]")
NEWLINE = re.compile(rb"\r?\n")
OPEN, CLOSE = b"BEGIN:VCALENDAR", b"END:VCALENDAR"


class Unreadable(Exception):
    """Not an iCalendar file this parser can read."""


class Busy(Exception):
    """The time ran out."""


class _Budget:
    """Interrupts the main thread (KeyboardInterrupt) when the work runs past its seconds."""

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


def _within(seconds: float, work):
    """`work()`, or Busy when it runs past `seconds` (or none are left)."""
    if seconds <= 0:
        raise Busy
    budget, taken = _Budget(seconds), False
    try:
        with budget:
            result = work()
    except KeyboardInterrupt:
        taken = True
        raise Busy from None
    finally:
        if budget.fired and not taken:
            _settle()
    return result


def _settle() -> None:
    """A fired interrupt is on the way: take it here, not later. Busy either way (a library that
    swallowed it still ran out of time)."""
    try:
        for _ in range(200):
            clock.sleep(0.005)
    except KeyboardInterrupt:
        pass
    raise Busy


def _zone(name: str) -> ZoneInfo | None:
    """The zone called `name`, or None: no such zone, a path, or a folder of the zone database
    ("America"), which the file system refuses to open as a file (an OSError, not a KeyError)."""
    try:
        return ZoneInfo(name)
    except Exception:
        return None


class _Zones(ZONEINFO):
    """icalendar's zone lookup, with every name the database cannot load an unknown zone."""

    def timezone(self, name: str):
        return _zone(name)


def _lines(body: bytes) -> list[bytes]:
    """The file's content lines, unfolded and without blank ones, as icalendar reads them."""
    return [line for line in NEWLINE.split(UNFOLD.sub(b"", body.lstrip(SPACE))) if line]


def _marker(line: bytes) -> tuple[bytes, bytes]:
    """(BEGIN or END, the component's name) for a line that opens or closes one, else empty."""
    head = line[:5].upper()
    if head != b"BEGIN" and head[:3] != b"END":
        return b"", b""
    name, _, value = line.partition(b":")
    word = name.split(b";", 1)[0].strip().upper()
    return (word, value.strip().upper()) if word in (b"BEGIN", b"END") else (b"", b"")


def _parts(lines: list[bytes]) -> tuple[list[bytes], list[list[bytes]], list[list[bytes]], bool]:
    """The calendar's own properties, its zones and its events (each a component's lines), within
    the limits above, and whether any were left out."""
    props: list[bytes] = []
    kept: dict[bytes, list[list[bytes]]] = {b"VTIMEZONE": [], b"VEVENT": []}
    limits = {b"VTIMEZONE": MAX_ZONES, b"VEVENT": MAX_READ}
    stack: list[bytes] = []
    current: list[bytes] = []
    room, cut, opened = MAX_LINES, False, False
    for line in lines:
        word, name = _marker(line)
        if not stack:
            if opened:
                cut = True  # more after the calendar closed: not read
                break
            if (word, name) != (b"BEGIN", b"VCALENDAR"):
                raise Unreadable("not a calendar")
            opened = True
        if word == b"BEGIN":
            stack.append(name)
        if len(stack) >= 2 and stack[1] in kept:
            current.append(line)
        elif len(stack) == 1 and not word:
            if room > 0:
                props.append(line)
                room -= 1
            else:
                cut = True
        if word == b"END" and stack:
            closed = stack.pop()
            if len(stack) == 1 and current:
                if closed in kept and len(kept[closed]) < limits[closed] and len(current) <= room:
                    kept[closed].append(current)
                    room -= len(current)
                else:
                    cut = True
                current = []
    return props, kept[b"VTIMEZONE"], kept[b"VEVENT"], cut or bool(current) or bool(stack)


def _repeats(series) -> bool:
    """Whether a series has repeat rules (the costly kind); one that cannot say is taken as one."""
    try:
        return any(component.has_recurrence_rules() for component in series.components)
    except Exception:
        return True


def _series(props: list[bytes], zones: list[list[bytes]], events: list[list[bytes]]):
    """The series of one calendar made of these parts, single events first, and whether some
    were not read (an unusable X-WR-TIMEZONE, an event the engine skipped as broken)."""
    calendar = icalendar.Calendar.from_ical(
        LF.join([OPEN, *props, *chain(*zones), *chain(*events), CLOSE])
    )
    if getattr(calendar, "name", None) != "VCALENDAR":
        raise Unreadable("not a calendar")
    partial = False
    named = calendar.get("X-WR-TIMEZONE")
    if named is not None and _zone(str(named)) is None:
        del calendar["X-WR-TIMEZONE"]  # floating times are then read in ZONE
        partial = True
    query = recurring_ical_events.of(calendar, skip_bad_series=True)
    every = sorted(query.series, key=_repeats)
    # Every event of the file (with a UID or without) comes back in some series, or was skipped.
    return every, partial or _returned(every) < len(calendar.walk("VEVENT"))


def _returned(every) -> int:
    """How many of the file's events the series hold; -1 when one cannot say."""
    try:
        return sum(len(series.components) for series in every)
    except Exception:
        return -1


def _all_series(props, zones, events, deadline: float) -> tuple[list, bool]:
    """Every series of the file and whether some were not read. When the file cannot be read as
    a whole, each event is tried on its own (with the calendar's properties) and the ones that
    read are kept: one the engine cannot take costs only itself. Busy when the time runs out."""

    def within(work):
        return _within(deadline - clock.monotonic(), work)

    try:
        return within(lambda: _series(props, zones, events))
    except (Busy, Unreadable):
        raise
    except Exception:
        pass  # one event or zone the engine cannot take: try the events one by one
    kept = []
    for event in events:
        try:
            within(lambda event=event: _series(props, [], [event]))
        except Busy:
            raise
        except Exception:
            continue
        kept.append(event)
    for frame in (zones, []):  # a zone the engine cannot take: then without the file's zones
        try:
            return within(lambda frame=frame: _series(props, frame, kept))[0], True
        except Busy:
            raise
        except Exception:
            continue
    raise Unreadable("unparsable")


def _expand(series, start: datetime, end: datetime, seconds: float) -> list | None:
    """The occurrences of one series in the window; None when it is malformed, too many or late."""

    def occurrences() -> list:
        found = []
        for occurrence in series.between(start, end):
            found.append(occurrence.as_component(False))
            if len(found) > MAX_PER_SERIES:
                raise Unreadable("too many occurrences")
        return found

    try:
        return _within(seconds, occurrences)
    except Exception:
        return None


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
    body: bytes,
    days: int,
    zone: ZoneInfo,
    today: date,
    seconds: float = SERIES_SECONDS,
    total: float = TOTAL_SECONDS,
    started: float | None = None,
) -> tuple[list[dict], bool]:
    """The events overlapping `days` days from the start of `today` in `zone`, by start, and
    whether some could not be read. Everything counts against `total` seconds from `started`
    (now when not given); Busy when the file itself cannot be read in that time."""
    deadline = (clock.monotonic() if started is None else started) + total
    if len(body) > LIMIT_BYTES or body.lstrip(SPACE)[:15].upper() != OPEN:
        raise Unreadable("not an iCalendar file")
    tzp.use(_Zones())
    props, zones, events, cut = _within(deadline - clock.monotonic(), lambda: _parts(_lines(body)))
    every, partial = _all_series(props, zones, events, deadline)
    partial = partial or cut
    start = datetime.combine(today, time(), zone)
    end = datetime.combine(today + timedelta(days=days), time(), zone)
    found_events = []
    for series in every:
        left = deadline - clock.monotonic()
        found = _expand(series, start, end, min(seconds, left)) if left > 0 else None
        if found is None:
            partial = True
            continue
        for component in found:
            try:
                event = _event(component, zone)
            except (KeyError, ValueError, TypeError, Unreadable):
                partial = True
                continue
            if event is not None:
                found_events.append(event)
    found_events.sort(key=lambda event: _order(event, zone))
    return found_events[:MAX_EVENTS], partial


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
        events, partial = expand(
            sys.stdin.buffer.read(LIMIT_BYTES + 1), days, zone, today, started=STARTED
        )
    except Busy:
        return BUSY
    except (Unreadable, ValueError, IndexError, KeyError, MemoryError, OSError):
        return UNREADABLE
    sys.stdout.write(json.dumps({"events": events, "partial": partial}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
