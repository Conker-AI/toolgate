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
- Single events that cannot touch the window (read cheaply from their DTSTART, DTEND or
  DURATION lines, with `MARGIN` for any zone; any doubt keeps the event) are not read at all,
  unless another version of them (the same UID, a moved occurrence among them) is read.
  Of the rest, at most `MAX_READ` events (VEVENT components) and `MAX_LINES` lines in all,
  single events before repeating ones and each kind in file order, with the calendar's own
  properties and up to `MAX_ZONES` time zones (VTIMEZONE). Tasks, journal entries and other
  components are not read.
- Each series gets `SERIES_SECONDS` and `MAX_PER_SERIES` occurrences and is left out past them;
  single events are expanded before repeating ones (the only kind that can spin; by kind, as a
  single event can share its UID with a series), so they are never the ones the time runs
  out on.
- A zone name the zone database cannot load (folders such as `America` included) is an unknown
  zone, whose times float; an X-WR-TIMEZONE it cannot load is ignored.
- When the file cannot be read as a whole (one event with an UNTIL that is no date fails them
  all), its halves are read, and the halves of each half that fails, down to the events that
  fail, which are left out: each half that reads builds its series once. An event and its
  moved occurrences (the same UID) stay together. When the file's zones are what fails, the
  events are read without them.
Whatever is cut or skipped as broken (an event the engine did not return in any series) makes
the answer `partial`; an event outside the window does not. The child imports nothing from
ToolGate, reads no environment and never sees the calendar's address.

Times: a timed event is given in ZONE with its offset; a floating time (no zone of its own) is
read in ZONE; an all-day event is a date, its end the day after it ends (as iCalendar writes it).
Cancelled occurrences are left out. Titles and places come back as the file wrote them, cut to
`TEXT_CHARS`; the parent cleans them.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time as clock
from datetime import date, datetime, time, timedelta
from itertools import chain
from zoneinfo import ZoneInfo

if __package__:  # imported by ToolGate and its tests
    from toolgate.executors.child_guard import Busy, limit_memory
    from toolgate.executors.child_guard import within as _within
else:  # its own process (python -I): its folder, after the standard library
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from child_guard import Busy, limit_memory  # type: ignore[import-not-found]
    from child_guard import within as _within  # type: ignore[import-not-found]

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
KEPT = (b"VEVENT", b"VTIMEZONE")
# A line that makes an event repeat, or move one occurrence of a series: never left out unread.
REPEATS = (b"RRULE", b"RDATE", b"EXRULE")
DAY = re.compile(rb"(\d{8})(T\d{6}Z?)?")
# Days by which an event's written day can differ from the window's: any zone's offset, and
# an end or a duration read as whole days.
MARGIN = timedelta(days=2)


class Unreadable(Exception):
    """Not an iCalendar file this parser can read."""


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


def _own(block: list[bytes]):
    """(name, value) of each of a component's own lines, not those of components inside it."""
    depth = 0
    for line in block[1:-1]:
        word, _ = _marker(line)
        if word:
            depth += 1 if word == b"BEGIN" else -1
        elif not depth:
            name, _, value = line.partition(b":")
            yield name.split(b";", 1)[0].strip().upper(), value


def _day(value: bytes) -> date | None:
    """The day an iCalendar date or date-time is written on, or None."""
    match = DAY.fullmatch(value.strip())
    if match is None:
        return None
    try:
        return datetime.strptime(match.group(1).decode(), "%Y%m%d").date()
    except ValueError:
        return None


def _span(block: list[bytes]) -> tuple[date, date] | None:
    """The first and last day a single event is written to touch; None for one that repeats, and
    whenever anything about it is in doubt. (A moved occurrence is a single event here: the
    version rule in `_parts` reads it whenever its series is read.)"""
    found: dict[bytes, bytes] = {}
    for name, value in _own(block):
        if name in REPEATS:
            return None
        if name in (b"DTSTART", b"DTEND", b"DURATION"):
            if name in found:
                return None
            found[name] = value
    start = _day(found.get(b"DTSTART", b""))
    if start is None or (b"DTEND" in found and b"DURATION" in found):
        return None
    if b"DURATION" in found:
        try:
            length = icalendar.vDuration.from_ical(found[b"DURATION"].strip().decode())
            # Whole days, and one more: the start's time of day and the duration's hours (each
            # under a day) can carry the end that far, as a DTEND's own time can past its day.
            end = start + timedelta(days=length.days + 1)
        except Exception:
            return None
    else:
        end = _day(found[b"DTEND"]) if b"DTEND" in found else start
    return None if end is None or end < start else (start, end)


def _parts(
    lines: list[bytes], first: date, last: date
) -> tuple[list[bytes], list[list[bytes]], list[list[bytes]], bool]:
    """The calendar's own properties, its zones and the events that can touch the days from
    `first` to `last` (each a component's lines), within the limits above, and whether any were
    left out by them."""
    props: list[bytes] = []
    zones: list[list[bytes]] = []
    singles: list[list[bytes]] = []
    repeating: list[list[bytes]] = []
    outside: list[list[bytes]] = []
    stack: list[bytes] = []
    current: list[bytes] = []
    cut, opened = False, False
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
        if len(stack) >= 2 and stack[1] in KEPT:
            current.append(line)
        elif len(stack) == 1 and not word:
            props.append(line)
        if word == b"END" and stack:
            closed = stack.pop()
            if len(stack) == 1 and current:
                span = _span(current) if closed == b"VEVENT" else None
                if closed == b"VTIMEZONE":
                    zones.append(current)
                elif span is None:
                    repeating.append(current)
                elif span[1] >= first and span[0] <= last:
                    singles.append(current)
                else:
                    outside.append(current)
                current = []
    # An event outside the window is not read, unless another version of it (the same UID: a
    # higher SEQUENCE perhaps, or an occurrence of its series moved away) is: the engine needs both.
    uids = {_block_uid(block) for block in singles + repeating} - {None}
    singles += [block for block in outside if _block_uid(block) in uids]
    cut = cut or bool(current) or bool(stack) or len(props) > MAX_LINES
    room = MAX_LINES - len(props[:MAX_LINES])
    kept: list[list[list[bytes]]] = [[], []]
    for taken, blocks, limit in (
        (kept[0], zones, MAX_ZONES),
        (kept[1], singles + repeating, MAX_READ),
    ):
        for block in blocks:
            if len(taken) < limit and len(block) <= room:
                taken.append(block)
                room -= len(block)
            else:
                cut = True
    return props[:MAX_LINES], kept[0], kept[1], cut


def _calendar(props: list[bytes], zones: list[list[bytes]], events: list[list[bytes]]):
    """One calendar parsed from these parts."""
    calendar = icalendar.Calendar.from_ical(
        LF.join([OPEN, *props, *chain(*zones), *chain(*events), CLOSE])
    )
    if getattr(calendar, "name", None) != "VCALENDAR":
        raise Unreadable("not a calendar")
    return calendar


def _part_of(whole, zones: list, events: list):
    """A calendar with `whole`'s own properties and only these zones and events (parsed)."""
    part = icalendar.Calendar()
    part.update(whole)
    part.subcomponents = [*zones, *events]
    return part


def _series(calendar) -> tuple[list, bool]:
    """The calendar's series, single events first, and whether some were not read (an unusable
    X-WR-TIMEZONE, an event the engine skipped as broken)."""
    partial = False
    named = calendar.get("X-WR-TIMEZONE")
    if named is not None and _zone(str(named)) is None:
        del calendar["X-WR-TIMEZONE"]  # floating times are then read in ZONE
        partial = True
    query = recurring_ical_events.of(calendar, skip_bad_series=True)
    # By kind and not file order alone: a single event can share its UID with a series.
    every = sorted(query.series, key=_repeats)
    return every, partial or _missing(calendar, every)


def _repeats(series) -> bool:
    """Whether a series has repeat rules (the costly kind); one that cannot say is taken as one."""
    try:
        return any(component.has_recurrence_rules() for component in series.components)
    except Exception:
        return True


def _missing(calendar, every) -> bool:
    """Whether an event of the file came back in no series (the engine skips a broken one and
    says nothing): a UID no series has, or fewer other series than events without a UID. An
    older version of an event (the same UID, a lower SEQUENCE) is the engine's to drop."""
    uids = [component.get("UID") for component in calendar.walk("VEVENT")]
    named = {str(uid) for uid in uids if uid}
    try:
        returned = {str(series.uid) for series in every}
    except Exception:
        return True
    return not named <= returned or len(returned - named) < sum(1 for uid in uids if not uid)


def _groups(items: list, uid) -> list[list]:
    """The events, those with the same UID together (a series and its moved occurrences)."""
    groups: dict[object, list] = {}
    for index, item in enumerate(items):
        groups.setdefault(uid(item) or index, []).append(item)
    return list(groups.values())


def _block_uid(block: list[bytes]) -> bytes | None:
    return next((value.strip() for name, value in _own(block) if name == b"UID"), None)


def _readable(groups: list[list], read, failed: bool = False) -> list:
    """The series of these groups of events read together (`read`); when they fail together
    (`failed`: known to), those of each half, and so on down to the single groups that fail."""
    if not failed:
        try:
            return read(groups)
        except Busy:
            raise
        except Exception:
            pass
    if len(groups) <= 1:
        return []
    middle = len(groups) // 2
    return _readable(groups[:middle], read) + _readable(groups[middle:], read)


def _all_series(props, zones, events, deadline: float) -> tuple[list, bool]:
    """Every series of the file and whether some were not read. When the file cannot be read as
    a whole, its halves are (`_readable`), so one event the engine cannot take costs only
    itself: from the parsed file when only building its series fails, from its text when parsing
    does. Without the file's zones when they are what fails. Busy when the time runs out."""

    def within(work):
        return _within(deadline - clock.monotonic(), work)

    try:
        whole = within(lambda: _calendar(props, zones, events))
    except (Busy, Unreadable):
        raise
    except Exception:  # the text itself fails: read its parts as text

        def build(frame, items):
            return _calendar(props, frame, items)

        frames, groups = (zones, []), _groups(events, _block_uid)
    else:
        try:
            return within(lambda: _series(whole))
        except (Busy, Unreadable):
            raise
        except Exception:
            pass  # one event or zone the engine cannot take: find what reads

        def build(frame, items):
            return _part_of(whole, frame, items)

        own = whole.subcomponents
        frames = ([item for item in own if item.name == "VTIMEZONE"], [])
        groups = _groups(
            [item for item in own if item.name == "VEVENT"], lambda item: item.get("UID")
        )
    for frame in frames:  # the file's zones, else none: what reads without the events
        try:
            within(lambda frame=frame: _series(build(frame, [])))
        except Busy:
            raise
        except Exception:
            continue

        def read(part, frame=frame):
            return within(lambda: _series(build(frame, list(chain(*part)))))[0]

        return sorted(_readable(groups, read, frame is frames[0]), key=_repeats), True
    raise Unreadable("unparsable")  # the calendar's own lines fail


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
    first, last = today - MARGIN, today + timedelta(days=days) + MARGIN
    props, zones, events, cut = _within(
        deadline - clock.monotonic(), lambda: _parts(_lines(body), first, last)
    )
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
    limit_memory(MEMORY_BYTES)


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
