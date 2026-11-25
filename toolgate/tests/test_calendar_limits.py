"""What a large, hostile or broken calendar costs (executors/calendar_parse.py): the child's time
counted from its own start, at most MAX_READ events read, an event or zone the engine cannot take
costing only itself, and `partial` whenever something was not read."""

from __future__ import annotations

import io
import time
from zoneinfo import ZoneInfo

import pytest

from toolgate.executors import calendar_ics, calendar_parse
from toolgate.tests.calendar_fixtures import NL, PLAIN, TODAY, WEEK, calendar, event, inner

BERLIN = ZoneInfo("Europe/Berlin")
# A zone the file defines itself, three hours ahead of UTC.
OFFICE = NL.join(
    [
        "BEGIN:VTIMEZONE",
        "TZID:Office",
        "BEGIN:STANDARD",
        "DTSTART:19700101T000000",
        "TZOFFSETFROM:+0300",
        "TZOFFSETTO:+0300",
        "TZNAME:OFF",
        "END:STANDARD",
        "END:VTIMEZONE",
    ]
)
# Its UNTIL is no date: the file parses, then building its series fails for every event in it.
BAD_UNTIL = event("bad", "DTSTART:20261124T090000Z", "RRULE:FREQ=DAILY;UNTIL=notadate")


def read(body: bytes) -> tuple[list[tuple[str, str]], bool]:
    events, partial = calendar_parse.expand(body, 1, BERLIN, TODAY)
    return [(item["title"], item["start"]) for item in events], partial


def titles(body: bytes) -> tuple[list[str], bool]:
    events, partial = read(body)
    return [title for title, _ in events], partial


def short_events(count: int) -> list[str]:
    return [
        event(f"p{index}", "DTSTART:20261124T150000Z", "SUMMARY:Dentist") for index in range(count)
    ]


def never_events(count: int) -> list[str]:
    rule = "RRULE:FREQ=DAILY;BYMONTH=2;BYMONTHDAY=30"
    return [event(f"n{index}", "DTSTART:20260101T090000Z", rule) for index in range(count)]


def test_the_childs_time_counts_from_its_own_start():
    # Started at the call, a big file's parse ran before the budget began: a child that has
    # already used its time reads nothing more.
    spent = time.monotonic() - calendar_parse.TOTAL_SECONDS
    with pytest.raises(calendar_parse.Busy):
        calendar_parse.expand(WEEK, 1, BERLIN, TODAY, started=spent)


def test_the_child_starts_its_clock_before_loading_the_libraries(monkeypatch):
    monkeypatch.setattr(calendar_parse, "STARTED", time.monotonic() - calendar_parse.TOTAL_SECONDS)
    monkeypatch.setattr(calendar_parse, "_limit_memory", lambda: None)  # not this test process
    monkeypatch.setattr(calendar_parse.sys, "stdin", type("In", (), {"buffer": io.BytesIO(WEEK)}))
    argv = ["calendar_parse.py", "1", "UTC", TODAY.isoformat()]
    assert calendar_parse.main(argv) == calendar_parse.BUSY


def test_the_parent_reads_the_childs_busy_as_too_busy(monkeypatch):
    assert calendar_ics.BUSY == calendar_parse.BUSY
    assert calendar_ics.PARSE_SECONDS - calendar_parse.TOTAL_SECONDS >= 3  # the child stops first

    class Done:
        returncode = calendar_parse.BUSY
        stdout = b""

    monkeypatch.setattr(calendar_ics.subprocess, "run", lambda *_a, **_k: Done())
    with pytest.raises(calendar_ics.CalendarError) as busy:
        calendar_ics.parse(WEEK, 1, "UTC", TODAY)
    assert busy.value.code == "calendar_too_busy"


def old_events(count: int) -> list[str]:
    return [event(f"o{index}", "DTSTART:20200101T150000Z", "SUMMARY:Old") for index in range(count)]


@pytest.mark.parametrize(
    ("body", "cut"),
    [
        (calendar(*short_events(27000)), True),
        (calendar(*never_events(20000), PLAIN), True),
        (calendar(*old_events(27000), PLAIN), False),
    ],
    ids=["27000-events-today", "20000-series-that-never-match", "27000-events-in-2020"],
)
def test_a_calendar_near_2_mb_reads_inside_the_parents_limit(body, cut):
    # The reviewer's cases: they ran into the parent's 15 s kill, parsing 24,000 events alone
    # taking 8.6 s. Only MAX_READ events are read (single events that can touch the window
    # first), and the answer says when some were not; the plain event comes last in the file.
    assert 1_400_000 < len(body) <= calendar_parse.LIMIT_BYTES
    started = time.monotonic()
    events, partial = calendar_ics.parse(body, 1, "Europe/Berlin", TODAY)
    assert partial is cut and inner(events[0]["title"]) == "Dentist"
    assert time.monotonic() - started < calendar_ics.PARSE_SECONDS


def test_only_the_first_events_are_read_and_the_rest_make_the_answer_partial(monkeypatch):
    body = calendar(
        event("a", "DTSTART:20261124T150000Z", "SUMMARY:A"),
        event("b", "DTSTART:20261124T160000Z", "SUMMARY:B"),
        event("c", "DTSTART:20261124T140000Z", "SUMMARY:C"),
    )
    assert titles(body) == (["C", "A", "B"], False)
    monkeypatch.setattr(calendar_parse, "MAX_READ", 2)
    assert titles(body) == (["A", "B"], True)
    monkeypatch.setattr(calendar_parse, "MAX_READ", 3)
    monkeypatch.setattr(calendar_parse, "MAX_LINES", 12)  # VERSION, PRODID, two of five lines
    assert titles(body) == (["A", "B"], True)


@pytest.mark.parametrize("folder", ["America", "America/"])
def test_a_zone_folder_named_in_the_file_is_an_unknown_zone(folder):
    # The zone database opens a folder as a file and the file system refuses (PermissionError on
    # Windows, IsADirectoryError on Linux): that blanked the whole calendar. Its times now float.
    odd = event(
        "odd",
        f"DTSTART;TZID={folder}:20261124T100000",
        f"DTEND;TZID={folder}:20261124T110000",
        "SUMMARY:Folder",
    )
    assert read(calendar(odd, PLAIN)) == (
        [("Folder", "2026-11-24T10:00:00+01:00"), ("Dentist", "2026-11-24T16:00:00+01:00")],
        False,
    )


def test_an_x_wr_timezone_the_database_cannot_load_is_ignored():
    floating = event("floating", "DTSTART:20261124T080000", "SUMMARY:Floating")
    body = calendar(floating, PLAIN, header=("X-WR-TIMEZONE:America",))
    assert read(body) == (
        [("Floating", "2026-11-24T08:00:00+01:00"), ("Dentist", "2026-11-24T16:00:00+01:00")],
        True,
    )


def test_an_event_the_engine_cannot_take_costs_only_itself():
    assert titles(calendar(BAD_UNTIL, PLAIN)) == (["Dentist"], True)


def test_the_events_kept_after_a_broken_one_keep_the_files_own_zones():
    office = event("office", "DTSTART;TZID=Office:20261124T120000", "SUMMARY:Office")
    assert read(calendar(OFFICE, office, BAD_UNTIL)) == (
        [("Office", "2026-11-24T10:00:00+01:00")],
        True,
    )


def test_a_zone_the_engine_cannot_take_costs_only_its_own_times():
    # A VTIMEZONE without its offsets fails the whole file; its events are then read without
    # the file's zones (their times float), and the rest as always.
    broken = OFFICE.replace("TZOFFSETFROM:+0300" + NL, "").replace("TZOFFSETTO:+0300" + NL, "")
    office = event("office", "DTSTART;TZID=Office:20261124T120000", "SUMMARY:Office")
    assert read(calendar(broken, office, PLAIN)) == (
        [("Office", "2026-11-24T12:00:00+01:00"), ("Dentist", "2026-11-24T16:00:00+01:00")],
        True,
    )


@pytest.mark.parametrize(
    "broken",
    [
        event("bogus", "DTSTART:20261124T090000Z", "RRULE:FREQ=BOGUS", "SUMMARY:Bogus"),
        event("garbage", "DTSTART:garbage", "SUMMARY:Garbage"),
        NL.join(["BEGIN:VEVENT", "DTSTART:20261124T090000Z", "RRULE:FREQ=BOGUS", "END:VEVENT"]),
    ],
    ids=["bogus-frequency", "garbage-start", "bogus-without-a-uid"],
)
def test_an_event_the_engine_skips_as_broken_makes_the_answer_partial(broken):
    # The engine leaves these out on its own and says nothing; they are missing from its series.
    assert titles(calendar(broken, PLAIN)) == (["Dentist"], True)


def test_what_the_calendar_does_not_close_or_holds_after_it_ends_makes_the_answer_partial():
    late = event("late", "DTSTART:20261124T170000Z", "SUMMARY:Late")
    assert titles(calendar(PLAIN) + calendar(late)) == (["Dentist"], True)
    assert titles(calendar(PLAIN).replace(b"END:VCALENDAR", b"")) == (["Dentist"], True)
    assert titles(calendar(PLAIN)) == (["Dentist"], False)
