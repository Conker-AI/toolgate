"""Which events of a large file are read (executors/calendar_parse.py): a single event that cannot
touch the window is not read at all and does not count toward MAX_READ, single events come before
repeating ones, and one event the engine cannot take costs only itself, also among 2,000 others
and inside the time."""

from __future__ import annotations

import threading
import time
from zoneinfo import ZoneInfo

import pytest

from toolgate.executors import calendar_ics, calendar_parse, child_guard
from toolgate.tests.calendar_fixtures import NEVER, PLAIN, TODAY, WEEK, calendar, event, inner

BERLIN = ZoneInfo("Europe/Berlin")
BAD_UNTIL = event("bad", "DTSTART:20261124T090000Z", "RRULE:FREQ=DAILY;UNTIL=notadate")
NEVER_RULE = "RRULE:FREQ=DAILY;BYMONTH=2;BYMONTHDAY=30"


def titles(body: bytes, days: int = 1) -> tuple[list[str], bool]:
    events, partial = calendar_parse.expand(body, days, BERLIN, TODAY)
    return [item["title"] for item in events], partial


def old(index: int) -> str:
    return event(f"old{index}", "DTSTART:20200101T100000Z", "DTEND:20200101T110000Z", "SUMMARY:Old")


def sized(uid: str, *lines: str) -> str:
    """An event the size of a real one: a description and an attendee (the reviewer's probe)."""
    return event(
        uid,
        *lines,
        f"SUMMARY:{uid}",
        "DESCRIPTION:" + "x" * 200,
        "ATTENDEE;CN=A:mailto:a@example.com",
    )


def test_events_that_cannot_touch_the_window_are_not_read_and_do_not_count(monkeypatch):
    monkeypatch.setattr(calendar_parse, "MAX_READ", 2)
    later = event("later", "DTSTART:20270101T100000Z", "SUMMARY:Later")
    first = event("a", "DTSTART:20261124T150000Z", "SUMMARY:A")
    second = event("b", "DTSTART:20261124T160000Z", "SUMMARY:B")
    assert titles(calendar(old(1), first, later, second)) == (["A", "B"], False)


def test_2500_old_events_do_not_push_todays_out():
    # The reviewer's case: the cap kept the first 2,000 events of the file, all from 2020.
    assert titles(calendar(*(old(index) for index in range(2500)), PLAIN)) == (["Dentist"], False)


def test_single_events_are_read_before_repeating_ones(monkeypatch):
    monkeypatch.setattr(calendar_parse, "MAX_READ", 2)
    nevers = [event(f"n{index}", "DTSTART:20260101T090000Z", NEVER_RULE) for index in range(2)]
    assert titles(calendar(*nevers, PLAIN), days=1)[0] == ["Dentist"]


@pytest.mark.parametrize("broken", [False, True], ids=["whole", "halves"])
def test_a_single_event_sharing_a_uid_does_not_move_its_series_ahead(broken):
    # A plain event (SEQUENCE 0) with the UID of a series that never matches (SEQUENCE 1) sits
    # among the single events, and the engine groups the two: the series must still wait its
    # turn, read whole or in halves, or the budget runs out before the Dentist (listed last).
    hostile = []
    for index in range(20):
        uid = f"never-{index}"
        decoy = event(uid, "SEQUENCE:0", "DTSTART:20261124T090000Z", "SUMMARY:Decoy")
        hostile += [decoy, NEVER.replace("UID:never", f"UID:{uid}\nSEQUENCE:1")]
    body = calendar(*hostile, *([BAD_UNTIL] if broken else []), PLAIN)
    events, partial = calendar_parse.expand(body, 1, BERLIN, TODAY, 0.2, total=1.0)
    assert [item["title"] for item in events] == ["Dentist"] and partial


def test_an_event_that_might_touch_the_window_is_always_read():
    since = event("since", "DTSTART:20261101T100000Z", "DTEND:20261124T120000Z", "SUMMARY:Ends")
    lasting = event("lasting", "DTSTART;VALUE=DATE:20261101", "DURATION:P30D", "SUMMARY:Lasts")
    # 22:00 in Los Angeles on the 23rd is 07:00 in Berlin on the 24th: written a day early.
    west = event(
        "west",
        "DTSTART;TZID=America/Los_Angeles:20261123T220000",
        "DTEND;TZID=America/Los_Angeles:20261123T235900",
        "SUMMARY:West",
    )
    assert titles(calendar(since, lasting, west)) == (["Lasts", "Ends", "West"], False)


def test_an_event_given_as_a_duration_is_read_while_its_hours_may_reach_the_window():
    # 23:59 on the 19th, 12 hours behind UTC, plus 2 days 23 hours ends at 00:59 on the 24th for
    # an owner 14 hours ahead of UTC; the duration's whole days alone would end it on the 21st.
    far = event("far", "DTSTART;TZID=Etc/GMT+12:20261119T235900", "DURATION:P2DT23H", "SUMMARY:Far")
    events, partial = calendar_parse.expand(calendar(far), 1, ZoneInfo("Pacific/Kiritimati"), TODAY)
    assert [item["title"] for item in events] == ["Far"] and not partial


def test_an_occurrence_moved_out_of_the_window_stays_out():
    # The moved copy is dated in the past, but it says where today's occurrence went: read it.
    weekly = event("weekly", "DTSTART:20261103T100000Z", "RRULE:FREQ=WEEKLY", "SUMMARY:Weekly")
    moved = event(
        "weekly", "RECURRENCE-ID:20261124T100000Z", "DTSTART:20261110T100000Z", "SUMMARY:Moved"
    )
    assert titles(calendar(weekly, moved)) == ([], False)


def test_a_newer_version_of_an_event_outside_the_window_still_counts():
    # Moved from today to the 10th: the newer version (SEQUENCE 1) is outside the window, but the
    # engine must see it to know the older one no longer holds.
    was = event("moved", "SEQUENCE:0", "DTSTART:20261124T150000Z", "SUMMARY:Was today")
    now = event("moved", "SEQUENCE:1", "DTSTART:20261110T150000Z", "SUMMARY:Now earlier")
    assert titles(calendar(was, now)) == ([], False)
    assert titles(calendar(now, was)) == ([], False)


def test_a_series_and_its_moved_occurrence_stay_together_when_a_broken_event_is_left_out():
    # The file fails as a whole and its halves are read: the gym series and its moved
    # occurrence (the same UID) must be read together, or the occurrence comes back twice.
    body = WEEK.replace(b"END:VCALENDAR", BAD_UNTIL.encode() + b"\nEND:VCALENDAR")
    events, partial = calendar_parse.expand(body, 3, BERLIN, TODAY)
    assert [(item["start"], item["title"]) for item in events] == [
        ("2026-11-24", "Day off"),
        ("2026-11-24T12:00:00+01:00", "Lunch with the team"),
        ("2026-11-24T15:00:00+01:00", "Standup"),
        ("2026-11-24T18:00:00+01:00", "Gym"),
        ("2026-11-26T15:00:00+01:00", "Standup"),
        ("2026-11-26T20:00:00+01:00", "Gym (late)"),
    ]
    assert partial


def test_a_broken_event_among_2000_is_found_by_halves_not_by_reading_each_event(monkeypatch):
    # Reading each of 2,000 events on its own costs 2,000 parses and grows past the time on a
    # slower machine; halves cost two parses for each halving, about 22 for 2,000 events. This
    # counts the work, not the clock: six times the child's budget, so the Dentist, listed
    # last, comes back on any machine, and reading one by one still ends.
    calls = []
    series = calendar_parse._series

    def counted(*args):
        calls.append(1)
        return series(*args)

    monkeypatch.setattr(calendar_parse, "_series", counted)
    others = [event(f"s{index}", "DTSTART:20261124T200000Z") for index in range(1998)]
    body = calendar(*others, BAD_UNTIL, PLAIN)
    events, partial = calendar_parse.expand(body, 1, BERLIN, TODAY, total=60)
    assert events[0]["title"] == "Dentist" and partial
    assert len(calls) <= 2 + 2 * 11


def test_a_thread_that_cannot_start_costs_no_events(monkeypatch):
    # On Linux, under the child's address-space limit, a thread for each budget stopped
    # starting after a few dozen (an 8 MB stack each, kept a while after the thread ends): the
    # work it guarded looked broken, and its events were left out. One thread serves them all.
    started = []
    start = threading.Thread.start

    def refused_after_one(self):
        if started:
            raise RuntimeError("can't start new thread")
        started.append(self)
        return start(self)

    monkeypatch.setattr(threading.Thread, "start", refused_after_one)
    others = [event(f"s{index}", "DTSTART:20261124T200000Z") for index in range(98)]
    body = calendar(*others, BAD_UNTIL, PLAIN)
    events, partial = calendar_parse.expand(body, 1, BERLIN, TODAY)
    assert events[0]["title"] == "Dentist" and len(events) == 99 and partial


def test_a_watchdog_that_ended_is_started_again():
    # Otherwise no budget would fire again (a test's clock that raises could end it).
    ended = threading.Thread(target=lambda: None)
    ended.start()
    ended.join()
    child_guard.WATCH.thread = ended  # not restored: the new watchdog takes its place

    def spin() -> None:
        until = time.monotonic() + 2
        while time.monotonic() < until:
            pass

    with pytest.raises(calendar_parse.Busy):
        calendar_parse._within(0.05, spin)


def test_one_broken_event_among_100_leaves_the_last_one_in_through_the_child():
    # The small, fast form of the next test's 1998-today case: the Dentist is listed last.
    others = [sized(f"s{index}", "DTSTART:20261124T200000Z") for index in range(98)]
    body = calendar(*others, BAD_UNTIL, PLAIN)
    events, partial = calendar_ics.parse(body, 1, "Europe/Berlin", TODAY)
    assert inner(events[0]["title"]) == "Dentist" and partial


@pytest.mark.parametrize(
    ("others", "dentist"),
    [
        (
            [
                sized(f"y{index}", "DTSTART:20200101T100000Z", "RRULE:FREQ=YEARLY;COUNT=2")
                for index in range(1990)
            ],
            True,
        ),
        ([sized(f"s{index}", "DTSTART:20261124T200000Z") for index in range(1998)], False),
    ],
    ids=["1990-repeating", "1998-today"],
)
def test_one_broken_event_among_2000_is_answered_inside_the_time(others, dentist):
    # The reviewer's cases: reading each event on its own took 10.5 s and lost today's event, or
    # ran into the parent's kill. Halves are read instead, each building its series once.
    body = calendar(*others, BAD_UNTIL, PLAIN)
    started = time.monotonic()
    events, partial = calendar_ics.parse(body, 1, "Europe/Berlin", TODAY)
    assert partial and time.monotonic() - started < calendar_ics.PARSE_SECONDS
    # Among 1,990 repeating events the Dentist is the one single event, expanded first. Among
    # 1,999 single events in the window, how many the child's budget reaches is the machine's;
    # the Dentist (listed last) is then the count test's and the smaller test's above.
    assert not dentist or inner(events[0]["title"]) == "Dentist"
