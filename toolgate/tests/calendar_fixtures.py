"""Synthetic iCalendar files for the calendar tests: no real calendar, address or person.

Every test reads "today" as Tuesday 24 November 2026.
"""

from __future__ import annotations

from datetime import date

TODAY = date(2026, 11, 24)
# A made-up secret address; PRIVATE_PART is the part a real provider keeps secret.
PRIVATE_PART = "made-up-private-part"
ADDRESS = f"https://calendar.example.com/ical/{PRIVATE_PART}/basic.ics"


def event(uid: str, *lines: str) -> str:
    return "\n".join(["BEGIN:VEVENT", f"UID:{uid}", *lines, "END:VEVENT"])


def calendar(*events: str, header: tuple[str, ...] = ()) -> bytes:
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Conker tests//EN", *header, *events]
    return ("\n".join([*lines, "END:VCALENDAR"]) + "\n").encode()


WEEK = calendar(
    event(
        "holiday",
        "DTSTART;VALUE=DATE:20261124",
        "DTEND;VALUE=DATE:20261125",
        "SUMMARY:Day off",
    ),
    event(
        "standup",
        "DTSTART;TZID=America/New_York:20261122T090000",
        "DTEND;TZID=America/New_York:20261122T093000",
        "RRULE:FREQ=DAILY;COUNT=6",
        "EXDATE;TZID=America/New_York:20261125T090000",
        "SUMMARY:Standup",
    ),
    event(
        "lunch",
        "DTSTART:20261124T110000Z",
        "DTEND:20261124T120000Z",
        "SUMMARY:Lunch with the team",
        "LOCATION:Corner cafe",
    ),
    event(
        "gym",
        "DTSTART;TZID=Europe/Berlin:20261103T180000",
        "DTEND;TZID=Europe/Berlin:20261103T190000",
        "RRULE:FREQ=WEEKLY;BYDAY=TU,TH",
        "SUMMARY:Gym",
    ),
    event(
        "gym",
        "RECURRENCE-ID;TZID=Europe/Berlin:20261126T180000",
        "DTSTART;TZID=Europe/Berlin:20261126T200000",
        "DTEND;TZID=Europe/Berlin:20261126T210000",
        "SUMMARY:Gym (late)",
    ),
    event(
        "called-off",
        "DTSTART:20261125T100000Z",
        "DTEND:20261125T110000Z",
        "STATUS:CANCELLED",
        "SUMMARY:Called off",
    ),
    event(
        "next-week",
        "DTSTART:20261203T100000Z",
        "DTEND:20261203T110000Z",
        "SUMMARY:Outside the window",
    ),
    "BEGIN:VTODO\nUID:todo\nSUMMARY:A task, not an event\nEND:VTODO",
)

# A rule that never matches (there is no 30 February): the engine walks to the year 9999.
NEVER = event(
    "never",
    "DTSTART:20260101T090000Z",
    "DTEND:20260101T100000Z",
    "RRULE:FREQ=DAILY;BYMONTH=2;BYMONTHDAY=30",
    "SUMMARY:Never",
)
EVERY_SECOND = event(
    "every-second",
    "DTSTART:20261124T000000Z",
    "RRULE:FREQ=SECONDLY",
    "SUMMARY:Every second",
)
PLAIN = event("plain", "DTSTART:20261124T150000Z", "DTEND:20261124T160000Z", "SUMMARY:Dentist")
