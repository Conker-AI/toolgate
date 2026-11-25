# Calendar (read only)

`calendar.events` reads the owner's next events from one private iCalendar (ICS) address: the
"secret address" that Google Calendar, Outlook, Apple iCloud and Fastmail all offer. It never
writes to the calendar and needs no sign-in or OAuth. Like the other read-only built-ins it runs
without an approval card, and it costs nothing.

## Setting the address

The address is a secret: whoever has it can read the calendar. Store it in the vault like any
other secret, with the admin key (`X-ToolGate-Key`). Put
`{"name": "CALENDAR_ICS_URL", "value": "<the secret address>"}` in a file only you can read (so
the address stays out of shell history), then:

```bash
curl -X POST http://localhost:8010/vault/secrets \
  -H "X-ToolGate-Key: $TOOLGATE_ADMIN_KEY" -H "Content-Type: application/json" \
  --data @calendar-secret.json && rm calendar-secret.json
```

Change it with `PUT /vault/secrets/CALENDAR_ICS_URL` (body `{"value": "..."}`) and remove it with
`DELETE /vault/secrets/CALENDAR_ICS_URL`. As with every vault value, ToolGate stores it encrypted
and no route returns it: `GET /vault/secrets` lists the name only. Treat the address like a
password: if it leaks, reset the secret address at the calendar provider and store the new one.

`CALENDAR_ICS_URL` is read only by this tool (`vault.BUILTIN_SECRETS`). No other tool can name
it: an `http_json` secret header, an MCP server's `secret_ref` or a verification method that
names it is refused as not configured, so the address cannot be sent anywhere else.

## Who may read it

Startup registers `calendar.events` once if it is missing (category `safe`, authorization
`auto`) and never changes it afterwards, so the owner's edits stay. A caller needs a scope that
covers `tool:calendar.events`. The owner can grant it to the chat's own key with
`POST /v2/owner/tools/calendar.events/access` (`{"enabled": true, "expected_digest": ...}`), or
make the tool ask every time by marking it sensitive (`POST /v2/owner/tools/calendar.events/sensitive`)
or setting its authorization to `owner_confirmation`.

Limit: ToolGate's scope rules have no exact-grant-only kind yet, so a key that already holds `*`,
`tool:*` or a prefix such as `tool:cal*` covers `calendar.events` too, including after an upgrade
that adds the tool. Until that rule exists, give such wide scopes only to keys that may read the
owner's calendar, or mark the tool sensitive so that every read asks the owner.

## Asking

```json
POST /v2/tools/calendar.events/invoke
{"action_id": "morning-2026-11-24", "args": {"days": 1, "time_zone": "Europe/Berlin"}}
```

- `days`: 1 to 14, default 1. The window starts at midnight today in `time_zone`.
- `time_zone`: an IANA zone name, default `UTC`. Times come back in this zone with their offset.

The answer is `{"events": [...], "source": "ics", "partial": false}`, sorted by start, at most
200 events. Each event is `{"start", "end", "all_day", "title", "location"}`: ISO 8601 times (an
all-day event is a date, and its end is the day after its last day), the title and the place (or
`null`), each cleaned of invisible characters and cut to 200 characters. Repeating events are
expanded inside the window, with their exceptions and moved occurrences; cancelled events and
tasks are left out. `partial` is `true` when some events could not be read (see below); the rest
are still there.

Titles and places are the calendar's text, not the owner's words (an invitation can come from
anyone), so each one comes fenced like web and MCP text:

```text
[UNTRUSTED_CALENDAR_CONTENT field=title]
Dentist
[/UNTRUSTED_CALENDAR_CONTENT]
```

A fence token inside the text is defused (`[/UNTRUSTED_` becomes `(/UNTRUSTED_`), so the text
cannot close its fence. A caller must treat what is inside as outside content.

Replaying an `action_id` returns its receipt; a fresh read needs a new one. At most 6 reads a
minute and 60 an hour. One read takes at most 20 seconds (the fetch's 5, then the parser's 15).

## How the address is fetched

- `https://` only (a `webcal://` address is read as `https://`), port 443, no user name or
  password in it.
- The host must resolve to public addresses only, checked before the request and again for the
  address the socket connects to (`core/public_https.py`): private, loopback, link-local,
  carrier-grade NAT and tailnet ranges are refused.
- At most 3 redirects, each target checked by the same rules.
- 5 seconds in all, however slowly the server or the name server answers (each name lookup,
  connect, read and write gets only the time left, and none starts once it is up), 2 MB at
  most, never compressed.
- Requests go straight to the transport, so no HTTP client logs the address.

The file is then read by `executors/calendar_parse.py` in a child process that gets only the
file's bytes (no environment, no keys) and is stopped after 15 seconds (`executors/child_guard.py`,
shared with the mail parser). The child keeps its own
clock from the moment it starts: reading the file, building its series and expanding them get
10 seconds in all, and a child that runs out before its series are built says so itself
(`calendar_too_busy`), well before the parent's limit. (On Windows, where a virtual environment's
`python` is a launcher, the parent's kill stops the launcher only; the child still stops itself
at 10 seconds. ToolGate's server runs on Linux.) What it reads, so that a large or hostile
file still answers in time:

- A single (non-repeating) event that cannot touch the window is not read at all: its DTSTART
  and DTEND (or DURATION, a day more for its hours) lines are read first, with two days of
  margin for any time zone, and any doubt keeps the event, as does another version (the same
  UID, such as an occurrence of its series moved away) of an event that is read. Repeating
  events are always read. So years of past events cost nothing and do not make the answer
  `partial`.
- Of the rest, 2,000 events at most (and 40,000 lines, 20 time zones), single events before
  repeating ones; those past the limit are not read and the answer is `partial`.
- A repeating series that would take long to expand (a rule that never matches, one that repeats
  every second) is left out after half a second or 1000 occurrences, so one bad series costs only
  itself. Single events are read before repeating ones, so a calendar full of bad series still
  answers with its single events and the good series it reached.
- An event or zone the engine cannot take would fail the whole file (an RRULE whose UNTIL is no
  date, a VTIMEZONE without its offsets): then its halves are read, and the halves of a half that
  fails, down to the events that fail, which are left out (an event and its moved occurrences
  stay together). The file's zones are left out when they are the trouble (their events' times
  then float). An event the engine skips as broken (FREQ=BOGUS, a DTSTART that is no time) is
  left out.
- A zone name the zone database cannot load (`TZID=America`, a folder) is an unknown zone: that
  event's times are read in `time_zone`, as for any zone ToolGate does not know. An
  `X-WR-TIMEZONE` it cannot load is ignored.

Whatever is cut or skipped makes the answer `partial`; an event outside the window does not.

## Failures

Every failure is one fixed sentence that names no address:

| `code` | `error_code` | Meaning |
|---|---|---|
| `CALENDAR_NOT_CONFIGURED` (503) | | No address is stored, or the vault cannot open it. Nothing was sent. |
| `VALIDATION_ERROR` (422) | | `days` or `time_zone` is not valid (a folder of the zone database such as `America` is no zone). Nothing was sent. |
| `TOOL_UNAVAILABLE` | `calendar_address_refused` | The address, or a redirect, is not public `https://`. |
| `TOOL_UNAVAILABLE` | `calendar_unavailable` | The server could not be reached, did not answer 200, or was too slow. |
| `TOOL_UNAVAILABLE` | `calendar_too_large` | The file is over 2 MB. |
| `TOOL_UNAVAILABLE` | `calendar_unreadable` | The answer is not an iCalendar file. |
| `TOOL_UNAVAILABLE` | `calendar_too_busy` | The file could not be read in its 10 seconds (or the child was stopped at 15). |

Tests: `toolgate/tests/test_calendar_parse.py`, `test_calendar_limits.py`,
`test_calendar_window.py`, `test_calendar_fetch.py` and `test_calendar_boundary.py`, all on
synthetic files with no network.
