"""The messages of one IMAP UID FETCH answer: sender, subject, received time, a snippet and
whether attachments are listed.

Run by `mail_imap` in a child process of its own (`python -I -B mail_parse.py UIDS`, the server's
FETCH responses on stdin exactly as they came, JSON on stdout), because all of it is outside
content: a message is written by whoever sent it, and reading MIME, encoded words, charsets and
HTML is the work a hostile message can make slow or large. The parent kills the child after
`mail_imap.PARSE_SECONDS`. The child keeps its own clock from its start (`STARTED`): everything
fits in `TOTAL_SECONDS`, at least 3 s inside the parent's limit, and running out before the
answer is even split into responses is its own exit, `BUSY`. Each message gets
`MESSAGE_SECONDS` and is left out past them (the answer is then partial), newest first, so a
slow message costs only itself and those older than it. The address space is capped at
`MEMORY_BYTES` (Linux). The child imports nothing from ToolGate but `child_guard`, reads no
environment and never sees the account.

What it reads of each message whose UID the parent asked for (nothing else is in the answer):
- from: the first address of the From field and its display name, encoded words (RFC 2047)
  decoded. Both are the sender's own words: nothing here proves who sent it.
- subject: the Subject field, encoded words decoded.
- date: when the server received it (INTERNALDATE), in UTC. The Date field is the sender's word
  and is not read.
- snippet: the first text/plain part that is not an attachment, else the first text/html one
  (its tags dropped, script and style left out), decoded from base64 or quoted-printable and its
  charset, whitespace collapsed, at most `SNIPPET_CHARS`. Only the first `TEXT_BYTES` of the
  message's text were fetched, so a part that starts later gives no snippet.
- has_attachments: whether BODYSTRUCTURE lists a part with disposition attachment, an attached
  message, or a named part that is neither text nor inline.
Undecodable bytes become U+FFFD; an unknown charset (or one that is no plain text encoding) is
read as UTF-8. A message without UID or INTERNALDATE, or whose parts cannot be read, is left
out and the answer is partial; one whose BODYSTRUCTURE cannot be read is kept, without
attachments, and the answer is partial. The parent checks and cleans what comes back.
"""

from __future__ import annotations

import time as clock

# The child's own clock starts before the modules below load: their import is part of the time.
STARTED = clock.monotonic()

import base64  # noqa: E402
import binascii  # noqa: E402
import codecs  # noqa: E402
import email  # noqa: E402
import email.utils  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import sys  # noqa: E402
from datetime import UTC, datetime, timedelta, timezone  # noqa: E402
from email.parser import BytesParser  # noqa: E402
from html.parser import HTMLParser  # noqa: E402

if __package__:  # imported by ToolGate and its tests
    from toolgate.executors.child_guard import Busy, limit_memory, within
else:  # its own process (python -I): its folder, after the standard library
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from child_guard import Busy, limit_memory, within  # type: ignore[import-not-found]

LIMIT_BYTES = 2 * 1024 * 1024 + 65536  # mail_imap.TOTAL_BYTES and one read past it
TOTAL_SECONDS = 10.0
MESSAGE_SECONDS = 0.5
MEMORY_BYTES = 512 * 1024 * 1024
MAX_MESSAGES = 50
MAX_DEPTH = 64
MAX_PARTS = 200
TEXT_BYTES = 8192
SNIPPET_BYTES = 4096
SNIPPET_CHARS = 2048
FIELD_CHARS = 1000
UNREADABLE = 2
BUSY = 3
MONTHS = {
    name: index + 1
    for index, name in enumerate(
        ("JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC")
    )
}
RECEIVED = re.compile(rb" ?(\d{1,2})-([A-Za-z]{3})-(\d{4}) (\d\d):(\d\d):(\d\d) ([+-])(\d\d)(\d\d)")
# One IMAP token at a time: a quoted string, a literal's announcement, or an atom (which may
# hold a bracketed section such as BODY[HEADER.FIELDS (FROM)]<0>).
QUOTED = re.compile(rb'"((?:[^"\\\r\n]|\\[^\r\n])*)"')
LITERAL = re.compile(rb"\{(\d{1,10})\}\r\n")
ATOM = re.compile(rb'(?:[^ ()"{\r\n\[\]]|\[[^\]\r\n]*\])+')
ESCAPE = re.compile(rb"\\(.)")
UNFOLD = re.compile(rb"\r?\n[ \t]")
CUT_ESCAPE = re.compile(rb"=[0-9A-Fa-f]?\Z")
FIELD = re.compile(rb"([!-9;-~]+)[ \t]*:(.*)")
WORD = re.compile(r"=\?([^?\s]{1,40})\?([bBqQ])\?([^?\s]*)\?=")
# Codecs that are no charset a message can name, or are slow on hostile text.
ODD_CODECS = {"punycode", "idna", "unicode-escape", "raw-unicode-escape", "undefined"}
SKIPPED_TAGS = {"script", "style", "head", "title", "template", "noscript"}
# Tags that end a run of text (a space between their words and the next); others do not.
BLOCK_TAGS = {
    *("p", "div", "br", "hr", "li", "ul", "ol", "tr", "td", "th", "table", "blockquote"),
    *("h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "header", "footer", "pre"),
}


class Unreadable(Exception):
    """Not something this parser can read."""


def _tokens(data: bytes) -> tuple[list[list], bool]:
    """Each whole response in `data` as a list of tokens (atoms as str, strings as bytes, NIL as
    None, lists as lists), and whether something could not be read. A response nested deeper
    than MAX_DEPTH (a message built to be) is followed to its end, keeping nothing past that
    depth, and then left out, so it costs only itself; framing this cannot follow (a list closed
    that was never opened, a literal longer than the data, a stray byte) ends the reading."""
    responses: list[list] = []
    broken, at, end = False, 0, len(data)
    while at < end:
        stack: list[list] = [[]]
        deeper, spoiled = 0, False  # lists open past MAX_DEPTH: counted, not kept
        while True:
            if at >= end:
                return responses, True  # the data ends inside a response
            char = data[at]
            if char == 0x20:
                at += 1
                continue
            if data.startswith(b"\r\n", at):
                at += 2
                if len(stack) != 1 or deeper:
                    return responses, True
                if spoiled:
                    broken = True
                else:
                    responses.append(stack[0])
                break
            if char == 0x28:  # (
                if deeper or len(stack) > MAX_DEPTH:
                    deeper, spoiled = deeper + 1, True
                else:
                    stack[-1].append([])
                    stack.append(stack[-1][-1])
                at += 1
                continue
            if char == 0x29:  # )
                if deeper:
                    deeper -= 1
                elif len(stack) == 1:
                    return responses, True
                else:
                    stack.pop()
                at += 1
                continue
            if (match := QUOTED.match(data, at)) is not None:
                token = ESCAPE.sub(rb"\1", match.group(1)) if not deeper else None
                at = match.end()
            elif (match := LITERAL.match(data, at)) is not None:
                size, start = int(match.group(1)), match.end()
                if start + size > end:
                    return responses, True
                token = data[start : start + size] if not deeper else None
                at = start + size
            elif (match := ATOM.match(data, at)) is not None:
                atom = match.group(0).decode("latin-1")
                token = None if atom.upper() == "NIL" else atom
                at = match.end()
            else:
                return responses, True
            if not deeper:
                stack[-1].append(token)
    return responses, broken


def _item(name: str) -> str:
    """A FETCH item's name as the parser keys it: UID, INTERNALDATE, BODYSTRUCTURE, HEADER, TEXT."""
    name = name.upper()
    if name.startswith("BODY[HEADER"):
        return "HEADER"
    if name.startswith("BODY[TEXT]"):
        return "TEXT"
    return name


def _fetched(responses: list[list], wanted: set[int]) -> tuple[dict[int, dict], bool]:
    """The items of each asked-for message by UID (one message's items may come in several
    responses), and whether a FETCH response could not be read."""
    by_number: dict[str, dict] = {}
    broken = False
    for response in responses:
        if len(response) != 4 or response[0] != "*" or not isinstance(response[2], str):
            continue
        number, kind, items = response[1], response[2].upper(), response[3]
        if kind != "FETCH" or not isinstance(number, str) or not number.isdigit():
            continue
        if (
            not isinstance(items, list)
            or len(items) % 2
            or not all(isinstance(name, str) for name in items[::2])
        ):
            broken = True
            continue
        found = by_number.setdefault(number, {})
        for name, value in zip(items[::2], items[1::2], strict=True):
            found.setdefault(_item(name), value)
    messages: dict[int, dict] = {}
    for items in by_number.values():
        uid = items.get("UID")
        if isinstance(uid, str) and uid.isdigit() and int(uid) in wanted:
            messages.setdefault(int(uid), items)
    return messages, broken


def _received(value) -> str:
    """INTERNALDATE ("25-Nov-2026 08:00:00 +0100") as an ISO 8601 time in UTC."""
    match = RECEIVED.fullmatch(value) if isinstance(value, bytes) else None
    if match is None or match.group(2).decode().upper() not in MONTHS:
        raise Unreadable("received")
    day, month, year = (
        int(match.group(1)),
        MONTHS[match.group(2).decode().upper()],
        int(match.group(3)),
    )
    hours, minutes = int(match.group(8)), int(match.group(9))
    offset = timedelta(hours=hours, minutes=minutes) * (-1 if match.group(7) == b"-" else 1)
    if abs(offset) >= timedelta(hours=24) or minutes >= 60:
        raise Unreadable("offset")
    moment = datetime(
        year, month, day, *(int(match.group(i)) for i in (4, 5, 6)), tzinfo=timezone(offset)
    )
    return moment.astimezone(UTC).isoformat()


def _text(data: bytes, charset: str | None) -> str:
    """`data` decoded in `charset` (UTF-8 when it names no plain text encoding)."""
    name = (charset or "utf-8").strip().strip('"').lower()[:40] or "utf-8"
    try:
        if codecs.lookup(name).name in ODD_CODECS:
            raise LookupError(name)
        return data.decode(name, "replace")
    except Exception:  # LookupError, or a codec that refuses "replace"
        return data.decode("utf-8", "replace")


def _decoded_word(kind: str, data: str) -> bytes:
    raw = data.encode("ascii", "replace")
    if kind in "bB":
        return base64.b64decode(raw + b"=" * (-len(raw) % 4))
    return binascii.a2b_qp(raw.replace(b"_", b" "))


def _words(text: str) -> str:
    """Encoded words (RFC 2047) decoded. Whitespace between two of them is dropped, and the bytes
    of neighbours in the same charset are decoded together (some mailers split a character)."""
    out: list[str] = []
    run: list[bytes] = []
    run_charset: str | None = None
    last = 0
    for match in WORD.finditer(text):
        between = text[last : match.start()]
        charset = match.group(1).split("*", 1)[0].lower()
        try:
            data = _decoded_word(match.group(2), match.group(3))
        except (binascii.Error, ValueError):
            data = None
        joined = bool(run) and not between.strip()
        if run and not (joined and data is not None and charset == run_charset):
            out.append(_text(b"".join(run), run_charset))
            run = []
        if not joined or data is None:
            out.append(between)
        if data is None:
            out.append(match.group(0))
        else:
            run.append(data)
            run_charset = charset
        last = match.end()
    if run:
        out.append(_text(b"".join(run), run_charset))
    out.append(text[last:])
    return "".join(out)


def _fields(head: bytes) -> dict[str, bytes]:
    """The first value of each header field, unfolded."""
    fields: dict[str, bytes] = {}
    for line in UNFOLD.sub(b" ", head).splitlines():
        match = FIELD.fullmatch(line)
        if match is not None:
            fields.setdefault(match.group(1).decode("ascii").lower(), match.group(2).strip())
    return fields


def _sender(value: bytes) -> tuple[str, str]:
    """(display name, address) of the first address in a From field."""
    text = value.decode("utf-8", "replace")
    pairs = email.utils.getaddresses([text])
    name, address = pairs[0] if pairs else ("", "")
    if not address and not name:
        name = text  # no address in it: the field is all there is
    return _words(name)[:FIELD_CHARS], address[:FIELD_CHARS]


class _Visible(HTMLParser):
    """The text of an HTML part, script and style left out."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skipping = 0

    def handle_starttag(self, tag, attrs) -> None:
        if tag in SKIPPED_TAGS:
            self.skipping += 1
        elif tag in BLOCK_TAGS:
            self.parts.append(" ")

    def handle_endtag(self, tag) -> None:
        if tag in SKIPPED_TAGS and self.skipping:
            self.skipping -= 1
        elif tag in BLOCK_TAGS:
            self.parts.append(" ")

    def handle_data(self, data) -> None:
        if not self.skipping:
            self.parts.append(data)


def _payload(part) -> bytes:
    """A leaf part's body as bytes, at most TEXT_BYTES, its transfer encoding undone: base64
    here (from its letters, so a body the fetch cut off still gives its start), the rest by the
    email package (quoted-printable decoded; 7bit, 8bit and binary bytes as they came)."""
    if str(part.get("content-transfer-encoding", "")).strip().lower() != "base64":
        data = part.get_payload(decode=True)
        return data[:TEXT_BYTES] if isinstance(data, bytes) else b""
    raw = part.get_payload(decode=False)
    if isinstance(raw, str):  # base64 is ASCII; any other byte is no part of it
        letters = re.sub(rb"[^A-Za-z0-9+/]", b"", raw.encode("ascii", "replace"))
        letters = letters[: TEXT_BYTES // 3 * 4]
        rest = len(letters) % 4
        whole = binascii.a2b_base64(letters[: len(letters) - rest])
        # A last group of two or three letters still holds bytes (its padding was dropped).
        return whole + (
            binascii.a2b_base64(letters[-rest:] + b"=" * (4 - rest)) if rest > 1 else b""
        )
    return b""


def _snippet(message) -> str:
    """The start of the first text/plain part (else text/html, as text), whitespace collapsed."""
    chosen = None
    for index, part in enumerate(message.walk()):
        if index >= MAX_PARTS:
            break
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        kind = part.get_content_type()
        if kind == "text/plain":
            chosen = part
            break
        if kind == "text/html" and chosen is None:
            chosen = part
    if chosen is None:
        return ""
    data = _payload(chosen)
    if chosen.get_content_type() == "text/plain":
        text = _text(data[:SNIPPET_BYTES], chosen.get_content_charset())
    else:
        visible = _Visible()
        visible.feed(_text(data, chosen.get_content_charset()))
        visible.close()
        text = "".join(visible.parts)
    return " ".join(text.split())[:SNIPPET_CHARS]


def _word(value) -> str:
    return value.decode("latin-1").lower() if isinstance(value, bytes) else ""


def _named(params) -> bool:
    """Whether a BODYSTRUCTURE parameter list gives a file name."""
    if not isinstance(params, list):
        return False
    names = [_word(item) for item in params[::2]]
    return any(name.split("*", 1)[0] in ("name", "filename") for name in names)


def _attached(structure) -> bool:
    """Whether BODYSTRUCTURE lists an attachment (see the module's description)."""
    stack, seen = [structure], 0
    while stack:
        part = stack.pop()
        seen += 1
        if seen > MAX_PARTS or not isinstance(part, list) or not part:
            raise Unreadable("structure")
        if isinstance(part[0], list):  # a multipart: its parts come first, then its subtype
            for item in part:
                if not isinstance(item, list):
                    break
                stack.append(item)
            continue
        if len(part) < 2 or not isinstance(part[0], bytes) or not isinstance(part[1], bytes):
            raise Unreadable("structure")  # a part names its type and subtype first
        kind, subtype = _word(part[0]), _word(part[1])
        if kind == "message" and subtype in ("rfc822", "global"):
            return True
        # The disposition follows the body's fields (and, for text, its line count) and MD5.
        at = 9 if kind == "text" else 8
        disposition = part[at] if len(part) > at else None
        how = _word(disposition[0]) if isinstance(disposition, list) and disposition else ""
        if how == "attachment":
            return True
        if how == "inline" or kind == "text":
            continue
        if (len(part) > 2 and _named(part[2])) or (
            isinstance(disposition, list) and len(disposition) > 1 and _named(disposition[1])
        ):
            return True
    return False


def _bytes(value) -> bytes:
    return value if isinstance(value, bytes) else b""


def _message(uid: int, items: dict) -> tuple[dict, bool]:
    """One message in the parent's shape, and whether part of it could not be read."""
    received = _received(items.get("INTERNALDATE"))
    head, body = _bytes(items.get("HEADER")), _bytes(items.get("TEXT"))
    if len(body) >= TEXT_BYTES:  # cut off by the fetch: a quoted-printable escape it split goes
        body = CUT_ESCAPE.sub(b"", body)
    fields = _fields(head)
    name, address = _sender(fields.get("from", b""))
    subject = _words(fields.get("subject", b"").decode("utf-8", "replace"))[:FIELD_CHARS]
    mime = head.rstrip(b"\r\n") + b"\r\n\r\n" + body if head.strip() else b"\r\n" + body
    snippet = _snippet(BytesParser().parsebytes(mime))
    try:
        attached, unsure = _attached(items.get("BODYSTRUCTURE")), False
    except Unreadable:
        attached, unsure = False, True
    return {
        "uid": uid,
        "date": received,
        "from_name": name,
        "from_address": address,
        "subject": subject,
        "snippet": snippet,
        "has_attachments": attached,
    }, unsure


def read(
    data: bytes, wanted: set[int], total: float = TOTAL_SECONDS, started: float | None = None
) -> tuple[list[dict], bool]:
    """The asked-for messages in `data`, newest (highest UID) first, and whether some could not
    be read. Everything counts against `total` seconds from `started` (now when not given)."""
    deadline = (clock.monotonic() if started is None else started) + total
    if len(data) > LIMIT_BYTES:
        raise Unreadable("too large")
    responses, broken = within(deadline - clock.monotonic(), lambda: _tokens(data))
    found, bad = _fetched(responses, wanted)
    partial = broken or bad or len(found) < len(wanted)
    messages = []
    for uid in sorted(found, reverse=True)[:MAX_MESSAGES]:
        left = deadline - clock.monotonic()
        try:
            message, unsure = within(
                min(MESSAGE_SECONDS, left), lambda uid=uid: _message(uid, found[uid])
            )
        except Exception:  # Busy, Unreadable, or a message the email package cannot take
            partial = True
            continue
        messages.append(message)
        partial = partial or unsure
    return messages, partial


def _limit_memory() -> None:
    limit_memory(MEMORY_BYTES)


def main(argv: list[str]) -> int:
    _limit_memory()
    try:
        wanted = {int(uid) for uid in argv[1].split(",") if uid}
        messages, partial = read(sys.stdin.buffer.read(LIMIT_BYTES + 1), wanted, started=STARTED)
    except Busy:
        return BUSY
    except (Unreadable, ValueError, IndexError, MemoryError, OSError):
        return UNREADABLE
    sys.stdout.write(json.dumps({"messages": messages, "partial": partial}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
