"""The owner's mail, read only: the newest INBOX messages of one IMAP account (`mail.recent`).

The account lives in the vault as MAIL_IMAP_HOST, MAIL_IMAP_USER and MAIL_IMAP_PASSWORD (an
app password), which only this executor reads (`vault.builtin_secret`). No route returns them,
and no failure, message, log line or result carries any of them: every failure is one of the
fixed sentences in `WORDS`, and the server's own words never leave this module. Without all
three, `read` answers "not connected" and nothing is sent.

Connecting: implicit TLS only, port `PORT` (no STARTTLS, no plaintext, no POP or SMTP), TLS 1.2
or newer, the certificate checked against certifi's roots (as for public HTTPS) and against the
host's name, which is also sent as SNI. The host must be a DNS name; it is looked up once,
under the deadline, and every address must be public (`core.public_https.public_addresses`:
private, loopback, link-local, multicast, reserved, carrier-grade NAT and tailnet ranges are
refused). The socket connects to those numbers, so nothing is looked up a second time.

Strictly read only. `Session.send` writes nothing but the commands in `READ_ONLY` (LOGIN,
EXAMINE, UID SEARCH, UID FETCH, LOGOUT) and refuses a fetch of any body section that is not
BODY.PEEK or of an RFC822 item that marks a message read; INBOX is opened with EXAMINE, never
SELECT, and the server must confirm it read-only. So no STORE, COPY, MOVE, EXPUNGE or APPEND is
ever sent and no \\Seen flag changes.

Limits: `SECONDS` for the whole conversation (the lookup, connect, handshake and every read and
write get only the time left), `TOTAL_BYTES` read from the server at most. First the size of
every message asked for (`SIZE_ITEMS`, one small command). Then each message on its own, newest
first (the commands pipelined): its fields and the first `TEXT_BYTES` of its text
(`CONTENT_ITEMS`, whose partial ranges keep an honest server's answer under `MESSAGE_BYTES`).
Then, apart, each one's structure (`STRUCTURE_ITEMS`, at most `STRUCTURE_BYTES`), smallest
message first. An answer over its share is dropped and the answer is partial; at the total cap
the reading stops with what came whole. A structure is made of its message's parts, so a huge
one comes from a large message: a stranger's message built that way costs at most the
structures (the attachment flags) of messages as large as itself, never another message's
fields or text. The answer is parsed by `mail_parse.py` in a child process with nothing but
those bytes (`child_guard`), killed after `PARSE_SECONDS`.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import subprocess
import time
from datetime import UTC, datetime, timedelta
from itertools import count
from pathlib import Path

import httpx

from toolgate.core import vault
from toolgate.core.public_https import DestinationDenied, public_addresses
from toolgate.core.untrusted_text import fenced, strip_invisible
from toolgate.executors import child_guard

SECRETS = ("MAIL_IMAP_HOST", "MAIL_IMAP_USER", "MAIL_IMAP_PASSWORD")
PORT = 993
SECONDS = 12.0
PARSE_SECONDS = 15.0
BUSY = 3  # mail_parse.BUSY: the child ran out of its own time
MAX_HOURS = 72
MAX_MESSAGES = 50
TOTAL_BYTES = 2 * 1024 * 1024
MESSAGE_BYTES = 20 * 1024  # a message's fields and text: two 8 KB partial ranges
STRUCTURE_BYTES = 16 * 1024  # a message's BODYSTRUCTURE: about 150 parts
LINE_BYTES = 16 * 1024
SEARCH_BYTES = 512 * 1024
HEADER_BYTES = 8192
TEXT_BYTES = 8192
CHARS = {"name": 200, "address": 320, "subject": 300, "snippet": 300}
CHILD_CHARS = 4096
PARSER = Path(__file__).with_name("mail_parse.py")
CA_FILE: str | None = None  # tests only: one more root to trust (their own test authority)
READ_ONLY = ("LOGIN ", "EXAMINE ", "UID SEARCH ", "UID FETCH ")  # and LOGOUT itself
FIELDS = "FROM SUBJECT CONTENT-TYPE CONTENT-TRANSFER-ENCODING"
CONTENT_ITEMS = (
    f"(UID INTERNALDATE BODY.PEEK[HEADER.FIELDS ({FIELDS})]<0.{HEADER_BYTES}>"
    f" BODY.PEEK[TEXT]<0.{TEXT_BYTES}>)"
)
STRUCTURE_ITEMS = "(UID BODYSTRUCTURE)"
SIZE_ITEMS = "(UID RFC822.SIZE)"
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
# A DNS name whose last label starts with a letter (so no address literal), ASCII only.
HOST = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
LITERAL = re.compile(rb"\{(\d{1,10})\}\Z")
SEARCH = re.compile(rb"\* SEARCH((?: \d{1,10})*) ?")
FETCH = re.compile(rb"\* \d{1,10} FETCH \(")
VALIDITY = re.compile(rb"\[UIDVALIDITY (\d{1,10})\]")
# A size answer, its two items in either order.
SIZED = re.compile(
    rb"\* \d{1,10} FETCH \((?:UID (\d{1,10}) RFC822\.SIZE (\d{1,12})"
    rb"|RFC822\.SIZE (\d{1,12}) UID (\d{1,10}))\)\r\n"
)
WORDS = {
    "mail_not_connected": "No mail account is connected: store MAIL_IMAP_HOST, MAIL_IMAP_USER "
    "and MAIL_IMAP_PASSWORD (an app password) in ToolGate's vault.",
    "mail_address_refused": "The mail server must be a public host name.",
    "mail_certificate_refused": "The mail server's certificate could not be verified.",
    "mail_login_refused": "The mail server did not accept the user name and app password.",
    "mail_unavailable": "The mail server could not be read.",
    "mail_unreadable": "The mail could not be read.",
    "mail_too_busy": "The mail took too long to read.",
}


class MailError(Exception):
    """A known failure, named by its code; its message is fixed and names nothing of the account."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code
        self.message = WORDS[code]


class _Cut(Exception):
    """TOTAL_BYTES were read: nothing more is."""


def account() -> tuple[str, str, str]:
    """(host, user, app password). KeyError when one is not set or the vault cannot read it
    (fail closed: then nothing is sent)."""
    host, user, password = (vault.builtin_secret(name).strip() for name in SECRETS)
    if not host or not user or not password:
        raise KeyError("mail account")
    return host.lower(), user, password


def read_only(command: str) -> bool:
    """Whether `command` is one this reader may send: one that changes nothing on the server."""
    if command == "LOGOUT":
        return True
    if any(char in command for char in "\r\n\0") or not command.startswith(READ_ONLY):
        return False
    if not command.startswith("UID FETCH "):
        return True
    items = command.upper()
    # BODY[...] and BINARY[...] mark a message read (BODY.PEEK[...] does not), as do RFC822
    # and RFC822.TEXT; RFC822.SIZE and RFC822.HEADER do not.
    return (
        "BODY[" not in items.replace("BODY.PEEK[", "")
        and "BINARY[" not in items
        and re.search(r"RFC822(?!\.SIZE|\.HEADER)", items) is None
    )


def _quoted(value: str) -> str:
    """An IMAP quoted string; ValueError for what one cannot carry (CR, LF, NUL, non-ASCII)."""
    if not value.isascii() or any(char in value for char in "\r\n\0"):
        raise ValueError("unquotable")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def tls_context() -> ssl.SSLContext:
    context = httpx.create_ssl_context(trust_env=False)  # certifi's roots, as public HTTPS uses
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode, context.check_hostname = ssl.CERT_REQUIRED, True
    if CA_FILE:
        context.load_verify_locations(cafile=CA_FILE)
    return context


def _left(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise MailError("mail_unavailable")
    return left


def _connect(
    host: str, addresses: list[str], deadline: float, context: ssl.SSLContext
) -> ssl.SSLSocket:
    """A TLS connection to the first of `addresses` that answers, verified for `host`."""
    for address in addresses:
        raw = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET)
        try:
            raw.settimeout(_left(deadline))
            raw.connect((address, PORT))
        except OSError:
            raw.close()
            continue
        except BaseException:
            raw.close()
            raise
        tls = context.wrap_socket(raw, server_hostname=host, do_handshake_on_connect=False)
        try:
            tls.settimeout(_left(deadline))
            tls.do_handshake()
            if tls.version() not in ("TLSv1.2", "TLSv1.3"):
                raise MailError("mail_unavailable")
            return tls
        except ssl.SSLCertVerificationError:
            tls.close()
            raise MailError("mail_certificate_refused") from None
        except OSError:
            tls.close()
            raise MailError("mail_unavailable") from None
        except BaseException:
            tls.close()
            raise
    raise MailError("mail_unavailable")


class Session:
    """One IMAP conversation over `sock`, read only (`send`), framed by lines and literals."""

    def __init__(self, sock, deadline: float) -> None:
        self.sock, self.deadline = sock, deadline
        self.buffer = bytearray()
        self.received = 0
        self.tags = count(1)

    def send(self, command: str) -> bytes:
        """Write `command` under a new tag (returned); anything not `read_only` is refused before
        a byte is written."""
        if not read_only(command):
            raise MailError("mail_unavailable")
        tag = f"T{next(self.tags)}"
        self.sock.settimeout(_left(self.deadline))
        self.sock.sendall(f"{tag} {command}\r\n".encode("ascii"))
        return tag.encode("ascii")

    def _fill(self) -> None:
        """More of the server's answer; never more than TOTAL_BYTES in all (then _Cut)."""
        if self.received >= TOTAL_BYTES:
            raise _Cut
        self.sock.settimeout(_left(self.deadline))
        chunk = self.sock.recv(min(65536, TOTAL_BYTES - self.received))
        if not chunk:
            raise MailError("mail_unavailable")
        self.received += len(chunk)
        self.buffer += chunk

    def _line(self, limit: int) -> tuple[bytes, bool]:
        """The next line without its CRLF, and whether it fit in `limit` bytes; one that does
        not is read to its end and only its last bytes are kept (enough to see a literal)."""
        dropped = False
        while True:
            end = self.buffer.find(b"\r\n")
            if end >= 0:
                line = bytes(self.buffer[:end])
                del self.buffer[: end + 2]
                if dropped or len(line) > limit:
                    return line[-16:], False
                return line, True
            if len(self.buffer) > max(limit, 16):
                del self.buffer[:-16]  # the line's start is dropped; its end may hold "{n}"
                dropped = True
            self._fill()

    def _literal(self, size: int, keep: bool) -> bytes:
        kept = bytearray()
        while size:
            if not self.buffer:
                self._fill()
            take = min(size, len(self.buffer))
            if keep:
                kept += self.buffer[:take]
            del self.buffer[:take]
            size -= take
        return bytes(kept)

    def response(self, limit: int) -> bytes | None:
        """One whole response (its lines and literals, CRLFs kept), or None when it is over
        `limit` bytes: then it is read to its end and dropped."""
        kept, whole = bytearray(), True
        while True:
            line, fits = self._line(limit - len(kept) if whole else 0)
            whole = whole and fits
            if whole:
                kept += line + b"\r\n"
            marker = LITERAL.search(line)
            if marker is None:
                return bytes(kept) if whole else None
            size = int(marker.group(1))
            whole = whole and len(kept) + size <= limit
            data = self._literal(size, whole)
            if whole:
                kept += data

    def until(self, tag: bytes, limit: int = LINE_BYTES) -> tuple[bytes, list[bytes]]:
        """The responses up to `tag`'s own: its status (OK, NO or BAD) and text, and the
        untagged ones before it. A response over `limit`, BYE or a continuation fails."""
        untagged: list[bytes] = []
        while True:
            data = self.response(limit)
            if data is None or data.startswith((b"+", b"* BYE")):
                raise MailError("mail_unavailable")
            if data.startswith(tag + b" "):
                return data[len(tag) + 1 : -2], untagged
            if not data.startswith(b"* "):
                raise MailError("mail_unavailable")
            untagged.append(data)

    def pipeline(self, commands: list[str], limit: int) -> tuple[bytes, bool, bool]:
        """Send `commands` at once (IMAP pipelining), then read their answers in order: the
        FETCH responses, each at most `limit` bytes; whether one was dropped or a command
        failed; and whether the reading stopped early, keeping what came whole."""
        pending = [self.send(command) for command in commands]
        answers, partial = bytearray(), False
        try:
            while pending:
                data = self.response(limit)
                if data is None:
                    partial = True  # one answer over its share: dropped, the rest still read
                elif FETCH.match(data):
                    answers += data
                elif (tag := data.split(b" ", 1)[0]) in pending:
                    pending.remove(tag)
                    partial = partial or not data.startswith(tag + b" OK")
                elif not data.startswith(b"* ") or data.startswith(b"* BYE"):
                    return bytes(answers), True, True  # a continuation, another tag, goodbye
        except (_Cut, MailError, OSError):
            # The total cap, the deadline or a broken connection: what came whole is kept.
            return bytes(answers), True, True
        return bytes(answers), partial, False

    def logout(self) -> None:
        """LOGOUT, waiting a second at most for its answer; any failure is ignored."""
        try:
            self.deadline = min(self.deadline, time.monotonic() + 1.0)
            tag = self.send("LOGOUT")
            while (data := self.response(LINE_BYTES)) is not None and not data.startswith(tag):
                pass
        except Exception:
            return


def _since(day: datetime) -> str:
    return f"{day.day}-{MONTHS[day.month - 1]}-{day.year}"


def conversation(session: Session, user: str, password: str, since: datetime):
    """Log in, open INBOX read only and fetch the newest messages since `since`'s day: the FETCH
    answers, the UIDs asked for, whether more matched, whether some were dropped or cut, and
    UIDVALIDITY."""
    greeting = session.response(LINE_BYTES)
    if greeting is None or not greeting.upper().startswith(b"* OK"):
        raise MailError("mail_unavailable")
    try:
        login = f"LOGIN {_quoted(user)} {_quoted(password)}"
    except ValueError:
        raise MailError("mail_login_refused") from None
    status, _ = session.until(session.send(login))
    if not status.upper().startswith(b"OK"):
        raise MailError("mail_login_refused")
    status, untagged = session.until(session.send('EXAMINE "INBOX"'))
    if not status.upper().startswith(b"OK [READ-ONLY]"):
        raise MailError("mail_unavailable")  # not confirmed read only: nothing is fetched
    validity = next((int(m.group(1)) for d in untagged if (m := VALIDITY.search(d))), None)
    status, untagged = session.until(
        session.send(f"UID SEARCH SINCE {_since(since)}"), SEARCH_BYTES
    )
    found: set[int] = set()
    for data in untagged:
        match = SEARCH.fullmatch(data.rstrip(b"\r\n"))
        if data.startswith(b"* SEARCH") and match is None:
            raise MailError("mail_unavailable")
        if match is not None:
            found.update(int(uid) for uid in match.group(1).split())
    if not status.upper().startswith(b"OK"):
        raise MailError("mail_unavailable")
    chosen = sorted(uid for uid in found if 0 < uid < 2**32)[-MAX_MESSAGES:]
    newest = chosen[::-1]
    # The sizes only order the structures: one missing or unread puts its message last.
    asked = [f"UID FETCH {','.join(map(str, newest))} {SIZE_ITEMS}"] if newest else []
    sized, _, stopped = session.pipeline(asked, LINE_BYTES)
    size = {int(m[0] or m[3]): int(m[1] or m[2]) for m in SIZED.findall(sized)}
    answers, partial = b"", False
    if not stopped:
        answers, partial, stopped = session.pipeline(
            [f"UID FETCH {uid} {CONTENT_ITEMS}" for uid in newest], MESSAGE_BYTES
        )
    if not stopped:
        # The structures apart, smallest message first (newest first among equals): one over its
        # share is dropped, and one too large for what is left of the total stops only the
        # structures of messages as large as its own.
        smallest = sorted(newest, key=lambda uid: (uid not in size, size.get(uid, 0)))
        structures, dropped, stopped = session.pipeline(
            [f"UID FETCH {uid} {STRUCTURE_ITEMS}" for uid in smallest], STRUCTURE_BYTES
        )
        answers, partial = answers + structures, partial or dropped
    if not stopped:
        session.logout()
    return answers, chosen, len(found) > len(chosen), partial or stopped, validity


def fetch(host: str, user: str, password: str, since: datetime):
    """`conversation` with the server at `host`, under every rule above. The clock starts once
    the TLS context is loaded, so it is the network's."""
    if HOST.fullmatch(host) is None:
        raise MailError("mail_address_refused")
    context = tls_context()
    deadline = time.monotonic() + SECONDS
    try:
        addresses = public_addresses(host, PORT, deadline)
    except DestinationDenied:
        raise MailError("mail_address_refused") from None
    except Exception:  # the lookup ran out of time
        raise MailError("mail_unavailable") from None
    sock = _connect(host, addresses, deadline, context)
    try:
        return conversation(Session(sock, deadline), user, password, since)
    except MailError:
        raise
    except Exception:
        # Socket and TLS errors can name the host; none of it leaves this function.
        raise MailError("mail_unavailable") from None
    finally:
        sock.close()


def parse(answers: bytes, uids: list[int]) -> tuple[list[dict], bool]:
    """Run the parser on the FETCH answer; its messages, checked, and whether some were not read."""
    try:
        done = child_guard.run(PARSER, [",".join(map(str, uids))], answers, PARSE_SECONDS)
    except subprocess.TimeoutExpired:
        raise MailError("mail_too_busy") from None
    except OSError:
        raise MailError("mail_unreadable") from None
    if done.returncode == BUSY:
        raise MailError("mail_too_busy")
    if done.returncode != 0:
        raise MailError("mail_unreadable")
    try:
        answer = json.loads(done.stdout)
        messages, partial = answer["messages"], answer["partial"]
        if not isinstance(messages, list) or type(partial) is not bool:
            raise ValueError("answer")
        checked = [_checked(message, set(uids)) for message in messages]
        if len({message["uid"] for message in checked}) != len(checked):
            raise ValueError("uid")
        return checked, partial
    except (ValueError, KeyError, TypeError):
        raise MailError("mail_unreadable") from None


def _clean(value: str, kind: str, label: str) -> str | None:
    text = " ".join(strip_invisible(value).split())[: CHARS[kind]]
    return fenced("MAIL", f"field={label}", text) if text else None


def _checked(message, uids: set[int]) -> dict:
    """One message from the child in the output's exact shape; anything else is refused."""
    keys = {"uid", "date", "from_name", "from_address", "subject", "snippet", "has_attachments"}
    if not isinstance(message, dict) or set(message) != keys:
        raise ValueError("message")
    uid, date, attached = message["uid"], message["date"], message["has_attachments"]
    if type(uid) is not int or uid not in uids or type(attached) is not bool:
        raise TypeError("uid")
    if not isinstance(date, str) or len(date) > 40:
        raise TypeError("date")
    received = datetime.fromisoformat(date)
    if received.utcoffset() != timedelta(0):
        raise ValueError("date")
    for key in ("from_name", "from_address", "subject", "snippet"):
        if not isinstance(message[key], str) or len(message[key]) > CHILD_CHARS:
            raise TypeError(key)
    return {
        "uid": uid,
        "date": received,
        "from": {
            "name": _clean(message["from_name"], "name", "from_name"),
            "address": _clean(message["from_address"], "address", "from_address"),
        },
        "subject": _clean(message["subject"], "subject", "subject"),
        "snippet": _clean(message["snippet"], "snippet", "snippet"),
        "has_attachments": attached,
    }


def read(hours: int = 24, now: datetime | None = None) -> dict[str, object]:
    """The INBOX messages received in the last `hours` hours (1 to MAX_HOURS), newest first, at
    most MAX_MESSAGES. "Not connected" when the account is not set; MailError for every failure."""
    if type(hours) is not int or not 1 <= hours <= MAX_HOURS:
        raise ValueError("hours")
    try:
        host, user, password = account()
    except KeyError:
        return {
            "connected": False,
            "messages": [],
            "source": "imap",
            "partial": False,
            "uid_validity": None,
            "note": WORDS["mail_not_connected"],
        }
    cutoff = (now or datetime.now(UTC)).astimezone(UTC) - timedelta(hours=hours)
    answers, uids, more, cut, validity = fetch(host, user, password, cutoff - timedelta(days=1))
    messages, partial = parse(answers, uids) if answers else ([], False)
    missing = set(uids) - {message["uid"] for message in messages}
    oldest = min(uids, default=None)
    # More matched than were asked for: some may be missing, unless the oldest asked for is
    # already outside the window (UIDs grow as mail arrives). A message that did not come back
    # (cut, broken, or removed meanwhile) leaves the answer partial too.
    reached = any(m["uid"] == oldest and m["date"] < cutoff for m in messages)
    recent = sorted(
        (message for message in messages if message["date"] >= cutoff),
        key=lambda message: (message["date"], message["uid"]),
        reverse=True,
    )
    return {
        "connected": True,
        "messages": [{**message, "date": message["date"].isoformat()} for message in recent],
        "source": "imap",
        "partial": partial or cut or bool(missing) or (more and not reached),
        "uid_validity": validity,
    }
