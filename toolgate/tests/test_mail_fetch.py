"""Reading mail over IMAP (executors/mail_imap.py) against a fake server on this machine over real
TLS: implicit TLS 1.2+ with a verified certificate for the host's name, public addresses only
from one lookup, a strictly read-only session (no write command, no \\Seen flag), a deadline and
byte caps however the server answers, and nothing of the account in any failure."""

from __future__ import annotations

import datetime as dt
import logging
import socket
import ssl
import time

import pytest

from toolgate.core import public_https
from toolgate.executors import mail_imap
from toolgate.tests import imap_fake
from toolgate.tests.imap_fake import APP_WORDS, HOST, USER, mail

NOW = dt.datetime(2026, 11, 25, 9, 0, tzinfo=dt.UTC)
VERBS = ["LOGIN", "EXAMINE", "UID SEARCH", "UID FETCH", "LOGOUT"]


def ago(hours: float) -> dt.datetime:
    return NOW - dt.timedelta(hours=hours)


def inbox() -> list[imap_fake.Message]:
    return [
        mail(10, ago(30), subject="Yesterday's news"),
        mail(11, ago(5), subject="Lunch", sender='"Ana Friend" <ana@example.org>'),
        mail(12, ago(1), subject="Bill", text="Your bill is attached.", attachment=b"%PDF-1"),
    ]


@pytest.fixture
def serve(monkeypatch, tmp_path):
    servers: list[imap_fake.Server] = []

    def start(messages=None, **options) -> imap_fake.Server:
        folder = tmp_path / f"run{len(servers)}"
        server = imap_fake.connect(
            monkeypatch, folder, inbox() if messages is None else messages, **options
        )
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def inner(text: str | None) -> str | None:
    return None if text is None else text.split("\n")[1]


def verbs(server) -> list[str]:
    found = []
    for command in server.commands:
        words = command.split(" ")[1:]
        found.append(" ".join(words[:2]) if words[0] == "UID" else words[0])
    return found


def network_only(monkeypatch) -> None:
    """The TLS context made now: what is timed after this is the network's part alone."""
    context = mail_imap.tls_context()
    monkeypatch.setattr(mail_imap, "tls_context", lambda: context)


def failed(code: str, caplog=None, hours: int = 24) -> mail_imap.MailError:
    with pytest.raises(mail_imap.MailError) as caught:
        mail_imap.read(hours, NOW)
    error = caught.value
    assert error.code == code and error.message == mail_imap.WORDS[code]
    told = str(error) + error.message + repr(error.__cause__) + (caplog.text if caplog else "")
    for secret in (HOST, USER, APP_WORDS):
        assert secret not in told
    return error


def test_the_newest_messages_of_the_window_are_read_over_verified_tls(serve):
    server = serve()
    answer = mail_imap.read(24, NOW)
    assert answer["connected"] is True and answer["source"] == "imap"
    assert answer["partial"] is False and answer["uid_validity"] == 3857529045
    first, second = answer["messages"]  # the 30-hour-old message is outside the window
    assert (first["uid"], second["uid"]) == (12, 11)
    assert first["date"] == "2026-11-25T08:00:00+00:00"
    assert inner(first["subject"]) == "Bill" and first["has_attachments"] is True
    assert inner(first["snippet"]) == "Your bill is attached."
    assert inner(second["from"]["name"]) == "Ana Friend"
    assert inner(second["from"]["address"]) == "ana@example.org"
    assert second["has_attachments"] is False
    for message in answer["messages"]:
        for text in (message["subject"], message["snippet"], *message["from"].values()):
            assert text.startswith("[UNTRUSTED_MAIL_CONTENT field=")
    # TLS to the address the one lookup gave, the host's name sent as SNI.
    assert server.lookups == [HOST] and server.server_names == [HOST]
    assert verbs(server) == VERBS


def test_the_session_is_read_only_and_changes_no_flag(serve):
    server = serve()
    mail_imap.read(72, NOW)
    assert server.writes == []
    assert verbs(server) == VERBS
    examine, fetch = server.commands[1], server.commands[3]
    assert examine.endswith('EXAMINE "INBOX"')
    assert fetch.count("BODY.PEEK[") == 2 and "BODY[" not in fetch.replace("BODY.PEEK[", "")
    assert all(not message.flags for message in server.messages)


@pytest.mark.parametrize(
    "command",
    [
        'SELECT "INBOX"',
        "UID STORE 12 +FLAGS (\\Seen)",
        "STORE 1 +FLAGS (\\Deleted)",
        "UID COPY 12 Trash",
        "UID MOVE 12 Trash",
        "EXPUNGE",
        "UID EXPUNGE 12",
        'APPEND "INBOX" {12}',
        "UID FETCH 12 (BODY[TEXT])",
        "UID FETCH 12 (body[])",
        "UID FETCH 12 (RFC822)",
        "UID FETCH 12 (RFC822.TEXT)",
        "UID FETCH 12 (BINARY[1])",
        'LOGIN "a" "b"\r\nT9 EXPUNGE',
        "LOGOUT EXPUNGE",
        "NOOP",
    ],
    ids=[
        "select",
        "uid-store",
        "store",
        "copy",
        "move",
        "expunge",
        "uid-expunge",
        "append",
        "body",
        "body-lowercase",
        "rfc822",
        "rfc822-text",
        "binary",
        "smuggled-line",
        "logout-and-more",
        "noop",
    ],
)
def test_no_command_that_writes_can_be_sent(command):
    assert mail_imap.read_only(command) is False

    class Recorder:
        sent = b""

        def settimeout(self, _seconds):
            pass

        def sendall(self, data):
            Recorder.sent += data

    session = mail_imap.Session(Recorder(), time.monotonic() + 5)
    with pytest.raises(mail_imap.MailError):
        session.send(command)
    assert Recorder.sent == b""


def test_the_commands_the_reader_sends_are_the_read_only_ones():
    fetch = f"UID FETCH 1,2 {mail_imap.FETCH_ITEMS}"
    for command in ('LOGIN "a" "b"', 'EXAMINE "INBOX"', "UID SEARCH SINCE 1-Nov-2026", fetch):
        assert mail_imap.read_only(command)
    assert mail_imap.read_only("LOGOUT") and mail_imap.read_only("UID FETCH 1 (RFC822.SIZE)")


def test_a_server_that_does_not_confirm_read_only_is_not_read(serve):
    server = serve(examine_code="[READ-WRITE]")
    failed("mail_unavailable")
    assert "UID FETCH" not in verbs(server) and server.writes == []


def test_a_wrong_app_password_is_refused_in_fixed_words(serve, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    server = serve()
    monkeypatch.setenv("MAIL_IMAP_PASSWORD", "not the app words")
    failed("mail_login_refused", caplog)
    assert verbs(server) == ["LOGIN"]


@pytest.mark.parametrize("password", ["two\r\nT9 EXPUNGE", "caf\u00e9", "tab\tthen\rreturn"])
def test_a_login_imap_cannot_carry_is_refused_before_it_is_sent(serve, monkeypatch, password):
    server = serve()
    monkeypatch.setenv("MAIL_IMAP_PASSWORD", password)
    failed("mail_login_refused")
    assert server.commands == []


@pytest.mark.parametrize("value", ["two\r\nT9 EXPUNGE", "nul\x00byte", "caf\u00e9", "line\n"])
def test_imap_quoting_refuses_what_it_cannot_carry(value):
    with pytest.raises(ValueError):
        mail_imap._quoted(value)
    assert mail_imap._quoted('back\\slash "quote"') == '"back\\\\slash \\"quote\\""'


def test_a_certificate_the_trusted_roots_did_not_sign_is_refused(serve, monkeypatch):
    server = serve()
    monkeypatch.setattr(mail_imap, "CA_FILE", None)  # certifi's roots only
    failed("mail_certificate_refused")
    assert server.commands == []


def test_a_certificate_for_another_name_is_refused(serve):
    server = serve(names=("other.example.test",))
    failed("mail_certificate_refused")
    assert server.commands == []


def test_a_plaintext_server_is_refused(serve):
    server = serve(tls=False)
    failed("mail_unavailable")
    assert not any("LOGIN" in command or APP_WORDS in command for command in server.commands)


def test_tls_older_than_1_2_is_refused(serve, monkeypatch):
    context = mail_imap.tls_context()
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    # Should a connection come up older anyway, its own version is checked before a word is sent.
    server = serve()
    monkeypatch.setattr(ssl.SSLSocket, "version", lambda _self: "TLSv1.1")
    failed("mail_unavailable")
    assert server.commands == []


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.2",
        "169.254.169.254",
        "100.64.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fd00::1",
        "ff02::1",
        "::ffff:10.0.0.1",
    ],
)
def test_a_host_that_resolves_inside_the_network_is_refused_before_any_connection(
    serve, monkeypatch, address
):
    server = serve()
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_k: [(family, socket.SOCK_STREAM, 6, "", (address, 993))],
    )
    failed("mail_address_refused")
    assert server.connections == 0


def test_one_private_answer_among_public_ones_refuses_the_host(serve, monkeypatch):
    server = serve()
    answers = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 993)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 993)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: answers)
    failed("mail_address_refused")
    assert server.connections == 0


@pytest.mark.parametrize(
    "host",
    [
        "10.0.0.1",
        "127.0.0.1",
        "[::1]",
        "::1",
        "localhost",
        "imap.example.test:143",
        "imaps://imap.example.test",
        "reader@imap.example.test",
        "imap.example.test/inbox",
        "imap.example.test.",
        "imap.ex\u00e4mple.test",
        "-imap.example.test",
        "imap example.test",
    ],
)
def test_a_host_that_is_no_public_dns_name_is_refused_before_any_lookup(serve, monkeypatch, host):
    server = serve()
    monkeypatch.setenv("MAIL_IMAP_HOST", host)
    failed("mail_address_refused")
    assert server.lookups == [] and server.connections == 0


def test_the_name_is_looked_up_once_and_the_socket_connects_to_that_address(serve, monkeypatch):
    # A second lookup (DNS rebinding) would get a private address and be refused; there is none.
    server = serve()
    first = socket.getaddrinfo

    def rebinding(host, port, *args, **kwargs):
        if server.lookups:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port))]
        return first(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", rebinding)
    assert len(mail_imap.read(24, NOW)["messages"]) == 2
    assert server.lookups == [HOST] and server.connections == 1


def test_a_slow_name_lookup_stops_at_the_deadline(serve, monkeypatch):
    serve()
    network_only(monkeypatch)
    monkeypatch.setattr(mail_imap, "SECONDS", 0.5)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: time.sleep(4) or [])
    started = time.monotonic()
    failed("mail_unavailable")
    assert time.monotonic() - started < 2.5


def test_a_server_that_sends_one_byte_at_a_time_stops_at_the_deadline(serve, monkeypatch):
    server = serve(pace=0.2)  # the greeting alone would take seconds
    network_only(monkeypatch)
    monkeypatch.setattr(mail_imap, "SECONDS", 1.0)
    started = time.monotonic()
    failed("mail_unavailable")
    assert time.monotonic() - started < 3.0
    server.close()


def test_a_fetch_the_deadline_cuts_answers_partial_with_what_came(serve, monkeypatch):
    serve(stall={"UID FETCH": 3.0})
    network_only(monkeypatch)
    monkeypatch.setattr(mail_imap, "SECONDS", 1.5)
    started = time.monotonic()
    answer = mail_imap.read(24, NOW)
    assert answer["connected"] and answer["partial"] is True and answer["messages"] == []
    assert time.monotonic() - started < 3.5


def oversized(uid: int, received: dt.datetime) -> imap_fake.Message:
    message = mail(uid, received, subject="Huge")
    message.structure = (
        '("TEXT" "PLAIN" ("NAME" "' + "x" * 70000 + '") NIL NIL "7BIT" 1 1 NIL NIL NIL NIL)'
    )
    return message


def test_a_message_over_its_cap_is_dropped_and_the_rest_are_read(serve):
    serve(
        [
            mail(20, ago(3), subject="Before"),
            oversized(21, ago(2)),
            mail(22, ago(1), subject="After"),
        ]
    )
    answer = mail_imap.read(24, NOW)
    assert [inner(m["subject"]) for m in answer["messages"]] == ["After", "Before"]
    assert answer["partial"] is True


class Wire:
    """A socket that answers with `data`, in pieces of at most `piece` bytes."""

    def __init__(self, data: bytes, piece: int = 4096) -> None:
        self.data, self.piece, self.sent = bytearray(data), piece, b""

    def settimeout(self, _seconds) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, size: int) -> bytes:
        chunk = bytes(self.data[: min(size, self.piece)])
        del self.data[: len(chunk)]
        return chunk


def test_the_fetch_itself_says_partial_when_it_drops_a_message(monkeypatch):
    # The parent and the child would both notice the missing UID too; this is the fetch's own say.
    monkeypatch.setattr(mail_imap, "MESSAGE_BYTES", 2000)
    small = b"* %d FETCH (UID %d BODY[TEXT]<0> {5}\r\nhello)\r\n"
    big = b"* 2 FETCH (UID 2 BODY[TEXT]<0> {5000}\r\n" + b"x" * 5000 + b")\r\n"
    wire = Wire(small % (1, 1) + big + small % (3, 3) + b"T1 OK done\r\n")
    answers, partial = mail_imap.Session(wire, time.monotonic() + 5).messages([1, 2, 3])
    assert partial is True
    assert answers == small % (1, 1) + small % (3, 3)
    assert wire.sent.startswith(b"T1 UID FETCH 1,2,3 (UID INTERNALDATE BODYSTRUCTURE BODY.PEEK[")


def test_the_total_cap_stops_reading_with_what_came_whole(serve, monkeypatch):
    serve([mail(30 + i, ago(10 - i), subject=f"Note {i}", text="y" * 1500) for i in range(8)])
    monkeypatch.setattr(mail_imap, "TOTAL_BYTES", 6000)
    answer = mail_imap.read(24, NOW)
    assert answer["partial"] is True
    assert 0 < len(answer["messages"]) < 8


def test_a_literal_announcing_more_than_the_caps_is_not_kept(serve, monkeypatch):
    def fetch(tag):
        return b"* 1 FETCH (UID 12 BODY[TEXT]<0> {4000000000}\r\n" + b"z" * 300000

    serve(hooks={"UID FETCH": fetch})
    monkeypatch.setattr(mail_imap, "SECONDS", 3.0)
    answer = mail_imap.read(24, NOW)
    assert answer["partial"] is True and answer["messages"] == []


def test_a_search_answer_over_its_cap_fails(serve):
    serve(
        hooks={
            "UID SEARCH": lambda tag: b"* SEARCH" + b" 1" * 300000 + f"\r\n{tag} OK\r\n".encode()
        }
    )
    failed("mail_unavailable")


def test_more_matches_than_the_cap_give_the_newest_and_say_partial(serve):
    many = [mail(100 + i, ago(20 - i * 0.3), subject=f"n{i}") for i in range(60)]
    server = serve(many)
    answer = mail_imap.read(24, NOW)
    assert len(answer["messages"]) == mail_imap.MAX_MESSAGES == 50
    assert [m["uid"] for m in answer["messages"]] == list(range(159, 109, -1))
    assert answer["partial"] is True
    assert server.commands[3].split(" ")[3] == ",".join(str(uid) for uid in range(110, 160))


def test_more_matches_reaching_past_the_window_are_not_partial(serve):
    # The SEARCH works in whole days: the oldest message asked for is already out of the window.
    many = [mail(200 + i, ago(59.5 - i), subject=f"n{i}") for i in range(60)]
    serve(many)
    answer = mail_imap.read(24, NOW)
    assert answer["partial"] is False
    assert len(answer["messages"]) == 24


@pytest.mark.parametrize("missing", ["MAIL_IMAP_HOST", "MAIL_IMAP_USER", "MAIL_IMAP_PASSWORD"])
def test_without_the_whole_account_nothing_is_sent_and_it_says_not_connected(
    serve, monkeypatch, missing
):
    server = serve()
    monkeypatch.delenv(missing)
    answer = mail_imap.read(24, NOW)
    assert answer == {
        "connected": False,
        "messages": [],
        "source": "imap",
        "partial": False,
        "uid_validity": None,
        "note": mail_imap.WORDS["mail_not_connected"],
    }
    monkeypatch.setenv(missing, "   ")  # blank is not set
    assert mail_imap.read(24, NOW)["connected"] is False
    assert server.lookups == [] and server.connections == 0


def test_a_vault_that_cannot_open_the_account_sends_nothing(serve, monkeypatch):
    server = serve()

    def sealed(name):
        raise mail_imap.vault.VaultError(f"{name} is encrypted with a different vault key")

    monkeypatch.setattr(mail_imap.vault, "builtin_secret", sealed)
    assert mail_imap.read(24, NOW)["connected"] is False
    assert server.connections == 0


@pytest.mark.parametrize("hours", [0, 73, -1, True, "24"])
def test_hours_outside_1_to_72_are_refused(hours):
    with pytest.raises(ValueError):
        mail_imap.read(hours, NOW)


def test_the_window_is_measured_in_hours_and_searched_from_the_day_before(serve):
    server = serve([mail(1, ago(71), subject="Old"), mail(2, ago(73), subject="Older")])
    answer = mail_imap.read(72, NOW)
    assert [inner(m["subject"]) for m in answer["messages"]] == ["Old"]
    assert server.commands[2].endswith("UID SEARCH SINCE 21-Nov-2026")


def test_the_lookup_is_the_public_one_with_the_deadline(monkeypatch):
    seen = []

    def addresses(host, port, deadline=None):
        seen.append((host, port, deadline is not None))
        raise public_https.DestinationDenied("no")

    monkeypatch.setattr(mail_imap, "public_addresses", addresses)
    with pytest.raises(mail_imap.MailError):
        mail_imap.fetch(HOST, USER, APP_WORDS, NOW)
    assert seen == [(HOST, 993, True)]
