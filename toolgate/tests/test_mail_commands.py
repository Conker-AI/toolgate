"""The commands the mail reader may send (executors/mail_imap.py `read_only`, `_quoted`):
nothing that changes the mailbox, marks a message read, or carries a second command."""

from __future__ import annotations

import time

import pytest

from toolgate.executors import mail_imap


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
        'EXAMINE "INBOX"\x00',
        "UID SEARCH ALL\nT9 EXPUNGE",
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
        "nul",
        "smuggled-newline",
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
    fetches = [f"UID FETCH 1 {mail_imap.CONTENT_ITEMS}", f"UID FETCH 1 {mail_imap.STRUCTURE_ITEMS}"]
    for command in ('LOGIN "a" "b"', 'EXAMINE "INBOX"', "UID SEARCH SINCE 1-Nov-2026", *fetches):
        assert mail_imap.read_only(command)
    assert mail_imap.read_only("LOGOUT") and mail_imap.read_only("UID FETCH 1 (RFC822.SIZE)")


@pytest.mark.parametrize(
    "value",
    ["two\r\nT9 EXPUNGE", "nul\x00byte", "caf\u00e9", "line\n"],
    ids=["smuggled-line", "nul", "non-ascii", "newline"],
)
def test_imap_quoting_refuses_what_it_cannot_carry(value):
    with pytest.raises(ValueError):
        mail_imap._quoted(value)


def test_imap_quoting_escapes_backslash_and_quote():
    assert mail_imap._quoted("back\\slash") == '"back\\\\slash"'
    assert mail_imap._quoted('say "hi"') == '"say \\"hi\\""'
    assert mail_imap._quoted("plain words") == '"plain words"'
