# Mail (read only)

`mail.recent` reads the owner's newest INBOX messages from one IMAP account: who sent each one,
its subject, when it arrived, a short snippet and whether it has attachments. It never writes to
the mailbox: nothing is marked read, flagged, moved, copied or deleted, and it cannot send mail.
Like the other read-only built-ins it runs without an approval card, and it costs nothing.

## Connecting an account

The account is three vault secrets:

| Name | Value |
|---|---|
| `MAIL_IMAP_HOST` | The provider's IMAP server name, such as `imap.example.com` (a name, not an address, without a port or `imaps://`) |
| `MAIL_IMAP_USER` | The account's IMAP user name, usually the mail address |
| `MAIL_IMAP_PASSWORD` | An app password made for Conker in the provider's security settings, not the account's own password |

Store each with the admin key (`X-ToolGate-Key`), from files only you can read (so the values
stay out of shell history). Each file holds one secret, for example
`{"name": "MAIL_IMAP_PASSWORD", "value": "<the app password>"}`:

```bash
for part in host user password; do
  curl -X POST http://localhost:8010/vault/secrets \
    -H "X-ToolGate-Key: $TOOLGATE_ADMIN_KEY" -H "Content-Type: application/json" \
    --data @mail-$part.json || break
done
rm mail-host.json mail-user.json mail-password.json
```

Change one with `PUT /vault/secrets/<name>` (body `{"value": "..."}`) and remove it with
`DELETE /vault/secrets/<name>`. As with every vault value, ToolGate stores them encrypted and no
route returns them: `GET /vault/secrets` lists the names only. If the app password leaks, revoke
it at the provider and store a new one. A provider that offers no app passwords (sign-in through
OAuth only) cannot be connected yet.

The three names are read only by this tool (`vault.BUILTIN_SECRETS`). No other tool can name
them: an `http_json` secret header, an MCP server's `secret_ref` or a verification method that
names one is refused as not configured, so the account cannot be sent anywhere else.

## Who may read it

Startup registers `mail.recent` once if it is missing (category `safe`, authorization `auto`)
and never changes it afterwards, so the owner's edits stay. A caller needs a scope that covers
`tool:mail.recent`. The owner can grant it to the chat's own key with
`POST /v2/owner/tools/mail.recent/access` (`{"enabled": true, "expected_digest": ...}`), or make
the tool ask every time by marking it sensitive (`POST /v2/owner/tools/mail.recent/sensitive`)
or setting its authorization to `owner_confirmation`.

Limit: ToolGate's scope rules have no exact-grant-only kind yet, so a key that already holds `*`,
`tool:*` or a prefix such as `tool:mail*` covers `mail.recent` too, including after an upgrade
that adds the tool. Until that rule exists, give such wide scopes only to keys that may read the
owner's mail, or mark the tool sensitive so that every read asks the owner.

## Asking

```json
POST /v2/tools/mail.recent/invoke
{"action_id": "morning-2026-11-25", "args": {"hours": 24}}
```

- `hours`: 1 to 72, default 24: the messages that arrived in the last `hours` hours.

The answer is
`{"connected": true, "messages": [...], "source": "imap", "partial": false, "uid_validity": 3857529045}`,
newest first, at most 50 messages. Each message is
`{"uid", "date", "from": {"name", "address"}, "subject", "snippet", "has_attachments"}`:

- `uid`: the message's IMAP UID in the INBOX. With `uid_validity` it names the message stably;
  when the server changes `uid_validity`, earlier UIDs no longer apply.
- `date`: when the server received the message (its INTERNALDATE), in UTC. The `Date` field is
  the sender's own word and is not read.
- `from`: the display name and address of the first sender in the `From` field.
- `subject`: the subject, encoded words decoded.
- `snippet`: the start of the first plain-text part that is not an attachment (else of the
  first HTML part, as its visible text), whitespace collapsed.
- `has_attachments`: whether the message's structure lists an attachment, an attached message
  or a named file.

Text is cleaned of invisible characters and cut: names to 200 characters, addresses to 320,
subjects and snippets to 300. An empty field is `null`. `partial` is `true` when some messages
could not be read or were left out (see below); the rest are still there.

Every field is the sender's text, not the owner's words: anyone can send the owner mail, and the
`From` field is the sender's claim, not proof of who sent it. So each one comes fenced like web
and MCP text:

```text
[UNTRUSTED_MAIL_CONTENT field=subject]
Lunch tomorrow?
[/UNTRUSTED_MAIL_CONTENT]
```

A fence token inside the text is defused (`[/UNTRUSTED_` becomes `(/UNTRUSTED_`), so the text
cannot close its fence. A caller must treat what is inside as outside content.

Without all three secrets, or when the vault cannot open them, nothing is sent and the answer
says so (code `OK`, not an error):

```json
{"connected": false, "messages": [], "source": "imap", "partial": false, "uid_validity": null,
 "note": "No mail account is connected: store MAIL_IMAP_HOST, MAIL_IMAP_USER and MAIL_IMAP_PASSWORD (an app password) in ToolGate's vault."}
```

At most 6 reads a minute and 60 an hour. One read takes at most 27 seconds (the conversation's
12, then the parser's 15).

## What the journal keeps

The messages go only on the live reply. ToolGate's journal keeps a read without them, and
everything that reads the journal gets that form: replaying the same `action_id` (a fresh read
needs a new one), `GET /v2/agent/actions/<action_id>`, the owner's `GET /v2/actions`, owner and
editor run histories, recovery receipts. In the kept receipt every mail answer, wherever it sits
(the tool's `result.result`, an automation's `steps`, `variables` or `result`), is exactly:

```json
{"connected": true, "count": 2, "uids": [12, 11], "uid_validity": 3857529045,
 "partial": false, "note": "The messages were shown once and are not kept. Read mail again to see them.",
 "redacted": true}
```

- `redacted` is `true` only here, and a live answer never has it, so a caller can rely on it: no
  `messages` key, and the messages must be read again with a new `action_id`.
- `count` and `uids` are those of the messages the read returned, newest first.
- `connected`, `uid_validity` and `partial` are the read's own; `note` is the read's own note
  when it had one (the "not connected" sentence), else the sentence above.
- The tool's envelope also copies the answer's outputs next to `ok` and `result`; that level
  keeps `ok` and `result` and gets the same fields, with `uid_validity` `null` (it carried none).

A workflow is not affected: a later step reads the earlier step's live answer
(`$last.result.result.messages.0.subject`), never the kept one. What a later step does with a
message (its arguments, its own receipt) is that step's record, as the owner built the workflow.
Events (`/v2/events`) and logs carry no message. Receipts kept whole by an earlier build of this
branch are redacted once by schema step `0002-mail-receipts` (`core/execution_journal.py`
`redact_kept_mail`); a forgotten action is left to forgetting.

## How the mail is read

- IMAP over implicit TLS on port 993 only: no STARTTLS, no plaintext, no POP or SMTP. TLS 1.2 or
  newer, the certificate checked against the same public roots as public HTTPS and against the
  host's name, which is also sent as SNI.
- The host must be a DNS name (an address literal, `localhost`, a port or a scheme is refused
  before any lookup). It is looked up once, and every address it resolves to must be public
  (`core/public_https.py`): private, loopback, link-local, multicast, reserved, carrier-grade NAT
  and tailnet ranges are refused. The socket connects to those numbers, so the name is never
  looked up a second time.
- The conversation is `LOGIN`, `EXAMINE "INBOX"`, `UID SEARCH SINCE <the day before the window>`,
  then one `UID FETCH` of the sizes (`RFC822.SIZE`) of the newest 50 matches, then for each of
  them, newest first, one `UID FETCH` of its fields and text, then for each one, smallest message
  first, a `UID FETCH` of its structure, then `LOGOUT`. Each group of fetches is sent
  at once (IMAP pipelining) and the answers are joined by UID, never by message number, which an
  expunge between two commands would shift. `EXAMINE` opens the INBOX read only, and the server
  must confirm it (`[READ-ONLY]`) or nothing is fetched. The fetches ask only for `BODY.PEEK`
  sections (a peek leaves the `\Seen` flag alone): the `From`, `Subject`, `Content-Type` and
  `Content-Transfer-Encoding` fields and the first 8 KB of the text, plus the received time, and
  apart, the structure (`BODYSTRUCTURE`). The writer refuses, before a byte is sent, any command
  but these five, any line with a CR, LF or NUL in it, and any fetch item that would mark a
  message read (`BODY[...]`, `BINARY[...]`, `RFC822`, `RFC822.TEXT`). So no `SELECT`, `STORE`,
  `COPY`, `MOVE`, `EXPUNGE` or `APPEND` is ever sent.
- 12 seconds for the whole conversation, however slowly the server or the name server answers
  (the lookup, connect, handshake and every read and write get only the time left). At most 2 MB
  is read from the server. Each answer has its own share: 20 KB for a message's fields and text
  (the partial ranges keep an honest server under it), 16 KB for its structure (about 150
  parts). An answer over its share is read to its end, dropped, and the answer is `partial`:
  a message whose fields and text are over is left out; one whose structure is over is kept,
  without attachments. At the total cap or the deadline the reading stops with what came whole.
  Fields and text come first for all 50 (at most 1 MB). A structure is made of its message's
  parts, so a huge one comes from a large message, and the structures are read smallest message
  first: a stranger's message built that way costs at most the attachment flags of the messages
  as large as itself (a long video, say), and every message still comes back. IMAP tells no
  structure's size before sending it, so one over its share is read to its end, counted against
  the 2 MB, and dropped. The server's own words (its errors, greetings) and
  the errors of the lookup, the socket and TLS (which can name the host) never leave the reader:
  each becomes one fixed failure with nothing chained to it.
- "Newest" is the order in which messages arrived in the INBOX (their UIDs). When more than 50
  match, the answer is `partial` unless the oldest one read already falls before the window.

The answer is then read by `executors/mail_parse.py` in a child process that gets only the
server's bytes (no environment, no keys, never the account) and is stopped after 15 seconds
(`executors/child_guard.py`, shared with the calendar's parser). The child keeps its own clock
from the moment it starts: everything fits in 10 seconds, each message gets half a second, and
a message past its time is left out, so a slow or hostile message costs only itself. Its address
space is capped at 512 MB (Linux). What it reads:

- Encoded words (RFC 2047) in any charset Python knows; an unknown charset, or one that is no
  plain text encoding, is read as UTF-8, and undecodable bytes become U+FFFD.
- Base64 and quoted-printable text, including text the 8 KB fetch cut off (what came is read,
  and an escape cut in two is dropped).
- HTML as its visible text: tags and comments dropped, `script`, `style` and the head left
  out with all in them, character references read. It is read in one forward pass, so broken
  markup (thousands of unclosed tags) takes as long as any text of its length; a tag or comment
  left open at the end is dropped.
- A response nested deeper than 64 lists, a message without a received time, or one the mail
  parser cannot take is left out and the answer is `partial`. A structure that cannot be read
  (or lists more than 200 parts) keeps the message, without attachments, and makes the answer
  `partial`. The snippet is looked for in the first 200 parts only.

## Failures

Every failure is one fixed sentence that names nothing of the account:

| `code` | `error_code` | Meaning |
|---|---|---|
| `VALIDATION_ERROR` (422) | | `hours` is not a whole number from 1 to 72. Nothing was sent. |
| `TOOL_UNAVAILABLE` | `mail_address_refused` | `MAIL_IMAP_HOST` is not a DNS name, or it resolves to an address that is not public. Nothing was sent. |
| `TOOL_UNAVAILABLE` | `mail_certificate_refused` | The server's certificate is not signed by a public root or is not for `MAIL_IMAP_HOST`. |
| `TOOL_UNAVAILABLE` | `mail_login_refused` | The server did not accept the user name and app password (or IMAP cannot carry them: a line break, NUL or non-ASCII character). |
| `TOOL_UNAVAILABLE` | `mail_unavailable` | The server could not be reached over TLS 1.2+, did not confirm a read-only INBOX, answered something this reader does not follow, or was too slow. |
| `TOOL_UNAVAILABLE` | `mail_unreadable` | The parser could not read the answer. |
| `TOOL_UNAVAILABLE` | `mail_too_busy` | The answer could not be read in the parser's 10 seconds (or the child was stopped at 15). |

Tests: `toolgate/tests/test_mail_fetch.py` (a local IMAP server over real TLS with a test-only
certificate authority), `test_mail_commands.py`, `test_mail_parse.py`, `test_mail_receipts.py`
and `test_mail_boundary.py`, all on synthetic mail with no network. Mutants:
`toolgate/scripts/mutations_mail.py`.
