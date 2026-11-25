"""A fake IMAP4 server over implicit TLS for the mail tests, with a certificate authority made for
the test run (trusted only by the tests, through `mail_imap.CA_FILE`), and messages to serve.

The server records every command line it receives (`commands`) and every command that would
change the mailbox (`writes`), and keeps each message's flags: a fetch of a body section that is
not BODY.PEEK marks the message \\Seen, as a real server does. `hooks` let a test replace the
answer to one command (a function of the tag that returns the bytes to send), `pace` sends the
answers one byte at a time with that many seconds between them, and `stall` waits before
answering.
"""

from __future__ import annotations

import datetime as dt
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from email import message_from_bytes
from email.message import EmailMessage
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HOST = "imap.example.test"
USER = "reader@example.test"
APP_WORDS = "made-up app words"  # the fake account's app password
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
LF = bytes([10])
WRITES = {"STORE", "COPY", "MOVE", "EXPUNGE", "APPEND", "SELECT", "DELETE", "CREATE", "RENAME"}


def _name(text: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])


def authority(folder: Path, names: tuple[str, ...] = (HOST,)) -> tuple[Path, Path, Path]:
    """A test CA and a server certificate it signed for `names`: (ca.pem, cert.pem, key.pem)."""
    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name("Mail test authority"))
        .issuer_name(_name("Mail test authority"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name(names[0]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    folder.mkdir(parents=True, exist_ok=True)
    paths = folder / "ca.pem", folder / "cert.pem", folder / "key.pem"
    paths[0].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    paths[1].write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    paths[2].write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return paths


@dataclass
class Message:
    uid: int
    received: dt.datetime
    raw: bytes
    structure: str | None = None  # BODYSTRUCTURE as sent; made from `raw` when None
    flags: set[str] = field(default_factory=set)


def mail(
    uid: int,
    received: dt.datetime,
    subject: str = "Hello",
    sender: str = "Ana Friend <ana@example.org>",
    text: str | None = "See you at noon.",
    html: str | None = None,
    attachment: bytes | None = None,
) -> Message:
    """A message as a mail program writes it."""
    message = EmailMessage()
    message["From"] = sender
    message["To"] = USER
    message["Subject"] = subject
    if text is not None:
        message.set_content(text)
    if html is not None:
        if text is None:
            message.set_content(html, subtype="html")
        else:
            message.add_alternative(html, subtype="html")
    if attachment is not None:
        message.add_attachment(
            attachment, maintype="application", subtype="pdf", filename="bill.pdf"
        )
    return Message(uid, received, message.as_bytes().replace(b"\n", b"\r\n"))


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _params(pairs) -> str:
    if not pairs:
        return "NIL"
    return "(" + " ".join(f"{_quote(k.upper())} {_quote(v)}" for k, v in pairs) + ")"


def structure(part) -> str:
    """BODYSTRUCTURE of a parsed message, as RFC 3501 writes it."""
    if part.get_content_maintype() == "multipart":
        inner = "".join(structure(sub) for sub in part.get_payload())
        boundary = _params([("boundary", part.get_boundary() or "")])
        return f"({inner} {_quote(part.get_content_subtype().upper())} {boundary} NIL NIL NIL)"
    kind, subtype = part.get_content_maintype().upper(), part.get_content_subtype().upper()
    payload = part.get_payload(decode=False)
    body = payload.encode("utf-8", "surrogateescape") if isinstance(payload, str) else b""
    params = _params(part.get_params()[1:] if part.get_params() else [])
    encoding = str(part.get("content-transfer-encoding", "7bit")).upper()
    fields = f"{_quote(kind)} {_quote(subtype)} {params} NIL NIL {_quote(encoding)} {len(body)}"
    if kind == "TEXT":
        fields += f" {body.count(LF)}"
    how, name = part.get_content_disposition(), part.get_filename()
    disposition = "NIL"
    if how:
        disposition = f"({_quote(how.upper())} {_params([('filename', name)] if name else [])})"
    return f"({fields} NIL {disposition} NIL NIL)"


def _section(raw: bytes, spec: str) -> bytes:
    head, _, body = raw.partition(b"\r\n\r\n")
    if spec == "TEXT":
        return body
    wanted = set(re.findall(r"[A-Z0-9-]+", spec.split("(", 1)[1].upper()))
    lines, keep = [], False
    for line in head.split(b"\r\n"):
        if line[:1] not in (b" ", b"\t"):
            keep = line.split(b":", 1)[0].strip().upper().decode("latin-1") in wanted
        if keep:
            lines.append(line)
    return b"".join(line + b"\r\n" for line in lines) + b"\r\n"


def connect(monkeypatch, folder: Path, messages: list[Message], account=True, **options):
    """A fake server with the mail reader pointed at it: its port, the test authority as one more
    root, HOST resolving to 127.0.0.1 (taken as public by these tests only; every lookup is
    recorded in `server.lookups`), the vault in `folder` and the account set when `account`."""
    from toolgate.core import public_https, vault
    from toolgate.executors import mail_imap

    server = Server(folder / "server", messages, **options)
    monkeypatch.setattr(mail_imap, "CA_FILE", str(server.ca))
    monkeypatch.setattr(mail_imap, "PORT", server.port)

    def answer(host, port, *_args, **_kwargs):
        server.lookups.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", answer)
    public = public_https.public_address
    monkeypatch.setattr(public_https, "public_address", lambda a: a == "127.0.0.1" or public(a))
    monkeypatch.setattr(vault, "ENV_PATH", folder / "vault.env")
    monkeypatch.setenv("TOOLGATE_VAULT_KEY_FILE", str(folder / "vault.key"))
    for name, value in zip(mail_imap.SECRETS, (HOST, USER, APP_WORDS), strict=True):
        if account:
            monkeypatch.setenv(name, value)
        else:
            monkeypatch.delenv(name, raising=False)
    return server


class Server:
    """The fake server. `tls=False` serves plaintext; `names` are the certificate's names."""

    def __init__(self, folder: Path, messages: list[Message], tls: bool = True, **options):
        self.messages = messages
        self.commands: list[str] = []
        self.writes: list[str] = []
        self.lookups: list[str] = []
        self.server_names: list[str | None] = []
        self.hooks: dict[str, object] = options.pop("hooks", {})
        self.pace: float = options.pop("pace", 0.0)
        self.stall: dict[str, float] = options.pop("stall", {})
        self.examine_code: str = options.pop("examine_code", "[READ-ONLY]")
        self.greeting: bytes = options.pop("greeting", b"* OK [CAPABILITY IMAP4rev1] ready\r\n")
        self.ca, cert, key = authority(folder, options.pop("names", (HOST,)))
        self.context = None
        if tls:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(cert, key)
            if "maximum_version" in options:
                self.context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
                self.context.maximum_version = options.pop("maximum_version")
            self.context.sni_callback = self._sni
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.connections = 0
        self.stopped = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def _sni(self, _socket, name, _context) -> None:
        self.server_names.append(name)

    def close(self) -> None:
        self.stopped.set()
        self.listener.close()

    def _accept(self) -> None:
        while not self.stopped.is_set():
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _send(self, conn, data: bytes) -> None:
        if not self.pace:
            conn.sendall(data)
            return
        for index in range(len(data)):
            if self.stopped.is_set():
                return
            conn.sendall(data[index : index + 1])
            time.sleep(self.pace)

    def _serve(self, conn) -> None:
        try:
            if self.context is not None:
                conn = self.context.wrap_socket(conn, server_side=True)
            reader = conn.makefile("rb")
            self._send(conn, self.greeting)
            while not self.stopped.is_set():
                line = reader.readline(100000)
                if not line:
                    return
                command = line.rstrip(b"\r\n").decode("latin-1")
                self.commands.append(command)
                tag, _, rest = command.partition(" ")
                words = rest.split(" ")
                verb = words[0].upper()
                if verb == "UID" and len(words) > 1:
                    verb = f"UID {words[1].upper()}"
                if verb.split(" ")[-1] in WRITES:
                    self.writes.append(command)
                time.sleep(self.stall.get(verb, 0.0))
                hook = self.hooks.get(verb)
                answer = hook(tag) if callable(hook) else self._answer(tag, verb, rest)
                self._send(conn, answer)
                if verb == "LOGOUT":
                    return
        except (OSError, ssl.SSLError):
            return
        finally:
            conn.close()

    def _answer(self, tag: str, verb: str, rest: str) -> bytes:
        if verb == "LOGIN":
            ok = rest == f"LOGIN {_quote(USER)} {_quote(APP_WORDS)}"
            return f"{tag} {'OK' if ok else 'NO [AUTHENTICATIONFAILED] Invalid'} login\r\n".encode()
        if verb in ("EXAMINE", "SELECT"):
            code = "[READ-WRITE]" if verb == "SELECT" else self.examine_code
            count = len(self.messages)
            return (
                f"* {count} EXISTS\r\n* OK [UIDVALIDITY 3857529045] UIDs valid\r\n"
                f"{tag} OK {code} done\r\n"
            ).encode()
        if verb == "UID SEARCH":
            day, month, year = rest.split(" ")[-1].split("-")
            since = dt.date(int(year), MONTHS.index(month) + 1, int(day))
            found = "".join(f" {m.uid}" for m in self.messages if m.received.date() >= since)
            return f"* SEARCH{found}\r\n{tag} OK done\r\n".encode()
        if verb == "UID FETCH":
            return self._fetch(tag, rest) + f"{tag} OK done\r\n".encode()
        if verb == "LOGOUT":
            return f"* BYE bye\r\n{tag} OK done\r\n".encode()
        return f"{tag} OK done\r\n".encode()

    def _fetch(self, tag: str, rest: str) -> bytes:
        _, _, uid_set, items = rest.split(" ", 3)
        return fetch_answer(self.messages, {int(uid) for uid in uid_set.split(",")}, items)


def fetch_answer(messages: list[Message], wanted: set[int], items: str = "") -> bytes:
    """The FETCH responses a server sends for `wanted` (UIDs) and `items` (the client's list;
    the reader's own by default), each body section a literal. A section fetched without PEEK
    marks its message \\Seen."""
    if not items:
        from toolgate.executors import mail_imap

        items = mail_imap.FETCH_ITEMS
    sections = re.findall(r"BODY(\.PEEK)?\[([^\]]*)\](?:<0\.(\d+)>)?", items)
    out = bytearray()
    for number, message in enumerate(messages, 1):
        if message.uid not in wanted:
            continue
        parts = [f"UID {message.uid}"]
        if "INTERNALDATE" in items:
            when = message.received
            stamp = f"{when.day:02d}-{MONTHS[when.month - 1]}-{when:%Y %H:%M:%S %z}"
            parts.append(f'INTERNALDATE "{stamp}"')
        if "BODYSTRUCTURE" in items:
            made = message.structure or structure(message_from_bytes(message.raw))
            parts.append(f"BODYSTRUCTURE {made}")
        chunks = [" ".join(parts).encode()]
        for peek, spec, size in sections:
            data = _section(message.raw, spec)
            if size:
                data = data[: int(size)]
            if not peek:
                message.flags.add("\\Seen")
            chunks.append(f" BODY[{spec}]<0> {{{len(data)}}}\r\n".encode() + data)
        out += f"* {number} FETCH (".encode() + b"".join(chunks) + b")\r\n"
    return bytes(out)
