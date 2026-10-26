"""The package proxy: the sandbox's only way to the internet, and only during an install.

A read-only pull-through to three fixed upstreams: PyPI's simple index (pypi.org), PyPI's files
(files.pythonhosted.org) and the npm registry (registry.npmjs.org). It answers GET and HEAD for
package metadata and archives under fixed path shapes and nothing else, so an install can
download from the official registries but cannot upload, publish, reach another host or tunnel.
It listens on a Unix socket that install containers mount read-only and admits only the sandbox
UID (SO_PEERCRED). Every request is logged as one JSON line. Usage:
`python -m toolgate.sandbox.proxy serve`.
"""

from __future__ import annotations

import contextlib
import http.client
import http.server
import json
import os
import re
import socket
import socketserver
import ssl
import struct
import sys
import time

PYPI = "pypi.org"
FILES = "files.pythonhosted.org"
NPM = "registry.npmjs.org"
UPSTREAMS = (PYPI, FILES, NPM)
DEFAULT_SOCKET = "/run/conker-proxy/proxy.sock"
CHUNK = 64 * 1024
METADATA_MAX = 64 * 1024 * 1024
ARCHIVE_MAX = 1024 * 1024 * 1024
# The only path shapes served; anything else is 404 and never leaves this process.
SIMPLE = re.compile(r"/pypi/simple/([a-z0-9][a-z0-9._-]{0,199})/")
PYPI_FILE = re.compile(r"/pypi/files/(packages/[A-Za-z0-9][A-Za-z0-9._/+-]{0,500})")
NPM_NAME = r"(?:@[a-z0-9][a-z0-9._~-]{0,213}(?:/|%2[fF]))?[a-z0-9][a-z0-9._~-]{0,213}"
NPM_META = re.compile(rf"/npm/({NPM_NAME})")
NPM_TARBALL = re.compile(rf"/npm/({NPM_NAME}/-/[A-Za-z0-9][A-Za-z0-9._~-]{{0,250}}\.tgz)")
LOCAL_HOST = re.compile(r"(?:127\.0\.0\.1|localhost):[0-9]{1,5}")
ACCEPT = re.compile(r"[A-Za-z0-9.+/*;=, -]{1,300}")
CONTENT_TYPE = re.compile(r"[A-Za-z0-9.+/;=, -]{1,200}")


def route(path: str) -> tuple[str, str, int, str] | None:
    """(upstream host, upstream path, size cap, kind) for an allowed path, else None."""
    if ".." in path or "//" in path or "?" in path or "#" in path:
        return None
    if match := SIMPLE.fullmatch(path):
        return PYPI, f"/simple/{match.group(1)}/", METADATA_MAX, "pypi-index"
    if match := PYPI_FILE.fullmatch(path):
        return FILES, "/" + match.group(1), ARCHIVE_MAX, "pypi-file"
    if match := NPM_TARBALL.fullmatch(path):
        return (
            NPM,
            "/" + match.group(1).replace("%2F", "/").replace("%2f", "/"),
            ARCHIVE_MAX,
            "npm-tarball",
        )
    if match := NPM_META.fullmatch(path):
        return NPM, "/" + match.group(1).replace("/", "%2f"), METADATA_MAX, "npm-metadata"
    return None


def rewrite(kind: str, body: bytes, host_header: str) -> bytes:
    """Point archive links back at this proxy, so the next request comes here too."""
    if kind == "pypi-index":
        return body.replace(f"https://{FILES}/packages/".encode(), b"/pypi/files/packages/")
    if kind == "npm-metadata" and LOCAL_HOST.fullmatch(host_header):
        return body.replace(f"https://{NPM}/".encode(), f"http://{host_header}/npm/".encode())
    return body


def location(value: str) -> str | None:
    """A redirect the proxy may pass on: only to an allowed path on the same upstreams."""
    for host, prefix in ((PYPI, "/pypi"), (FILES, "/pypi/files"), (NPM, "/npm")):
        start = f"https://{host}/"
        if value.startswith(start):
            candidate = prefix + "/" + value[len(start) :]
            return candidate if route(candidate) else None
    if value.startswith("/simple/"):
        candidate = "/pypi" + value
        return candidate if route(candidate) else None
    return None


def log(**fields) -> None:
    print(json.dumps({"t": round(time.time(), 3), **fields}), flush=True)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "conker-package-proxy"
    sys_version = ""

    def log_message(self, *args):
        pass

    def address_string(self):
        # A Unix socket peer has no address; the peer check already admitted the sandbox UID.
        return "sandbox"

    def _deny(self, status: int, reason: str) -> None:
        log(
            event="package_denied",
            method=self.command,
            path=self.path[:300],
            status=status,
            reason=reason,
        )
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._serve(head=False)

    def do_HEAD(self):
        self._serve(head=True)

    def _refuse_method(self):
        self._deny(405, "method")

    do_POST = do_PUT = do_PATCH = do_DELETE = do_CONNECT = do_OPTIONS = do_TRACE = _refuse_method

    def _serve(self, head: bool) -> None:
        target = route(self.path)
        if target is None:
            self._deny(404, "path")
            return
        host, upstream_path, cap, kind = target
        headers = {"User-Agent": "conker-package-proxy", "Accept-Encoding": "identity"}
        accept = self.headers.get("Accept", "")
        if accept and ACCEPT.fullmatch(accept):
            headers["Accept"] = accept
        started = time.monotonic()
        connection = http.client.HTTPSConnection(host, 443, timeout=30, context=self.server.tls)
        try:
            connection.request("HEAD" if head else "GET", upstream_path, headers=headers)
            response = connection.getresponse()
            status = response.status
            if status in (301, 302, 303, 307, 308):
                moved = location(response.getheader("Location", ""))
                if moved is None:
                    self._deny(502, "redirect")
                    return
                self.send_response(status)
                self.send_header("Location", moved)
                self.send_header("Content-Length", "0")
                self.end_headers()
                log(event="package_fetch", kind=kind, path=self.path[:300], status=status, bytes=0)
                return
            if status != 200:
                self._deny(404 if status in (404, 410) else 502, f"upstream_{status}")
                return
            content_type = response.getheader("Content-Type", "application/octet-stream")
            if not CONTENT_TYPE.fullmatch(content_type):
                content_type = "application/octet-stream"
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > cap):
                self._deny(502, "too_large")
                return
            sent = self._relay(response, kind, head, cap, content_type, length)
            log(
                event="package_fetch",
                kind=kind,
                path=self.path[:300],
                status=200,
                bytes=sent,
                ms=int((time.monotonic() - started) * 1000),
            )
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            with contextlib.suppress(OSError):
                self._deny(502, f"upstream_{type(exc).__name__}")
        finally:
            connection.close()

    def _relay(self, response, kind, head, cap, content_type, length) -> int:
        if kind in ("pypi-index", "npm-metadata"):
            body = response.read(cap + 1) if not head else b""
            if len(body) > cap:
                raise OSError("metadata too large")
            body = rewrite(kind, body, self.headers.get("Host", ""))
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if not head:
                self.wfile.write(body)
            return len(body)
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        if length is not None:
            self.send_header("Content-Length", length)
        self.end_headers()
        sent = 0
        while not head:
            chunk = response.read(CHUNK)
            if not chunk:
                break
            sent += len(chunk)
            if sent > cap:
                raise OSError("archive too large")
            self.wfile.write(chunk)
        return sent


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str, clients: set[int]):
        self.clients = clients
        self.tls = ssl.create_default_context()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        super().__init__(path, Handler)
        os.chmod(path, 0o666)

    def verify_request(self, request, client_address) -> bool:
        raw = request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        uid = struct.unpack("3i", raw)[1]
        if uid not in self.clients:
            log(event="package_denied", reason="peer", uid=uid)
            return False
        return True

    def server_bind(self):
        # UnixStreamServer has no address to report; BaseHTTPRequestHandler wants one.
        socketserver.UnixStreamServer.server_bind(self)
        self.server_name, self.server_port = "package-proxy", 0


def serve() -> int:
    raw = os.environ.get("PROXY_CLIENT_UIDS", "65533")
    try:
        clients = {int(part) for part in raw.split(",") if part.strip()}
    except ValueError:
        print("PROXY_CLIENT_UIDS must list numeric UIDs", file=sys.stderr)
        return 2
    path = os.environ.get("PROXY_SOCKET", DEFAULT_SOCKET)
    with Server(path, clients) as server:
        log(event="package_proxy_ready", upstreams=list(UPSTREAMS))
        server.serve_forever()
    return 0


def health() -> int:
    return 0 if os.path.exists(os.environ.get("PROXY_SOCKET", DEFAULT_SOCKET)) else 1


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "serve"
    sys.exit(health() if command == "health" else serve() if command == "serve" else 2)
