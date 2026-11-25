"""Public-only HTTPS, including the address actually used by the socket.

Validating a hostname before an ordinary client resolves it again leaves a DNS
rebinding window. The backend validates every answer and connects to a numeric
address while HTTP Host and TLS certificate verification retain the hostname.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from typing import cast

import httpcore
import httpx


class DestinationDenied(httpx.ConnectError):
    pass


def public_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        # Transition and scoped addresses can encode another destination. They
        # are unnecessary for public research and differ across host routing setups.
        if ip.is_site_local or ip.scope_id or ip.ipv4_mapped or ip.sixtofour or ip.teredo:
            return False
        if any(
            ip in network
            for network in (
                ipaddress.ip_network("64:ff9b::/96"),
                ipaddress.ip_network("64:ff9b:1::/48"),
            )
        ):
            return False
    elif any(
        ip in network
        for network in (
            ipaddress.ip_network("192.0.0.0/24"),
            ipaddress.ip_network("192.88.99.0/24"),
        )
    ):
        return False
    return (
        ip.is_global
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_unspecified
        and str(ip) != "168.63.129.16"
    )  # Azure's host infrastructure endpoint.


def resolve_public(host: str, port: int = 443) -> list[str]:
    if port != 443 or not host or "%" in host:
        raise DestinationDenied("Destination must be public HTTPS on port 443")
    try:
        addresses = list(
            dict.fromkeys(
                cast(str, answer[4][0])
                for answer in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            )
        )
    except OSError as exc:
        raise DestinationDenied("Public destination could not be resolved") from exc
    if not addresses or not all(public_address(address) for address in addresses):
        raise DestinationDenied("Destination resolved outside the public HTTPS boundary")
    return addresses


def public_url(url: str) -> bool:
    try:
        parsed = httpx.URL(url)
        if parsed.scheme != "https" or not parsed.host or parsed.userinfo:
            return False
        resolve_public(parsed.host, parsed.port or 443)
        return True
    except (ValueError, httpx.InvalidURL, DestinationDenied):
        return False


class DeadlineStream(httpcore.NetworkStream):
    """A connection that stops at `deadline` (a `time.monotonic()` value): each read, write and
    TLS handshake gets at most the time left, so a server that sends slowly, even one byte at a
    time, cannot keep a request alive past it. httpx's own timeouts apply to each step only."""

    def __init__(self, stream: httpcore.NetworkStream, deadline: float) -> None:
        self.stream, self.deadline = stream, deadline

    def _left(self, timeout: float | None) -> float:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise httpcore.ReadTimeout("Public HTTPS deadline passed")
        return left if timeout is None else min(timeout, left)

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self.stream.read(max_bytes, self._left(timeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.stream.write(buffer, self._left(timeout))

    def close(self) -> None:
        self.stream.close()

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        tls = self.stream.start_tls(ssl_context, server_hostname, self._left(timeout))
        return DeadlineStream(tls, self.deadline)

    def get_extra_info(self, info: str):
        return self.stream.get_extra_info(info)


class PublicBackend(httpcore.NetworkBackend):
    def __init__(self, deadline: float | None = None) -> None:
        self.deadline = deadline

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        addresses = resolve_public(host, port)
        backend = httpcore.SyncBackend()
        for index, address in enumerate(addresses):
            try:
                if self.deadline is not None:
                    left = self.deadline - time.monotonic()
                    if left <= 0:
                        raise httpcore.ConnectTimeout("Public HTTPS deadline passed")
                    timeout = left if timeout is None else min(timeout, left)
                stream = backend.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
                return stream if self.deadline is None else DeadlineStream(stream, self.deadline)
            except (httpcore.ConnectError, httpcore.ConnectTimeout):
                if index == len(addresses) - 1:
                    raise


CORE_ERRORS = (
    httpcore.TimeoutException,
    httpcore.NetworkError,
    httpcore.ProtocolError,
    httpcore.ProxyError,
    httpcore.UnsupportedProtocol,
)


class ResponseStream(httpx.SyncByteStream):
    def __init__(self, response: httpcore.Response) -> None:
        self.response = response

    def __iter__(self):
        try:
            yield from self.response.iter_stream()
        except CORE_ERRORS as exc:
            raise httpx.TransportError("Public HTTPS response failed") from exc

    def close(self) -> None:
        self.response.close()


class PublicTransport(httpx.BaseTransport):
    """With `seconds`, nothing sent through it outlasts that many seconds from when it is made
    (`DeadlineStream`); the clock starts once the TLS context is loaded, so it is the network's."""

    def __init__(self, seconds: float | None = None) -> None:
        context = httpx.create_ssl_context(trust_env=False)
        deadline = None if seconds is None else time.monotonic() + seconds
        self.pool = httpcore.ConnectionPool(
            ssl_context=context,
            network_backend=PublicBackend(deadline),
            max_keepalive_connections=0,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if (
            request.url.scheme != "https"
            or request.url.port not in (None, 443)
            or request.url.userinfo
        ):
            raise DestinationDenied("Destination must be public HTTPS on port 443")
        try:
            response = self.pool.handle_request(
                httpcore.Request(
                    method=request.method,
                    url=httpcore.URL(
                        scheme=request.url.raw_scheme,
                        host=request.url.raw_host,
                        port=request.url.port,
                        target=request.url.raw_path,
                    ),
                    headers=request.headers.raw,
                    content=request.stream,
                    extensions=request.extensions,
                )
            )
        except CORE_ERRORS as exc:
            raise httpx.TransportError("Public HTTPS connection failed", request=request) from exc
        return httpx.Response(
            response.status,
            headers=response.headers,
            stream=ResponseStream(response),
            extensions=response.extensions,
        )

    def close(self) -> None:
        self.pool.close()


def public_client(**kwargs) -> httpx.Client:
    return httpx.Client(
        transport=PublicTransport(), trust_env=False, follow_redirects=False, **kwargs
    )
