"""Public-only HTTPS, including the address actually used by the socket.

Validating a hostname before an ordinary client resolves it again leaves a DNS
rebinding window. The backend validates every answer and connects to a numeric
address while HTTP Host and TLS certificate verification retain the hostname.
"""
from __future__ import annotations

import ipaddress
import socket
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
        if any(ip in network for network in (
            ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"),
        )):
            return False
    elif any(ip in network for network in (
        ipaddress.ip_network("192.0.0.0/24"), ipaddress.ip_network("192.88.99.0/24"),
    )):
        return False
    return (ip.is_global and not ip.is_multicast and not ip.is_reserved
            and not ip.is_loopback and not ip.is_link_local and not ip.is_unspecified
            and str(ip) != "168.63.129.16")  # Azure's host infrastructure endpoint.


def resolve_public(host: str, port: int = 443) -> list[str]:
    if port != 443 or not host or "%" in host:
        raise DestinationDenied("Destination must be public HTTPS on port 443")
    try:
        addresses = list(dict.fromkeys(
            cast(str, answer[4][0]) for answer in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ))
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


class PublicBackend(httpcore.NetworkBackend):
    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        addresses = resolve_public(host, port)
        backend = httpcore.SyncBackend()
        for index, address in enumerate(addresses):
            try:
                return backend.connect_tcp(address, port, timeout=timeout,
                                           local_address=local_address,
                                           socket_options=socket_options)
            except (httpcore.ConnectError, httpcore.ConnectTimeout):
                if index == len(addresses) - 1:
                    raise


CORE_ERRORS = (httpcore.TimeoutException, httpcore.NetworkError, httpcore.ProtocolError,
               httpcore.ProxyError, httpcore.UnsupportedProtocol)


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
    def __init__(self) -> None:
        self.pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(trust_env=False),
            network_backend=PublicBackend(), max_keepalive_connections=0,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if (request.url.scheme != "https" or request.url.port not in (None, 443)
                or request.url.userinfo):
            raise DestinationDenied("Destination must be public HTTPS on port 443")
        try:
            response = self.pool.handle_request(httpcore.Request(
                method=request.method,
                url=httpcore.URL(scheme=request.url.raw_scheme, host=request.url.raw_host,
                                 port=request.url.port, target=request.url.raw_path),
                headers=request.headers.raw, content=request.stream, extensions=request.extensions,
            ))
        except CORE_ERRORS as exc:
            raise httpx.TransportError("Public HTTPS connection failed", request=request) from exc
        return httpx.Response(response.status, headers=response.headers,
                              stream=ResponseStream(response), extensions=response.extensions)

    def close(self) -> None:
        self.pool.close()


def public_client(**kwargs) -> httpx.Client:
    return httpx.Client(transport=PublicTransport(), trust_env=False,
                        follow_redirects=False, **kwargs)
