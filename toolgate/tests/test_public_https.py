import socket
import ssl
from datetime import UTC, datetime, timedelta

import httpcore
import httpx
import pytest
from fastapi import HTTPException

from toolgate.api import server
from toolgate.core import public_https
from toolgate.executors import research


def answers(*addresses):
    return [(socket.AF_INET6 if ":" in address else socket.AF_INET,
             socket.SOCK_STREAM, 6, "", (address, 443)) for address in addresses]


@pytest.mark.parametrize("address", [
    "100.64.0.1", "100.127.255.254", "100.100.100.200", "127.0.0.1", "10.0.0.1",
    "172.16.1.1", "192.168.1.1", "169.254.169.254", "168.63.129.16", "0.0.0.0",
    "224.0.0.1", "198.18.0.1", "::1", "::", "fe80::1", "fd7a:115c:a1e0::1",
    "ff02::1", "::ffff:100.64.0.1", "2002:6440:0001::1", "64:ff9b::6440:1",
    "64:ff9b:1::1", "fec0::1", "192.0.0.8", "192.88.99.1",
])
def test_private_answers_are_denied_everywhere(address, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answers(address))
    assert not research._public_https_url("https://public-looking.example/page")
    assert not server._public_destination("public-looking.example")
    assert research._normalize("title", "https://public-looking.example", "text", "web") is None
    with pytest.raises(HTTPException) as denied:
        server._execute_http_json({"url": "https://public-looking.example/page",
                                   "allowed_hosts": ["public-looking.example"]}, {})
    assert denied.value.detail["code"] == "DESTINATION_DENIED"


def test_mixed_and_empty_dns_fail_closed(monkeypatch):
    for resolved in (answers("93.184.216.34", "100.64.0.2"), []):
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, resolved=resolved, **k: resolved)
        assert not public_https.public_url("https://example.com")


class Wire(httpcore.NetworkStream):
    def __init__(self, response, writes, tls):
        self.response, self.writes, self.tls = response, writes, tls

    def read(self, max_bytes, timeout=None):
        data, self.response = self.response[:max_bytes], self.response[max_bytes:]
        return data

    def write(self, buffer, timeout=None):
        self.writes.append(buffer)

    def close(self):
        pass

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.tls.append(server_hostname)
        assert ssl_context.check_hostname
        assert ssl_context.verify_mode == ssl.CERT_REQUIRED
        return self

    def get_extra_info(self, info):
        return False if info == "is_readable" else None


def network(monkeypatch, responses):
    connections, writes, tls = [], [], []

    def connect(backend, host, port, **kwargs):
        connections.append((host, port))
        return Wire(responses.pop(0), writes, tls)

    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", connect)
    return connections, writes, tls


OK = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\npublic"


def handle(monkeypatch, url="https://example.com/page"):
    monkeypatch.setattr(research.control_plane, "get_research_result", lambda _: {
        "url": url, "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    })


def test_socket_is_pinned_and_hostname_tls_and_host_header_survive(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answers("93.184.216.34"))
    connections, writes, tls = network(monkeypatch, [OK])
    monkeypatch.setenv("HTTPS_PROXY", "http://100.64.0.99:8080")
    monkeypatch.setenv("ALL_PROXY", "http://100.64.0.99:8080")
    with public_https.public_client() as client:
        assert client.get("https://example.com/page").text == "public"
    assert connections == [("93.184.216.34", 443)]
    assert tls == ["example.com"]
    assert b"Host: example.com\r\n" in b"".join(writes)


def test_dns_rebinding_is_denied_before_socket_connect(monkeypatch):
    replies = [answers("93.184.216.34"), answers("100.64.0.1")]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: replies.pop(0))
    connections, _, _ = network(monkeypatch, [OK])
    handle(monkeypatch)
    with pytest.raises(research.ResearchError):
        research.fetch("issued-handle")
    assert connections == []


@pytest.mark.parametrize("location", [
    "https://tailnet.example/private", "https://100.64.0.5/private",
    "https://169.254.169.254/latest/meta-data/", "http://example.com/plaintext",
])
def test_redirect_chain_never_contacts_private_target(location, monkeypatch):
    def resolve(host, *a, **k):
        return answers("93.184.216.34" if host in {"example.com", "second.example"}
                       else "100.64.0.5")
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    responses = [(b"HTTP/1.1 302 Found\r\nLocation: https://second.example/page\r\n"
                  b"Content-Length: 0\r\n\r\n"),
                 f"HTTP/1.1 307 Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n".encode()]
    connections, _, _ = network(monkeypatch, responses)
    handle(monkeypatch)
    with pytest.raises(research.ResearchError, match="redirect"):
        research.fetch("issued-handle")
    assert connections == [("93.184.216.34", 443), ("93.184.216.34", 443)]


def test_public_fetch_still_returns_content(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answers("93.184.216.34"))
    network(monkeypatch, [OK])
    handle(monkeypatch)
    assert "public" in research.fetch("issued-handle")["content"]


def test_public_health_probe_cannot_rebind_into_tailnet(monkeypatch):
    replies = [answers("93.184.216.34"), answers("100.64.0.1")]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: replies.pop(0))
    monkeypatch.setattr(server.control_plane, "get", lambda *a: {
        "destination_policy": {"health_url": "https://example.com/health"},
    })
    monkeypatch.setattr(server.control_plane, "update_service", lambda sid, fields: fields)
    monkeypatch.setattr(server.control_plane, "event", lambda *a: None)
    connections, _, _ = network(monkeypatch, [OK])
    assert server.check_service("test-service")["health"] == "unhealthy"
    assert connections == []


def test_http_json_uses_pinned_transport_and_refuses_redirects(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answers("93.184.216.34"))
    connections, _, _ = network(monkeypatch, [
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 302 Found\r\nLocation: https://100.64.0.1/\r\nContent-Length: 0\r\n\r\n",
    ])
    execution = {"url": "https://example.com/page", "allowed_hosts": ["example.com"]}
    assert server._execute_http_json(execution, {}) == {"ok": True, "result": {}}
    with pytest.raises(HTTPException) as denied:
        server._execute_http_json(execution, {})
    assert denied.value.detail["code"] == "DESTINATION_DENIED"
    assert connections == [("93.184.216.34", 443), ("93.184.216.34", 443)]


@pytest.mark.parametrize("url", ["https://example.com:80/", "https://user:pass@example.com/",
                                 "http://example.com/", "https://[broken", "https://example.com:bad"])
def test_invalid_urls_never_connect(url, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answers("93.184.216.34"))
    assert not public_https.public_url(url)
    connections, _, _ = network(monkeypatch, [OK])
    with pytest.raises((httpx.HTTPError, httpx.InvalidURL)), public_https.public_client() as client:
        client.get(url)
    assert not connections
