"""Fetching the calendar (executors/calendar_ics.py): public https only, every redirect checked
again, 2 MB and 5 seconds at most, never compressed. No network: DNS answers and the server are
fakes; one test drives the real public-only transport."""

from __future__ import annotations

import socket

import httpx
import pytest

from toolgate.executors import calendar_ics
from toolgate.tests.calendar_fixtures import ADDRESS, WEEK

PUBLIC = "93.184.216.34"


def answers(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return [(family, socket.SOCK_STREAM, 6, "", (address, 443))]


@pytest.fixture
def dns(monkeypatch):
    """Host name -> address the fake DNS answers; anything not listed is public."""
    table: dict[str, str] = {}
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, *_a, **_k: answers(table.get(host, PUBLIC)),
    )
    return table


class Server:
    """A fake calendar server: `routes` maps a URL to a response; `seen` lists what was asked."""

    def __init__(self, routes):
        self.routes = routes
        self.seen: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(str(request.url))
        made = self.routes.get(str(request.url))
        return made() if callable(made) else made or httpx.Response(404)

    @property
    def transport(self):
        return httpx.MockTransport(self)


def ok(body=WEEK, **headers):
    """A 200 whose body is streamed, as from a real server (not read before ToolGate reads it)."""
    return lambda: httpx.Response(
        200, content=iter([body]), headers={"content-type": "text/calendar", **headers}
    )


def moved(location):
    return httpx.Response(302, headers={"location": location})


def refused(url, server, code):
    with pytest.raises(calendar_ics.CalendarError) as caught:
        calendar_ics.fetch(url, server.transport)
    assert caught.value.code == code
    assert caught.value.message == calendar_ics.WORDS[code]
    assert "example" not in str(caught.value) + caught.value.message
    return caught.value


def test_a_public_https_address_is_read(dns):
    server = Server({ADDRESS: ok()})
    assert calendar_ics.fetch(ADDRESS, server.transport) == WEEK
    request_headers = {}

    def capture(request):
        request_headers.update(request.headers)
        return ok()()

    calendar_ics.fetch(ADDRESS, httpx.MockTransport(capture))
    assert request_headers["accept-encoding"] == "identity"
    assert "authorization" not in request_headers and "cookie" not in request_headers


def test_webcal_is_read_as_https(dns):
    server = Server({ADDRESS: ok()})
    assert calendar_ics.fetch(ADDRESS.replace("https://", "webcal://"), server.transport) == WEEK
    assert server.seen == [ADDRESS]


@pytest.mark.parametrize(
    "url",
    [
        ADDRESS.replace("https://", "http://"),
        ADDRESS.replace("https://", "ftp://"),
        ADDRESS.replace("https://", "https://owner:pass@"),
        ADDRESS.replace("calendar.example.com", "calendar.example.com:8443"),
        "calendar.example.com/basic.ics",
        "https://",
        "https://exa mple.com/x.ics",
    ],
    ids=["http", "ftp", "user-and-password", "other-port", "no-scheme", "no-host", "space"],
)
def test_anything_but_public_https_is_refused_before_any_request(dns, url):
    server = Server({})
    refused(url, server, "calendar_address_refused")
    assert server.seen == []


@pytest.mark.parametrize(
    "address",
    ["10.0.0.5", "127.0.0.1", "169.254.169.254", "100.100.1.1", "fd7a:115c:a1e0::1", "::1"],
    ids=["private", "loopback", "link-local", "tailnet", "tailnet-v6", "loopback-v6"],
)
def test_a_host_that_resolves_inside_the_network_is_refused_before_any_request(dns, address):
    dns["calendar.example.com"] = address
    server = Server({ADDRESS: ok()})
    refused(ADDRESS, server, "calendar_address_refused")
    assert server.seen == []


@pytest.mark.parametrize(
    "target",
    [
        "https://internal.example/feed.ics",
        "http://calendar.example.com/feed.ics",
        "https://calendar.example.com:8443/feed.ics",
    ],
    ids=["private-host", "http", "other-port"],
)
def test_a_redirect_is_checked_like_the_address_itself(dns, target):
    dns["internal.example"] = "10.0.0.7"
    server = Server({ADDRESS: moved(target), target: ok()})
    refused(ADDRESS, server, "calendar_address_refused")
    assert server.seen == [ADDRESS]


def test_a_redirect_to_another_public_https_address_is_followed(dns):
    elsewhere = "https://calendars.example.net/published/feed.ics"
    server = Server(
        {
            ADDRESS: moved("/ical/moved.ics"),
            "https://calendar.example.com/ical/moved.ics": moved(elsewhere),
            elsewhere: ok(),
        }
    )
    assert calendar_ics.fetch(ADDRESS, server.transport) == WEEK
    assert server.seen == [ADDRESS, "https://calendar.example.com/ical/moved.ics", elsewhere]


def test_redirects_stop_after_three(dns):
    hops = [f"https://calendar.example.com/hop{index}.ics" for index in range(5)]
    server = Server(
        {ADDRESS: moved(hops[0]), **{hop: moved(hops[i + 1]) for i, hop in enumerate(hops[:-1])}}
    )
    refused(ADDRESS, server, "calendar_unavailable")
    assert len(server.seen) == calendar_ics.REDIRECTS + 1


@pytest.mark.parametrize("status", [401, 403, 404, 500, 304])
def test_an_answer_other_than_200_is_unavailable(dns, status):
    refused(ADDRESS, Server({ADDRESS: httpx.Response(status)}), "calendar_unavailable")


def test_a_compressed_answer_is_refused(dns):
    server = Server({ADDRESS: ok(**{"content-encoding": "gzip"})})
    refused(ADDRESS, server, "calendar_unavailable")


def test_a_declared_size_over_2_mb_is_refused_before_reading(dns):
    read = []

    def body():
        read.append(1)
        yield WEEK

    size = str(calendar_ics.LIMIT_BYTES + 1)
    answer = lambda: httpx.Response(200, content=body(), headers={"content-length": size})  # noqa: E731
    refused(ADDRESS, Server({ADDRESS: answer}), "calendar_too_large")
    assert read == []


def test_a_body_over_2_mb_without_a_length_stops_reading_at_the_cap(dns):
    sent = []

    def chunks():
        for _ in range(64):
            sent.append(1)
            yield b"x" * 65536  # 4 MB in all

    server = Server({ADDRESS: lambda: httpx.Response(200, content=chunks())})
    refused(ADDRESS, server, "calendar_too_large")
    assert len(sent) <= calendar_ics.LIMIT_BYTES // 65536 + 1


def test_a_slow_answer_stops_at_the_deadline(dns, monkeypatch):
    ticks = iter(range(0, 1000, 2))  # every look at the clock is two seconds later
    monkeypatch.setattr(calendar_ics.time, "monotonic", lambda: float(next(ticks)))

    def chunks():
        for _ in range(10):
            yield b"BEGIN:VCALENDAR\n"

    refused(
        ADDRESS,
        Server({ADDRESS: lambda: httpx.Response(200, content=chunks())}),
        "calendar_unavailable",
    )


def test_a_transport_error_is_unavailable_and_names_no_address(dns):
    def broken(request):
        raise httpx.ConnectError(f"cannot reach {request.url}")

    with pytest.raises(calendar_ics.CalendarError) as caught:
        calendar_ics.fetch(ADDRESS, httpx.MockTransport(broken))
    assert caught.value.code == "calendar_unavailable"
    assert caught.value.__cause__ is None and caught.value.__suppress_context__
    assert "calendar.example.com" not in repr(caught.value)


def test_the_real_transport_refuses_a_socket_address_inside_the_network(monkeypatch):
    # The check before the request saw a public answer; the socket's own lookup gets a private
    # one (DNS rebinding). The public-only transport refuses it, and no connection is made.
    lookups = iter([PUBLIC, "10.0.0.9"])
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: answers(next(lookups, "10.0.0.9")))
    connected = []
    monkeypatch.setattr(
        socket, "create_connection", lambda *a, **k: connected.append(a) or pytest.fail("connected")
    )
    with pytest.raises(calendar_ics.CalendarError) as caught:
        calendar_ics.fetch(ADDRESS)
    assert caught.value.code == "calendar_address_refused"
    assert connected == []
