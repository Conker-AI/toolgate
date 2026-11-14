"""General web search on bad upstream answers: community snapshots, SearXNG, Tavily and
Reddit feed dates. No network: httpx is replaced per test."""

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from toolgate.executors import research_base, research_web
from toolgate.executors.research_base import ResearchError


def answer(status=200, *, json=None, content=None, url="https://upstream.test/"):
    request = httpx.Request("GET", url)
    if json is not None:
        return httpx.Response(status, json=json, request=request)
    return httpx.Response(status, content=content or b"", request=request)


@pytest.fixture(autouse=True)
def public_and_ready(monkeypatch):
    monkeypatch.setattr(research_base, "_public_https_url", lambda url: str(url).startswith("https://"))
    research_base._PROVIDER_COOLDOWNS.clear()
    yield
    research_base._PROVIDER_COOLDOWNS.clear()


def serve(monkeypatch, handler, method="get"):
    calls = []

    def call(url, **kwargs):
        calls.append((url, kwargs))
        return handler(url, **kwargs)

    monkeypatch.setattr(research_web.httpx, method, call)
    return calls


def no_keys(monkeypatch, **stored):
    def get_key(name):
        if name not in stored:
            raise KeyError(name)
        return stored[name]

    monkeypatch.setattr(research_web.vault, "get_key", get_key)


# Community snapshots


def test_a_hackernews_row_without_an_item_id_is_kept_as_it_is(monkeypatch):
    calls = serve(monkeypatch, lambda url, **_: pytest.fail("no request without an id"))
    item = {"title": "Costs", "url": "https://news.ycombinator.com/news", "snippet": "x"}
    assert research_web._community_snapshot(item, "hackernews", 5) is item
    assert calls == []


def test_a_stackoverflow_row_is_hydrated_with_the_question_body(monkeypatch):
    no_keys(monkeypatch, STACKEXCHANGE_KEY="se-key")
    calls = serve(monkeypatch, lambda url, **_: answer(json={"items": [{"body": "<p>Invoices by hand.</p>"}]}))
    item = {"title": "Invoices", "url": "https://stackoverflow.com/questions/123/invoices"}
    hydrated = research_web._community_snapshot(item, "stackoverflow", 5)
    assert hydrated["document"] == "Stack Overflow question: Invoices\nQuestion body: Invoices by hand."
    assert calls[0][0].endswith("/questions/123") and calls[0][1]["params"]["key"] == "se-key"


@pytest.mark.parametrize("reply", [
    answer(json={"items": []}),
    answer(json={"items": [{"body": ""}]}),
    answer(502),
    answer(content=b"{broken"),
])
def test_a_stackoverflow_row_stays_unhydrated_when_the_question_cannot_be_read(monkeypatch, reply):
    no_keys(monkeypatch)
    serve(monkeypatch, lambda url, **_: reply)
    item = {"title": "Invoices", "url": "https://stackoverflow.com/questions/123/invoices"}
    assert research_web._community_snapshot(item, "stackoverflow", 5) == item


def test_a_stackoverflow_row_that_is_not_a_question_is_kept_without_a_request(monkeypatch):
    calls = serve(monkeypatch, lambda url, **_: pytest.fail("no request for a non-question"))
    item = {"title": "Tags", "url": "https://stackoverflow.com/tags"}
    assert research_web._community_snapshot(item, "stackoverflow", 5) is item
    assert calls == []


# SearXNG windows and dates


def test_searxng_has_no_window_beyond_a_year():
    assert research_web._searx_time_range(400) == {}
    assert research_web._searx_time_range(31) == {"time_range": "month"}


def test_rows_with_unreadable_or_naive_dates():
    assert research_web._older_than({"published_at": "last week"}, 7) is False
    assert research_web._older_than({"published_at": "2001-01-01T00:00:00"}, 7) is True
    fresh = datetime.now(UTC).replace(tzinfo=None).isoformat()
    assert research_web._older_than({"published_at": fresh}, 7) is False


def test_searxng_drops_old_excluded_and_unsafe_rows_and_stops_at_the_limit(monkeypatch):
    monkeypatch.setattr(research_web.control_plane, "settings", lambda: {"research_searxng_url": "https://search.test/"})
    monkeypatch.setattr(research_web, "_community_snapshot", lambda item, *_args: item)
    old = (datetime.now(UTC) - timedelta(days=400)).isoformat()
    rows = [
        {"title": "Old", "url": "https://example.com/old", "content": "x", "publishedDate": old},
        {"title": "Reddit", "url": "https://www.reddit.com/r/a/comments/b/", "content": "x"},
        {"title": "Local", "url": "http://10.0.0.1/", "content": "x"},
        {"title": "Kept", "url": "https://example.com/kept", "content": "x"},
        {"title": "Over the limit", "url": "https://example.com/more", "content": "x"},
    ]
    calls = serve(monkeypatch, lambda url, **_: answer(json={"results": rows}))
    found = research_web._searx("invoices", "general", 1, 30, 5)
    assert [row["title"] for row in found] == ["Kept"]
    url, kwargs = calls[0]
    assert url == "https://search.test/search"
    # Another instance gets no forged client address.
    assert "X-Forwarded-For" not in kwargs["headers"]


def test_searxng_refusal_is_raised(monkeypatch):
    monkeypatch.setattr(research_web.control_plane, "settings", lambda: {})
    serve(monkeypatch, lambda url, **_: answer(403, url=url))
    with pytest.raises(httpx.HTTPStatusError):
        research_web._searx("invoices", "general", 5, 30, 5)


def test_searxng_skips_snapshots_once_the_time_is_spent(monkeypatch):
    monkeypatch.setattr(research_web.control_plane, "settings", lambda: {})
    ticks = iter([0.0, 100.0])
    monkeypatch.setattr(research_web.time, "monotonic", lambda: next(ticks, 100.0))
    monkeypatch.setattr(research_web, "_community_snapshot", lambda *_a: pytest.fail("no snapshot"))
    rows = [{"title": "Kept", "url": "https://example.com/kept", "content": "x"}]
    serve(monkeypatch, lambda url, **_: answer(json={"results": rows}))
    assert [row["title"] for row in research_web._searx("invoices", "general", 5, 30, 1)] == ["Kept"]


# Tavily


def test_tavily_is_refused_without_a_spending_adapter():
    with pytest.raises(ResearchError, match="Tavily is disabled until it has a bounded spending adapter"):
        research_web._tavily("invoices", "general", 5, 30, 5)


@pytest.mark.parametrize("status", [429, 432, 401, 403])
def test_tavily_quota_and_key_refusals_cool_the_provider_down(monkeypatch, status):
    no_keys(monkeypatch, TAVILY_API_KEY="tv-key")
    calls = serve(monkeypatch, lambda url, **_: answer(status, url=url), method="post")
    with pytest.raises(httpx.HTTPStatusError):
        research_web._tavily_unmetered("invoices", "general", 5, 30, 5)
    with pytest.raises(ResearchError, match="tavily is temporarily unavailable"):
        research_web._tavily_unmetered("invoices", "general", 5, 30, 5)
    assert len(calls) == 1


def test_tavily_server_error_does_not_cool_down(monkeypatch):
    no_keys(monkeypatch, TAVILY_API_KEY="tv-key")
    serve(monkeypatch, lambda url, **_: answer(500, url=url), method="post")
    with pytest.raises(httpx.HTTPStatusError):
        research_web._tavily_unmetered("invoices", "general", 5, 30, 5)
    assert "tavily" not in research_base._PROVIDER_COOLDOWNS


def test_tavily_without_a_key_sends_nothing(monkeypatch):
    no_keys(monkeypatch)
    calls = serve(monkeypatch, lambda url, **_: pytest.fail("no request without a key"), method="post")
    with pytest.raises(KeyError):
        research_web._tavily_unmetered("invoices", "general", 5, 30, 5)
    assert calls == []


def test_tavily_reddit_rows_take_their_date_from_the_feed(monkeypatch):
    no_keys(monkeypatch, TAVILY_API_KEY="tv-key")
    monkeypatch.setattr(research_web, "_reddit_rss_published_at", lambda url, _t: "2026-07-01T00:00:00+00:00")
    monkeypatch.setattr(research_web, "_community_snapshot", lambda item, *_a: item)
    rows = [
        {"title": "Thread", "url": "https://www.reddit.com/r/a/comments/b/", "content": "manual"},
        {"title": "Elsewhere", "url": "https://example.com/x", "content": "manual"},
    ]
    serve(monkeypatch, lambda url, **_: answer(json={"results": rows}), method="post")
    (row,) = research_web._tavily_unmetered("invoices", "reddit", 5, 30, 5)
    assert row["published_at"] == "2026-07-01T00:00:00+00:00"


# Reddit feed dates


def atom(body):
    return f'<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">{body}</feed>'.encode()


@pytest.mark.parametrize("reply", [
    answer(content=atom("") + b" " * 262144),
    answer(content=atom("")),
    answer(content=atom("<entry><title>No date</title></entry>")),
    answer(content=atom("<entry><updated>soon</updated></entry>")),
    answer(content=b"<feed"),
    answer(404),
])
def test_reddit_feed_dates_are_none_when_the_feed_cannot_say(monkeypatch, reply):
    serve(monkeypatch, lambda url, **_: reply)
    assert research_web._reddit_rss_published_at("https://www.reddit.com/r/a/comments/b/topic/", 5) is None
