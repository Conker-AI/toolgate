"""Forum providers on bad upstream answers: Hacker News, Reddit's Atom feeds and Discourse.

Each test feeds one provider a refusal, a malformed or oversized body, or rows that break one
rule, and checks what it refuses or skips. No network: httpx.get is replaced per test.
"""

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from toolgate.executors import research_base, research_forums
from toolgate.executors.research_base import ResearchError

ATOM = "http://www.w3.org/2005/Atom"


def answer(status=200, *, json=None, content=None, url="https://upstream.test/"):
    """A real httpx response, so raise_for_status and json_body behave as in production."""
    request = httpx.Request("GET", url)
    if json is not None:
        return httpx.Response(status, json=json, request=request)
    return httpx.Response(status, content=content or b"", request=request)


@pytest.fixture(autouse=True)
def public_and_ready(monkeypatch):
    """Every result URL counts as public (no DNS), and no provider starts cooled down."""
    monkeypatch.setattr(research_base, "_public_https_url", lambda url: url.startswith("https://"))
    research_base._PROVIDER_COOLDOWNS.clear()
    yield
    research_base._PROVIDER_COOLDOWNS.clear()


def serve(monkeypatch, handler):
    calls = []

    def get(url, **kwargs):
        calls.append((url, kwargs))
        return handler(url, **kwargs)

    monkeypatch.setattr(research_forums.httpx, "get", get)
    return calls


def feed(*entries):
    body = "".join(entries)
    return f'<?xml version="1.0"?><feed xmlns="{ATOM}">{body}</feed>'.encode()


def entry(title, updated, href="https://www.reddit.com/r/smallbusiness/comments/a/b/",
          content="We copy every invoice by hand and dispatch takes hours."):
    return (f"<entry><title>{title}</title><updated>{updated}</updated>"
            f'<link rel="alternate" href="{href}" /><content type="html">{content}</content></entry>')


def now(days=0):
    return (datetime.now(UTC) - timedelta(days=days)).isoformat()


# Hacker News


def test_hackernews_skips_untitled_and_dead_stories_and_stops_at_the_limit(monkeypatch):
    hits = [
        {"story_title": "", "story_id": 1, "comment_text": "no title"},
        {"story_title": "[dead]", "story_id": 2, "comment_text": "dead story"},
        {"story_title": "Invoices by hand", "story_id": 3, "comment_text": "<p>We still type them.</p>",
         "created_at": "2026-07-01T00:00:00Z"},
        {"story_title": "Second story", "story_id": 4, "comment_text": "also manual"},
    ]
    calls = serve(monkeypatch, lambda url, **_: answer(json={"hits": hits}))
    rows = research_forums._hackernews("invoices", "hackernews", 1, 30, 5)
    assert [row["url"] for row in rows] == ["https://news.ycombinator.com/item?id=3"]
    assert rows[0]["document"] == "Hacker News story: Invoices by hand\nPublic comment: We still type them."
    assert "<p>" not in rows[0]["snippet"]
    params = calls[0][1]["params"]
    assert params["tags"] == "comment" and params["hitsPerPage"] == 4
    assert params["numericFilters"].startswith("created_at_i>")


def test_hackernews_falls_back_to_the_object_id_when_the_story_id_is_missing(monkeypatch):
    hits = [{"story_title": "Agent costs", "objectID": "77", "comment_text": "doubled"}]
    serve(monkeypatch, lambda url, **_: answer(json={"hits": hits}))
    (row,) = research_forums._hackernews("costs", "hackernews", 5, 30, 5)
    assert row["url"] == "https://news.ycombinator.com/item?id=77"


def test_hackernews_refusal_is_raised_not_read_as_no_results(monkeypatch):
    serve(monkeypatch, lambda url, **_: answer(503, url=url))
    with pytest.raises(httpx.HTTPStatusError):
        research_forums._hackernews("invoices", "hackernews", 5, 30, 5)


def test_hackernews_oversized_answer_is_refused_unparsed(monkeypatch):
    oversized = {"hits": [], "padding": "x" * research_base.JSON_LIMIT}
    serve(monkeypatch, lambda url, **_: answer(json=oversized))
    with pytest.raises(ResearchError, match="Hacker News response exceeded the safe size limit"):
        research_forums._hackernews("invoices", "hackernews", 5, 30, 5)


# Reddit search (Atom)


def test_reddit_search_skips_bad_dates_old_and_future_entries_and_stops_at_the_limit(monkeypatch):
    body = feed(
        entry("Bad date dispatch invoice", "not-a-date"),
        entry("Old dispatch invoice", now(400)),
        entry("Future dispatch invoice", (datetime.now(UTC) + timedelta(days=5)).isoformat()),
        entry("Dispatch invoice pain", now(), href="https://www.reddit.com/r/smallbusiness/comments/c/d/"),
        entry("Dispatch invoice again", now(), href="https://www.reddit.com/r/smallbusiness/comments/e/f/"),
    )
    calls = serve(monkeypatch, lambda url, **_: answer(content=body))
    rows = research_forums._reddit_rss_search("dispatch invoice", "reddit", 1, 30, 5)
    assert [row["title"] for row in rows] == ["Dispatch invoice pain"]
    assert calls[0][1]["params"]["t"] == "month"


@pytest.mark.parametrize(("days", "window"), [(1, "day"), (7, "week"), (300, "year"), (900, "all")])
def test_reddit_search_window_follows_the_recency(monkeypatch, days, window):
    calls = serve(monkeypatch, lambda url, **_: answer(content=feed()))
    assert research_forums._reddit_rss_search("dispatch invoice", "reddit", 5, days, 5) == []
    assert calls[0][1]["params"]["t"] == window


def test_reddit_search_refuses_an_oversized_or_malformed_feed(monkeypatch):
    serve(monkeypatch, lambda url, **_: answer(content=b"<feed>" + b" " * 524288))
    with pytest.raises(ResearchError, match="Reddit Atom response exceeded the safe size limit"):
        research_forums._reddit_rss_search("dispatch", "reddit", 5, 90, 5)
    serve(monkeypatch, lambda url, **_: answer(content=b"<feed><entry>"))
    with pytest.raises(ResearchError, match="Reddit Atom response was malformed"):
        research_forums._reddit_rss_search("dispatch", "reddit", 5, 90, 5)


def test_reddit_search_drops_entries_that_do_not_match_the_terms(monkeypatch):
    body = feed(entry("Gardening tips", now(), content="Tomatoes grow well in pots."))
    serve(monkeypatch, lambda url, **_: answer(content=body))
    assert research_forums._reddit_rss_search('"dispatch board" invoices hours', "reddit", 5, 90, 5) == []


# Reddit subreddit feed


def test_subreddit_feed_cools_down_after_a_quota_refusal_and_then_refuses_without_a_call(monkeypatch):
    calls = serve(monkeypatch, lambda url, **_: answer(429, url=url))
    with pytest.raises(httpx.HTTPStatusError):
        research_forums._reddit_subreddit_feed("subreddit:smallbusiness", "reddit", 5, 90, 5)
    assert "reddit_feed" in research_base._PROVIDER_COOLDOWNS
    with pytest.raises(ResearchError, match="reddit_feed is temporarily unavailable"):
        research_forums._reddit_subreddit_feed("subreddit:smallbusiness", "reddit", 5, 90, 5)
    assert len(calls) == 1


def test_subreddit_feed_server_error_does_not_cool_down(monkeypatch):
    serve(monkeypatch, lambda url, **_: answer(500, url=url))
    with pytest.raises(httpx.HTTPStatusError):
        research_forums._reddit_subreddit_feed("subreddit:smallbusiness", "reddit", 5, 90, 5)
    assert "reddit_feed" not in research_base._PROVIDER_COOLDOWNS


def test_subreddit_feed_refuses_an_oversized_or_malformed_feed(monkeypatch):
    serve(monkeypatch, lambda url, **_: answer(content=b"<feed>" + b" " * 524288))
    with pytest.raises(ResearchError, match="Reddit Atom response exceeded the safe size limit"):
        research_forums._reddit_subreddit_feed("subreddit:smallbusiness", "reddit", 5, 90, 5)
    serve(monkeypatch, lambda url, **_: answer(content=b"<<not xml"))
    with pytest.raises(ResearchError, match="Reddit Atom response was malformed"):
        research_forums._reddit_subreddit_feed("subreddit:smallbusiness", "reddit", 5, 90, 5)


def test_subreddit_feed_skips_bad_dates_old_entries_and_stops_at_the_limit(monkeypatch):
    body = feed(
        entry("Bad date", "yesterday"),
        entry("Old post", now(200)),
        entry("Fresh post", now(), href="https://www.reddit.com/r/smallbusiness/comments/g/h/"),
        entry("Another fresh post", now(), href="https://www.reddit.com/r/smallbusiness/comments/i/j/"),
    )
    serve(monkeypatch, lambda url, **_: answer(content=body))
    rows = research_forums._reddit_subreddit_feed("subreddit:smallbusiness", "reddit", 1, 90, 5)
    assert [row["title"] for row in rows] == ["Fresh post"]
    assert rows[0]["community"] == "r/smallbusiness"


@pytest.mark.parametrize("query", ["subreddit:notapproved", "smallbusiness", "subreddit:a"])
def test_subreddit_fallback_refuses_a_community_off_the_allowlist(monkeypatch, query):
    def provider(*_args):
        pytest.fail("no search may run for an unapproved community")

    with pytest.raises(ResearchError, match="subreddit fallback is not allowlisted"):
        research_forums._reddit_subreddit_fallback(query, "reddit", 5, 90, 5, provider)


@pytest.mark.parametrize("name", ["_searx", "_tavily"])
def test_subreddit_fallbacks_keep_only_that_communitys_threads(monkeypatch, name):
    rows = [
        {"url": "https://www.reddit.com/r/smallbusiness/comments/abc/topic/"},
        {"url": "https://www.reddit.com/r/other/comments/abc/topic/"},
        {"url": "https://example.com/r/smallbusiness/"},
        {"url": None},
    ]
    seen = []

    def provider(query, *_args):
        seen.append(query)
        return rows

    monkeypatch.setattr(research_forums, name, provider)
    wrapper = research_forums._reddit_subreddit_searx if name == "_searx" else research_forums._reddit_subreddit_tavily
    assert wrapper("subreddit:smallbusiness", "reddit", 5, 90, 5) == rows[:1]
    assert seen == ["site:reddit.com/r/smallbusiness manual workflow software problem"]


# Discourse


def test_discourse_with_no_topic_words_searches_nothing(monkeypatch):
    calls = serve(monkeypatch, lambda url, **_: pytest.fail("no search without topic words"))
    assert research_forums._discourse("a b", "discourse", 5, 30, 5) == []
    assert calls == []


def test_discourse_raises_the_last_error_when_every_host_fails(monkeypatch):
    monkeypatch.setattr(research_forums.time, "monotonic", lambda: 0.0)
    calls = serve(monkeypatch, lambda url, **_: answer(502, url=url))
    with pytest.raises(httpx.HTTPStatusError):
        research_forums._discourse("invoice reconciliation", "discourse", 5, 30, 5)
    assert len(calls) == len(research_base.DISCOURSE_HOSTS)


def test_discourse_stops_searching_when_the_deadline_is_spent(monkeypatch):
    clock = iter([0.0, 10.0])
    monkeypatch.setattr(research_forums.time, "monotonic", lambda: next(clock, 10.0))
    calls = serve(monkeypatch, lambda url, **_: pytest.fail("no host once the time is spent"))
    assert research_forums._discourse("invoice reconciliation", "discourse", 5, 1, 1) == []
    assert calls == []


def search_page(host):
    return {
        "topics": [
            {"id": 1, "title": "Invoice reconciliation", "slug": "Bad Slug!", "archetype": "regular"},
            {"id": 2, "title": "Private message", "slug": "pm", "archetype": "private_message"},
        ],
        "posts": [
            "not an object",
            {"topic_id": 99, "post_number": 1, "blurb": "topic missing"},
            {"topic_id": 2, "post_number": 1, "blurb": "a private message"},
            {"topic_id": 1, "post_number": 3, "username": "helper", "blurb": f"invoice reply on {host}",
             "created_at": "2026-07-02T00:00:00Z"},
        ],
    }


def test_discourse_skips_broken_posts_and_keeps_unhydrated_topics(monkeypatch):
    monkeypatch.setattr(research_forums.time, "monotonic", lambda: 0.0)
    first, second, third, fourth = research_base.DISCOURSE_HOSTS

    def handler(url, **_):
        host = url.split("/")[2]
        if url.endswith("/search.json"):
            return answer(json=search_page(host), url=url)
        if host == first:
            return answer(500, url=url)  # topic read fails: the search row is kept
        if host == second:
            return answer(json={"post_stream": {"posts": []}}, url=url)
        if host == third:
            return answer(json={"post_stream": {"posts": [{"post_number": 1, "cooked": ""}]}}, url=url)
        return answer(json={"post_stream": {"posts": [{"post_number": "x"}]}}, url=url)

    serve(monkeypatch, handler)
    rows = research_forums._discourse("invoice reconciliation", "discourse", 8, 30, 5)
    assert sorted(row["community"] for row in rows) == sorted(research_base.DISCOURSE_HOSTS)
    for row in rows:
        # The slug that is not a plain slug became "topic"; no row was rewritten to the root.
        assert row["url"] == f"https://{row['community']}/t/topic/1/3"
        assert row["post_number"] == 3 and row["reporter"] == "helper"
        assert row["document"].startswith(f"Public Discourse post ({row['community']})")
    assert fourth in {row["community"] for row in rows}


def test_discourse_keeps_the_rest_unhydrated_once_the_time_runs_out(monkeypatch):
    ticks = iter([0.0] * (1 + len(research_base.DISCOURSE_HOSTS)) + [100.0])
    monkeypatch.setattr(research_forums.time, "monotonic", lambda: next(ticks, 100.0))

    def handler(url, **_):
        if url.endswith("/search.json"):
            return answer(json=search_page(url.split("/")[2]), url=url)
        pytest.fail("no topic read once the time is spent")

    serve(monkeypatch, handler)
    rows = research_forums._discourse("invoice reconciliation", "discourse", 8, 30, 5)
    assert len(rows) == len(research_base.DISCOURSE_HOSTS)
    assert all(row["post_number"] == 3 for row in rows)
