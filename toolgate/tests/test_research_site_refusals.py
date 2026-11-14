"""Site providers on bad upstream answers: GitHub, Stack Exchange, the App Store and YouTube.

Each test feeds one provider a refusal, a malformed or oversized body, or rows that break one
rule, and checks what it refuses or skips. No network: httpx.get is replaced per test.
"""

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from toolgate.executors import research_base, research_sites
from toolgate.executors.research_base import ResearchError


def answer(status=200, *, json=None, content=None, url="https://upstream.test/"):
    request = httpx.Request("GET", url)
    if json is not None:
        return httpx.Response(status, json=json, request=request)
    return httpx.Response(status, content=content or b"", request=request)


@pytest.fixture(autouse=True)
def public(monkeypatch):
    monkeypatch.setattr(research_base, "_public_https_url", lambda url: str(url).startswith("https://"))


def keys(monkeypatch, **stored):
    def get_key(name):
        if name not in stored:
            raise KeyError(name)
        return stored[name]

    monkeypatch.setattr(research_sites.vault, "get_key", get_key)


def serve(monkeypatch, handler):
    calls = []

    def get(url, **kwargs):
        calls.append((url, kwargs))
        return handler(url, **kwargs)

    monkeypatch.setattr(research_sites.httpx, "get", get)
    return calls


def ago(days=0):
    return (datetime.now(UTC) - timedelta(days=days)).isoformat()


# GitHub


def test_github_repositories_with_no_topic_words_searches_nothing(monkeypatch):
    keys(monkeypatch)
    calls = serve(monkeypatch, lambda url, **_: pytest.fail("no search without topic words"))
    assert research_sites._github_repositories("a b", "github", 5, 30, 5) == []
    assert calls == []


def test_github_repositories_retries_without_a_rejected_token(monkeypatch):
    keys(monkeypatch, GITHUB_TOKEN="stale-token")
    repo = {"full_name": "acme/ledger", "description": "Invoice ledger", "html_url": "https://github.com/acme/ledger",
            "stargazers_count": "12", "license": "MIT", "topics": ["invoices", ""], "pushed_at": ago()}

    def handler(url, headers, **_):
        if "Authorization" in headers:
            return answer(401, url=url)
        return answer(json={"items": [repo, {"full_name": "", "html_url": "https://github.com/x"}]})

    calls = serve(monkeypatch, handler)
    (row,) = research_sites._github_repositories("invoice ledger", "github", 5, 30, 5)
    assert [("Authorization" in kwargs["headers"]) for _url, kwargs in calls] == [True, False]
    # A licence that is not an object is "unknown", never echoed.
    assert (row["repository"], row["stars"], row["license"]) == ("acme/ledger", 12, "unknown")


def test_github_repositories_refusal_after_the_retry_is_raised(monkeypatch):
    keys(monkeypatch, GITHUB_TOKEN="stale-token")
    serve(monkeypatch, lambda url, **_: answer(401, url=url))
    with pytest.raises(httpx.HTTPStatusError):
        research_sites._github_repositories("invoice ledger", "github", 5, 30, 5)


# Stack Exchange


@pytest.mark.parametrize(("query", "sites"), [
    ("crm leads", ("salesforce", "webapps", "softwareengineering")),
    ("retail inventory", ("magento", "webapps", "softwareengineering")),
    ("llm eval", ("ai", "datascience", "softwareengineering")),
    ("oauth secret", ("security", "serverfault", "devops")),
    ("deploy rollback", ("devops", "serverfault", "softwareengineering")),
    ("calendar sync", ("softwareengineering", "webapps", "superuser")),
])
def test_stackexchange_communities_follow_the_query(query, sites):
    assert research_sites._stackexchange_sites(query) == sites


def test_stackexchange_raises_the_last_error_when_every_site_fails(monkeypatch):
    keys(monkeypatch)
    calls = serve(monkeypatch, lambda url, **_: answer(503, url=url))
    with pytest.raises(httpx.HTTPStatusError):
        research_sites._stackexchange("deploy rollback", "stackexchange", 5, 30, 5)
    assert [kwargs["params"]["site"] for _url, kwargs in calls] == ["devops", "serverfault", "softwareengineering"]


def test_stackexchange_keeps_working_sites_and_drops_duplicate_links(monkeypatch):
    keys(monkeypatch, STACKEXCHANGE_KEY="se-key")
    row = {"title": "Rollback a deploy", "link": "https://serverfault.com/q/1", "body": "<p>How?</p>",
           "creation_date": 1780000000}

    def handler(url, params, **_):
        if params["site"] == "devops":
            return answer(500, url=url)
        return answer(json={"items": [row]})

    calls = serve(monkeypatch, handler)
    rows = research_sites._stackexchange("deploy rollback", "stackexchange", 5, 30, 5)
    assert [r["url"] for r in rows] == ["https://serverfault.com/q/1"]
    assert rows[0]["community"] == "serverfault"
    assert all(kwargs["params"]["key"] == "se-key" for _url, kwargs in calls)


# App Store reviews


@pytest.mark.parametrize("query", ["", "12ab", "1234", "1" * 16, "123456 789012"])
def test_appstore_reviews_refuse_anything_but_one_numeric_id(monkeypatch, query):
    calls = serve(monkeypatch, lambda url, **_: pytest.fail("no request for a bad id"))
    with pytest.raises(ResearchError, match="App Store review query must be one numeric application ID"):
        research_sites._appstore_reviews(query, "appstore", 5, 30, 5)
    assert calls == []


def test_appstore_reviews_refuse_an_oversized_or_malformed_answer(monkeypatch):
    serve(monkeypatch, lambda url, **_: answer(content=b" " * (1048576 + 1)))
    with pytest.raises(ResearchError, match="App Store review response exceeded the safe size limit"):
        research_sites._appstore_reviews("123456", "appstore", 5, 30, 5)
    serve(monkeypatch, lambda url, **_: answer(content=b"{not json"))
    with pytest.raises(ResearchError, match="App Store review response was malformed"):
        research_sites._appstore_reviews("123456", "appstore", 5, 30, 5)


def review(rating="2", updated=None, content="Sync keeps failing.", review_id="r1"):
    return {"im:rating": {"label": rating}, "content": {"label": content}, "title": {"label": "Broken"},
            "updated": {"label": updated or ago()}, "id": {"label": review_id}}


def test_appstore_reviews_keep_only_recent_low_ratings(monkeypatch):
    entries = [
        review(rating="5"),
        review(rating="x"),
        review(content=""),
        review(updated="not a date"),
        review(updated=ago(90)),
        review(updated=(datetime.now(UTC) + timedelta(days=3)).isoformat()),
        review(review_id=""),
        review(review_id="r2"),
    ]
    serve(monkeypatch, lambda url, **_: answer(json={"feed": {"entry": entries}}))
    rows = research_sites._appstore_reviews("123456", "appstore", 5, 30, 5)
    assert [row["url"] for row in rows] == [
        "https://apps.apple.com/us/app/id123456?see-all=reviews",
        "https://apps.apple.com/us/app/id123456?see-all=reviews&reviewId=r2",
    ]
    assert all(row["rating"] == 2 for row in rows)


def test_appstore_reviews_read_a_single_entry_and_stop_at_a_non_object(monkeypatch):
    serve(monkeypatch, lambda url, **_: answer(json={"feed": {"entry": review()}}))
    assert len(research_sites._appstore_reviews("123456", "appstore", 5, 30, 5)) == 1
    serve(monkeypatch, lambda url, **_: answer(json={"feed": {"entry": ["junk", review()]}}))
    assert research_sites._appstore_reviews("123456", "appstore", 5, 30, 5) == []
    serve(monkeypatch, lambda url, **_: answer(json={"feed": {"entry": [review(), review()]}}))
    assert len(research_sites._appstore_reviews("123456", "appstore", 1, 30, 5)) == 1


# App Store catalogue


def test_appstore_catalog_refuses_a_query_without_a_term(monkeypatch):
    calls = serve(monkeypatch, lambda url, **_: pytest.fail("no request without a term"))
    with pytest.raises(ResearchError, match="App Store catalog query needs a concrete market or workflow term"):
        research_sites._appstore_catalog("a b", "appstore", 5, 30, 5)
    assert calls == []


def test_appstore_catalog_refuses_an_oversized_answer(monkeypatch):
    serve(monkeypatch, lambda url, **_: answer(content=b" " * (1048576 + 1)))
    with pytest.raises(ResearchError, match="App Store catalog response exceeded the safe size limit"):
        research_sites._appstore_catalog("invoice scanner", "appstore", 5, 30, 5)


def test_appstore_catalog_skips_bad_ids_unrelated_apps_and_bad_ratings(monkeypatch):
    rows = [
        {"trackId": "12", "trackName": "Invoice scanner"},
        {"trackId": 123456, "trackName": ""},
        {"trackId": 234567, "trackName": "Puzzle game", "description": "Match three."},
        {"trackId": 345678, "trackName": "Invoice scanner", "averageUserRating": "bad",
         "userRatingCount": "many", "primaryGenreName": "Business"},
    ]
    serve(monkeypatch, lambda url, **_: answer(json={"results": rows}))
    (row,) = research_sites._appstore_catalog("invoice scanner", "appstore", 5, 30, 5)
    assert (row["app_id"], row["rating"], row["rating_count"]) == ("345678", 0.0, 0)


def test_appstore_catalog_skips_an_app_whose_page_is_not_public(monkeypatch):
    monkeypatch.setattr(research_base, "_public_https_url", lambda url: False)
    rows = [{"trackId": 345678, "trackName": "Invoice scanner"}]
    serve(monkeypatch, lambda url, **_: answer(json={"results": rows}))
    assert research_sites._appstore_catalog("invoice scanner", "appstore", 5, 30, 5) == []


# YouTube


def test_youtube_without_a_key_refuses_before_any_request(monkeypatch):
    keys(monkeypatch)
    calls = serve(monkeypatch, lambda url, **_: pytest.fail("no request without a key"))
    with pytest.raises(KeyError):
        research_sites._youtube("invoice scanner", "youtube", 5, 30, 5)
    assert calls == []


def comment(comment_id="Ugabcdefgh", text="Still typing invoices by hand.", likes=3):
    return {"snippet": {"topLevelComment": {"id": comment_id, "snippet": {
        "textOriginal": text, "likeCount": likes, "publishedAt": "2026-07-01T00:00:00Z"}}}}


def test_youtube_skips_bad_videos_failed_comment_reads_and_malformed_comments(monkeypatch):
    keys(monkeypatch, GOOGLE_API_KEY="yt-key")
    videos = [
        {"id": "not-an-object", "snippet": {"title": "x"}},
        {"id": {"videoId": "short"}, "snippet": {"title": "x"}},
        {"id": {"videoId": "AAAAAAAAAAA"}, "snippet": {"title": "Fails"}},
        {"id": {"videoId": "BBBBBBBBBBB"}, "snippet": {"title": "Invoices"}},
    ]
    comments = [
        "junk",
        {"snippet": "junk"},
        {"snippet": {"topLevelComment": "junk"}},
        {"snippet": {"topLevelComment": {"id": "Ugabcdefgh", "snippet": "junk"}}},
        comment(text=""),
        comment(comment_id="bad id!"),
        comment(likes=1),
        comment(comment_id="Ugzyxwvuts", likes=9),
    ]

    def handler(url, params, headers, **_):
        assert headers == {"X-Goog-Api-Key": "yt-key"} and "key" not in params
        if url.endswith("/search"):
            return answer(json={"items": videos})
        if params["videoId"] == "AAAAAAAAAAA":
            return answer(403, url=url)
        return answer(json={"items": comments})

    calls = serve(monkeypatch, handler)
    rows = research_sites._youtube("invoice scanner", "youtube", 5, 30, 5)
    assert [row["url"].rsplit("lc=", 1)[1] for row in rows] == ["Ugzyxwvuts", "Ugabcdefgh"]
    assert [kwargs["params"].get("videoId") for _url, kwargs in calls][1:] == ["AAAAAAAAAAA", "BBBBBBBBBBB"]
