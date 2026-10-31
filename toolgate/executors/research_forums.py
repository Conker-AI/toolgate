"""Community forums: Hacker News, Reddit and approved Discourse hosts."""
from __future__ import annotations

import re
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx

from toolgate.executors.research_base import (
    _PROVIDER_COOLDOWNS,
    DISCOURSE_HOSTS,
    QUERY_STOP_WORDS,
    REDDIT_FEED_ALLOWLIST,
    REDDIT_QUERY_STOP_WORDS,
    ResearchError,
    _cooldown_provider,
    _normalize,
    _require_provider_ready,
    json_body,
)
from toolgate.executors.research_text import clean_text, extract_html_text
from toolgate.executors.research_web import _searx, _tavily


def _hackernews(query: str, _source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    response = httpx.get(
        "https://hn.algolia.com/api/v1/search",
        params={"query": query, "tags": "comment", "hitsPerPage": min(limit * 4, 40),
                "numericFilters": f"created_at_i>{int((datetime.now(UTC) - timedelta(days=recency_days)).timestamp())}"},
        timeout=timeout,
    )
    response.raise_for_status()
    rows = json_body(response, "Hacker News").get("hits", [])
    results = []
    for row in rows:
        if len(results) >= limit:
            break
        title = str(row.get("story_title") or "").strip()
        if not title or title.lower() == "[dead]":
            continue
        target = f"https://news.ycombinator.com/item?id={row.get('story_id') or row.get('objectID')}"
        comment = extract_html_text(row.get("comment_text") or "", 6000)
        item = _normalize(title, target, comment, "hackernews", row.get("created_at"))
        if item:
            results.append({**item, "document": f"Hacker News story: {clean_text(title, 300)}\nPublic comment: {comment}"})
    return results


def _reddit_rss_search(query: str, _source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    """Use Reddit's public Atom search when its JSON endpoint is unavailable."""
    timeframe = "day" if recency_days <= 1 else "week" if recency_days <= 7 else "month" if recency_days <= 45 else "year" if recency_days <= 365 else "all"
    generic_quotes = {"how do you", "looking for", "takes hours", "we still use"}
    quoted = [
        clean_text(value, 80)
        for value in re.findall(r'"([^"\r\n]{2,80})"', query)
        if clean_text(value, 80).lower() not in generic_quotes
    ]
    unquoted = re.sub(r'"[^"\r\n]{2,80}"', " ", query)
    terms = list(dict.fromkeys(
        token for token in re.findall(r"[a-z0-9]{3,}", unquoted.lower())
        if token not in REDDIT_QUERY_STOP_WORDS and token not in {"and", "or", "not"}
    ))
    clauses = [f'"{value}"' for value in quoted[:1]] + terms[:3]
    strict_query = " AND ".join(clauses) or query
    response = httpx.get(
        "https://www.reddit.com/search.rss",
        params={"q": strict_query, "sort": "new", "t": timeframe, "limit": min(limit, 20)},
        headers={
            "User-Agent": "ToolGateResearch/2.0 (local owner-operated research)",
            "Accept": "application/atom+xml",
        },
        timeout=timeout,
    )
    response.raise_for_status()
    if len(response.content) > 524288:
        raise ResearchError("Reddit Atom response exceeded the safe size limit")
    try:
        root = ET.fromstring(response.content)
    except ET.ParseError as exc:
        raise ResearchError("Reddit Atom response was malformed") from exc
    atom = "{http://www.w3.org/2005/Atom}"
    cutoff = datetime.now(UTC) - timedelta(days=recency_days)
    results = []
    for entry in root.findall(f"{atom}entry"):
        if len(results) >= limit:
            break
        updated = clean_text(entry.findtext(f"{atom}updated"), 80)
        try:
            published = datetime.fromisoformat(updated.replace("Z", "+00:00")).astimezone(UTC)
        except (TypeError, ValueError):
            continue
        if published < cutoff or published > datetime.now(UTC) + timedelta(days=1):
            continue
        target = next(
            (
                clean_text(link.get("href"), 1000)
                for link in entry.findall(f"{atom}link")
                if link.get("rel", "alternate") == "alternate" and link.get("href")
            ),
            "",
        )
        content = extract_html_text(entry.findtext(f"{atom}content") or "", 2400)
        item = _normalize(entry.findtext(f"{atom}title"), target, content, "reddit", published.isoformat())
        item_tokens = set(re.findall(r"[a-z0-9]{3,}", f"{item.get('title', '')} {item.get('snippet', '')}".lower())) if item else set()
        required_terms = set(terms[:3])
        required_overlap = min(2, len(required_terms))
        quoted_match = any(value.lower() in f"{item.get('title', '')} {item.get('snippet', '')}".lower() for value in quoted) if item else False
        if item and (quoted_match or len(required_terms & item_tokens) >= required_overlap):
            results.append({
                **item,
                "recency_provenance": {
                    "provider": "reddit_atom",
                    "field": "entry.updated",
                    "max_age_days": recency_days,
                },
                "document": f"Reddit discussion excerpt: {item['title']}\n{content}",
            })
    return results


def _reddit_subreddit_feed(query: str, _source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    """Read one allowlisted chronological buyer-community feed per request."""
    match = re.fullmatch(r"subreddit:([a-z0-9_]{2,30})", query.strip().lower())
    if not match or match.group(1) not in REDDIT_FEED_ALLOWLIST:
        raise ResearchError("subreddit feed is not allowlisted")
    subreddit = match.group(1)
    _require_provider_ready("reddit_feed")
    response = httpx.get(
        f"https://www.reddit.com/r/{subreddit}/new.rss",
        headers={
            "User-Agent": "ToolGateResearch/2.0 (local owner-operated research)",
            "Accept": "application/atom+xml",
        },
        timeout=timeout,
    )
    if response.status_code in {403, 429}:
        _cooldown_provider("reddit_feed", 15 * 60)
    response.raise_for_status()
    _PROVIDER_COOLDOWNS.pop("reddit_feed", None)
    if len(response.content) > 524288:
        raise ResearchError("Reddit Atom response exceeded the safe size limit")
    try:
        root = ET.fromstring(response.content)
    except ET.ParseError as exc:
        raise ResearchError("Reddit Atom response was malformed") from exc
    atom = "{http://www.w3.org/2005/Atom}"
    cutoff = datetime.now(UTC) - timedelta(days=recency_days)
    results = []
    for entry in root.findall(f"{atom}entry"):
        if len(results) >= limit:
            break
        updated = clean_text(entry.findtext(f"{atom}updated"), 80)
        try:
            published = datetime.fromisoformat(updated.replace("Z", "+00:00")).astimezone(UTC)
        except (TypeError, ValueError):
            continue
        if published < cutoff or published > datetime.now(UTC) + timedelta(days=1):
            continue
        target = next((
            clean_text(link.get("href"), 1000)
            for link in entry.findall(f"{atom}link")
            if link.get("rel", "alternate") == "alternate" and link.get("href")
        ), "")
        content = extract_html_text(entry.findtext(f"{atom}content") or "", 2400)
        item = _normalize(entry.findtext(f"{atom}title"), target, content, "reddit", published.isoformat())
        if item:
            results.append({
                **item,
                "community": f"r/{subreddit}",
                "recency_provenance": {
                    "provider": "reddit_atom_feed", "field": "entry.updated",
                    "max_age_days": recency_days,
                },
                "document": f"Reddit r/{subreddit} discussion excerpt: {item['title']}\n{content}",
            })
    return results


def _reddit_subreddit_fallback(
    query: str,
    source: str,
    limit: int,
    recency_days: int,
    timeout: float,
    provider,
) -> list[dict]:
    """Search one approved subreddit when its chronological feed is blocked."""
    match = re.fullmatch(r"subreddit:([a-z0-9_]{2,30})", query.strip().lower())
    if not match or match.group(1) not in REDDIT_FEED_ALLOWLIST:
        raise ResearchError("subreddit fallback is not allowlisted")
    subreddit = match.group(1)
    focused_query = f"site:reddit.com/r/{subreddit} manual workflow software problem"
    rows = provider(focused_query, source, limit, recency_days, timeout)
    expected_prefix = f"/r/{subreddit}/comments/"
    return [
        row for row in rows
        if urlsplit(str(row.get("url") or "")).path.lower().startswith(expected_prefix)
    ][:limit]


def _reddit_subreddit_searx(query: str, source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    return _reddit_subreddit_fallback(query, source, limit, recency_days, timeout, _searx)


def _reddit_subreddit_tavily(query: str, source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    return _reddit_subreddit_fallback(query, source, limit, recency_days, timeout, _tavily)


def _discourse(query: str, _source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    """Search approved public automation communities through Discourse JSON."""
    deadline = time.monotonic() + max(1.0, timeout)
    terms = [
        term for term in dict.fromkeys(re.findall(r"[a-z0-9]+", query.lower()))
        if len(term) >= 3 and term not in QUERY_STOP_WORDS
    ][:4]
    if not terms:
        return []
    after = (datetime.now(UTC) - timedelta(days=recency_days)).date().isoformat()
    discourse_query = f"{' '.join(terms)} after:{after} order:latest"
    buckets: list[list[dict]] = []
    last_error: Exception | None = None
    for host in DISCOURSE_HOSTS:
        remaining = deadline - time.monotonic()
        if remaining < 0.25:
            break
        try:
            response = httpx.get(
                f"https://{host}/search.json",
                params={"q": discourse_query},
                headers={"Accept": "application/json", "User-Agent": "ToolGateResearch/2.0"},
                timeout=min(2.5, remaining),
            )
            response.raise_for_status()
            payload = json_body(response, "Discourse")
        except (httpx.HTTPError, ResearchError) as exc:
            last_error = exc
            continue
        topics = {int(topic.get("id")): topic for topic in payload.get("topics", []) if topic.get("id")}
        host_rows = []
        for post in payload.get("posts", []):
            topic = topics.get(int(post.get("topic_id") or 0))
            if not topic or topic.get("archetype") not in {None, "regular"}:
                continue
            topic_id = int(topic["id"])
            post_number = max(1, int(post.get("post_number") or 1))
            slug = clean_text(topic.get("slug") or "topic", 160)
            if not re.fullmatch(r"[a-z0-9-]{1,160}", slug):
                slug = "topic"
            url = f"https://{host}/t/{slug}/{topic_id}/{post_number}"
            body = extract_html_text(post.get("blurb") or topic.get("excerpt") or "", 6000)
            item = _normalize(topic.get("title"), url, body, "discourse", post.get("created_at") or topic.get("created_at"))
            if item:
                host_rows.append({
                    **item, "community": host, "reporter": clean_text(post.get("username") or "", 80),
                    "topic_id": topic_id, "post_number": post_number,
                    "document": f"Public Discourse post ({host}): {item['title']}\nPost excerpt: {body}",
                })
        buckets.append(host_rows)
    if not buckets and last_error:
        raise last_error
    results = []
    seen = set()
    for index in range(max((len(bucket) for bucket in buckets), default=0)):
        for bucket in buckets:
            if len(results) >= limit or index >= len(bucket) or bucket[index]["url"] in seen:
                continue
            seen.add(bucket[index]["url"])
            results.append(bucket[index])
    hydrated = []
    for index, item in enumerate(results):
        remaining = deadline - time.monotonic()
        if remaining < 0.25:
            hydrated.extend(results[index:])
            break
        host = item["community"]
        topic_id = int(item["topic_id"])
        try:
            response = httpx.get(
                f"https://{host}/t/{topic_id}.json",
                headers={"Accept": "application/json", "User-Agent": "ToolGateResearch/2.0"},
                timeout=min(2.0, remaining),
            )
            response.raise_for_status()
            posts = json_body(response, "Discourse").get("post_stream", {}).get("posts", [])
            opening = min(posts, key=lambda post: int(post.get("post_number") or 9999)) if posts else None
        except (httpx.HTTPError, ResearchError, TypeError, ValueError):
            opening = None
        if not opening:
            hydrated.append(item)
            continue
        opening_body = extract_html_text(opening.get("cooked") or opening.get("raw") or "", 6000)
        if not opening_body:
            hydrated.append(item)
            continue
        matched_excerpt = clean_text(item.get("snippet") or "", 1200)
        combined = opening_body
        if matched_excerpt and matched_excerpt.lower() not in opening_body.lower():
            combined = f"{opening_body}\nMatched reply excerpt: {matched_excerpt}"
        root_url = re.sub(r"/\d+$", "/1", item["url"])
        normalized = _normalize(
            item["title"], root_url, combined, "discourse",
            opening.get("created_at") or item.get("published_at"),
        )
        hydrated.append({
            **item, **(normalized or {}), "url": root_url,
            "reporter": clean_text(opening.get("username") or item.get("reporter") or "", 80),
            "post_number": 1,
            "document": f"Public Discourse topic ({host}): {item['title']}\nOpening post: {opening_body}"
            + (f"\nMatched reply excerpt: {matched_excerpt}" if matched_excerpt and matched_excerpt.lower() not in opening_body.lower() else ""),
        })
    return hydrated
