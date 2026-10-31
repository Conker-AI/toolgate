"""General web search: SearXNG and Tavily, with community snapshots and Reddit feed dates."""
from __future__ import annotations

import contextlib
import re
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx

from toolgate.core import control_plane, tool_settings, vault
from toolgate.executors.research_base import (
    _PROVIDER_COOLDOWNS,
    GENERAL_EXCLUDED_DOMAINS,
    SOURCE_DOMAINS,
    ResearchError,
    _cooldown_provider,
    _normalize,
    _requested_site_domain,
    _require_provider_ready,
    json_body,
)
from toolgate.executors.research_text import clean_text, extract_html_text


def _community_snapshot(item: dict, source: str, timeout: float) -> dict:
    """Resolve known community pages through bounded public JSON APIs."""
    try:
        if source == "reddit" and item.get("snippet"):
            # SearXNG already returns a bounded public excerpt. Keeping that
            # snapshot avoids direct Reddit scraping and preserves the same
            # injection scanning and short-lived provenance boundary as APIs.
            published_at = item.get("published_at") or _reddit_rss_published_at(item["url"], min(timeout, 5))
            return {
                **item,
                "published_at": published_at,
                **({"recency_provenance": {"provider": "reddit_atom", "field": "entry.updated"}} if published_at else {}),
                "document": f"Reddit discussion excerpt: {item['title']}\n{clean_text(item['snippet'], 2400)}",
            }
        if source == "hackernews":
            match = re.search(r"[?&]id=(\d+)", item["url"])
            if not match:
                return item
            response = httpx.get(f"https://hn.algolia.com/api/v1/items/{match.group(1)}", timeout=timeout)
            response.raise_for_status()
            payload = json_body(response, "Hacker News")
            parts = [extract_html_text(payload.get("text") or "", 2400)]
            for child in payload.get("children", [])[:12]:
                parts.append(extract_html_text(child.get("text") or "", 800))
            discussion = clean_text("\n".join(part for part in parts if part), 6000)
            hydrated = dict(item)
            normalized = _normalize(
                item.get("title"), item.get("url"), item.get("snippet"), source,
                item.get("published_at") or payload.get("created_at"),
            )
            if normalized and normalized.get("published_at"):
                hydrated.update({
                    "published_at": normalized["published_at"],
                    "recency_provenance": {"provider": "hackernews_item", "field": "created_at"},
                })
            if discussion:
                hydrated["document"] = f"Hacker News discussion: {item['title']}\n{discussion}"
            return hydrated
        if source == "stackoverflow":
            match = re.search(r"/questions/(\d+)(?:/|$)", urlsplit(item["url"]).path)
            if not match:
                return item
            params = {"site": "stackoverflow", "filter": "withbody"}
            with contextlib.suppress(KeyError):
                params["key"] = vault.get_key("STACKEXCHANGE_KEY")
            response = httpx.get(f"https://api.stackexchange.com/2.3/questions/{match.group(1)}", params=params, timeout=timeout)
            response.raise_for_status()
            rows = json_body(response, "Stack Overflow").get("items", [])
            body = extract_html_text(rows[0].get("body") or "", 6000) if rows else ""
            if body:
                return {**item, "document": f"Stack Overflow question: {item['title']}\nQuestion body: {body}"}
    except (httpx.HTTPError, ResearchError, KeyError, TypeError, ValueError):
        return item
    return item


def _searx(query: str, source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    deadline = time.monotonic() + max(1.0, timeout)
    source_domain = SOURCE_DOMAINS[source]
    domain = source_domain or _requested_site_domain(query)
    scoped_query = f"site:{domain} {query}" if source_domain else query
    base_url = control_plane.settings().get("research_searxng_url", "http://toolgate-searxng:8080").rstrip("/")
    headers = {"Accept": "application/json"}
    # The bundled instance has no proxy in front of it and wants a client address; any other
    # instance sees ToolGate as it is, so its own rate limits still apply.
    if urlsplit(base_url).hostname == "toolgate-searxng":
        headers |= {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}
    response = httpx.get(
        f"{base_url}/search",
        params={"q": scoped_query, "format": "json", "language": tool_settings.search_language(),
                "safesearch": tool_settings.safe_search(), "categories": "general",
                **({"time_range": "day" if recency_days <= 1 else "month"} if recency_days <= 45 else {})},
        headers=headers,
        timeout=timeout,
    )
    response.raise_for_status()
    rows = json_body(response, "SearXNG").get("results", [])
    results = []
    for row in rows:
        if len(results) >= limit:
            break
        item = _normalize(row.get("title"), row.get("url"), row.get("content"), source, row.get("publishedDate"))
        hostname = urlsplit(item["url"]).hostname.lower() if item and urlsplit(item["url"]).hostname else ""
        if source == "general" and not domain and any(
            hostname == blocked or hostname.endswith(f".{blocked}")
            for blocked in GENERAL_EXCLUDED_DOMAINS
        ):
            continue
        if item and (not domain or hostname == domain or hostname.endswith(f".{domain}")):
            remaining = deadline - time.monotonic()
            results.append(
                _community_snapshot(item, source, min(1.5, remaining))
                if remaining >= 0.25 else item
            )
    return results


def _tavily(query: str, source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    raise ResearchError("Tavily is disabled until it has a bounded spending adapter; use SearXNG")


def _tavily_unmetered(query: str, source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    deadline = time.monotonic() + max(1.0, timeout)
    _require_provider_ready("tavily")
    token = vault.get_key("TAVILY_API_KEY")
    start_date = (datetime.now(UTC) - timedelta(days=recency_days)).date().isoformat()
    domain = SOURCE_DOMAINS[source] or _requested_site_domain(query)
    provider_options = (
        {"include_domains": [domain]}
        if domain else
        {"exclude_domains": sorted(GENERAL_EXCLUDED_DOMAINS)}
    )
    response = httpx.post(
        "https://api.tavily.com/search",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={
            "query": query,
            "search_depth": "basic",
            "max_results": limit,
            "topic": "general",
            "start_date": start_date,
            "include_answer": False,
            "include_raw_content": False,
            "include_images": False,
            **provider_options,
        },
        timeout=timeout,
    )
    if response.status_code == 429:
        _cooldown_provider("tavily", 15 * 60)
    elif response.status_code == 432:
        _cooldown_provider("tavily", 6 * 60 * 60)
    elif response.status_code in {401, 403}:
        _cooldown_provider("tavily", 60 * 60)
    response.raise_for_status()
    _PROVIDER_COOLDOWNS.pop("tavily", None)
    rows = json_body(response, "Tavily").get("results", [])
    results = []
    for row in rows[:limit]:
        extracted = clean_text(row.get("content") or "", 6000)
        published_at = row.get("published_date")
        remaining = deadline - time.monotonic()
        if source == "reddit" and not published_at and remaining >= 0.25:
            published_at = _reddit_rss_published_at(str(row.get("url") or ""), min(1.5, remaining))
        item = _normalize(
            row.get("title"), row.get("url"), extracted,
            source, published_at,
        )
        hostname = urlsplit(item["url"]).hostname.lower() if item and urlsplit(item["url"]).hostname else ""
        if item and (not domain or hostname == domain or hostname.endswith(f".{domain}")):
            normalized_result = {
                **item,
                "recency_provenance": {
                    "provider": "tavily",
                    "filter": "start_date",
                    "start_date": start_date,
                    "max_age_days": recency_days,
                },
                "document": f"Tavily extracted search content: {item['title']}\n{extracted}",
            }
            remaining = deadline - time.monotonic()
            results.append(
                _community_snapshot(normalized_result, source, min(1.5, remaining))
                if source in {"hackernews", "reddit", "stackoverflow"} and remaining >= 0.25
                else normalized_result
            )
    return results


def _reddit_rss_published_at(url: str, timeout: float) -> str | None:
    """Read the original post timestamp from Reddit's public Atom feed."""
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or hostname not in {"reddit.com", "www.reddit.com"} or "/comments/" not in parsed.path:
        return None
    feed_url = f"https://www.reddit.com{parsed.path.rstrip('/')}.rss"
    try:
        response = httpx.get(
            feed_url,
            headers={"User-Agent": "ToolGateResearch/2.0 (local owner-operated research)", "Accept": "application/atom+xml"},
            timeout=timeout,
        )
        response.raise_for_status()
        if len(response.content) > 262144:
            return None
        root = ET.fromstring(response.content)
        first_entry = root.find("{http://www.w3.org/2005/Atom}entry")
        if first_entry is None:
            return None
        updated = first_entry.findtext("{http://www.w3.org/2005/Atom}updated")
        if not updated:
            return None
        return datetime.fromisoformat(updated.replace("Z", "+00:00")).astimezone(UTC).isoformat()
    except (httpx.HTTPError, ET.ParseError, UnicodeError, ValueError, TypeError):
        return None
