"""Shared research pieces: errors, provider cooldowns, source constants, URL safety,
result normalization, and fetching pages by their short-lived handles."""
from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

import httpx

from toolgate.core import control_plane, research_cache
from toolgate.core.public_https import public_client, public_url
from toolgate.executors.research_text import (
    clean_text,
    extract_html_text,
    extract_published_metadata,
    inspect_text,
)


class ResearchError(RuntimeError):
    """A safe, owner-readable research failure."""


_PROVIDER_COOLDOWNS: dict[str, float] = {}


def _require_provider_ready(provider: str) -> None:
    blocked_until = _PROVIDER_COOLDOWNS.get(provider, 0)
    if blocked_until <= time.monotonic():
        _PROVIDER_COOLDOWNS.pop(provider, None)
        return
    raise ResearchError(f"{provider} is temporarily unavailable after an upstream quota or authentication failure")


def _cooldown_provider(provider: str, seconds: int) -> None:
    _PROVIDER_COOLDOWNS[provider] = max(
        _PROVIDER_COOLDOWNS.get(provider, 0), time.monotonic() + max(1, seconds),
    )


SOURCE_DOMAINS = {
    "appstore_catalog": "apps.apple.com",
    "appstore_reviews": "apps.apple.com",
    "discourse": None,
    "general": None,
    "reddit": "reddit.com",
    "hackernews": "news.ycombinator.com",
    "github": "github.com",
    "github_repositories": "github.com",
    "producthunt": "producthunt.com",
    "stackexchange": "stackexchange.com",
    "stackoverflow": "stackoverflow.com",
    "youtube": "youtube.com",
}


DISCOURSE_HOSTS = ("community.make.com", "community.n8n.io", "forum.bubble.io", "forum.manager.io")


GENERAL_EXCLUDED_DOMAINS = {"reddit.com"}


QUERY_STOP_WORDS = {
    "and", "business", "businesses", "company", "companies", "email", "for", "frustrating",
    "independent", "manual", "problem", "problems", "recommendations", "small",
    "software", "spreadsheet", "spreadsheets", "team", "teams", "the", "tool", "tools",
    "workflow", "workflows",
}


REDDIT_QUERY_STOP_WORDS = QUERY_STOP_WORDS - {
    "business", "businesses", "manual", "spreadsheet", "spreadsheets", "workflow", "workflows",
}


STACKEXCHANGE_QUERY_STOP_WORDS = QUERY_STOP_WORDS - {
    "spreadsheet", "spreadsheets", "workflow", "workflows",
}


REDDIT_FEED_ALLOWLIST = {
    "accounting", "askphotography", "autodetailing", "bookkeeping", "commercialcleaning",
    "construction", "creatorservices", "customersuccess", "cybersecurity", "doggrooming",
    "ecommerce", "fitness", "franchising", "freelance", "heavyequipment", "homeinspectors",
    "hvac", "landlord", "landscaping", "logistics", "machinists", "mechanicadvice",
    "msp", "musicteachers", "nonprofit", "procurement", "propertymanagement", "recruiting",
    "rentalproperty", "restaurantowners", "saas", "salesops", "selfstorage", "smallbusiness",
    "solar", "supplychain", "tutoring", "warehouse", "weddingphotography", "weddingplanning",
}


def _public_https_url(url: str) -> bool:
    return public_url(url)


def _normalize(title: object, url: object, snippet: object, source: str, published_at: object = None) -> dict | None:
    target = str(url or "").strip()
    if not _public_https_url(target):
        return None
    raw_title = str(title or "")
    raw_snippet = str(snippet or "")
    safe_title = (extract_html_text(raw_title, 300) if re.search(r"<[a-z][^>]*>", raw_title, re.I) else clean_text(raw_title, 300)) or urlsplit(target).hostname or "Untitled result"
    safe_snippet = extract_html_text(raw_snippet, 1200) if re.search(r"<[a-z][^>]*>", raw_snippet, re.I) else clean_text(raw_snippet, 1200)
    inspection = inspect_text(f"{safe_title}\n{safe_snippet}")
    normalized_published_at = None
    if isinstance(published_at, (int, float)) and not isinstance(published_at, bool):
        try:
            normalized_published_at = datetime.fromtimestamp(float(published_at), UTC).isoformat()
        except (OSError, OverflowError, ValueError):
            normalized_published_at = None
    else:
        raw_published_at = clean_text(published_at, 80)
        if raw_published_at and re.fullmatch(r"\d{9,13}(?:\.\d+)?", raw_published_at):
            try:
                epoch = float(raw_published_at)
                if epoch > 10_000_000_000:
                    epoch /= 1000
                normalized_published_at = datetime.fromtimestamp(epoch, UTC).isoformat()
            except (OSError, OverflowError, ValueError):
                normalized_published_at = None
        else:
            normalized_published_at = raw_published_at or None
    return {
        "title": safe_title,
        "url": target,
        "snippet": safe_snippet,
        "source": source,
        "published_at": normalized_published_at,
        "content_safety": inspection,
    }


def _requested_site_domain(query: str) -> str | None:
    match = re.search(r"(?:^|\s)site:([a-z0-9.-]{4,253})(?=[/\s]|$)", query.lower())
    if not match:
        return None
    domain = match.group(1).strip(".")
    if (
        "." not in domain or ".." in domain
        or domain in {"localhost", "localhost.localdomain"}
        or re.fullmatch(r"[0-9.]+", domain)
    ):
        return None
    return domain


def fetch(result_id: str, max_chars: int = 12000) -> dict:
    record = research_cache.get_research_result(result_id)
    if not record:
        raise ResearchError("research result handle was not found")
    try:
        if datetime.fromisoformat(record["expires_at"]) <= datetime.now(UTC):
            raise ResearchError("research result handle has expired")
    except (KeyError, ValueError, TypeError) as exc:
        raise ResearchError("research result handle is invalid") from exc

    snapshot = record.get("document")
    if snapshot:
        limit = min(max(int(max_chars), 1000), 20000)
        text = (
            extract_html_text(snapshot, limit)
            if re.search(r"<[a-z][^>]*>", str(snapshot), re.I)
            else clean_text(snapshot, limit)
        )
        inspection = inspect_text(text)
        if inspection["risk"] == "high":
            control_plane.event("research_content_blocked", "warning", "research_result", result_id, "research_fetch", inspection)
            return {
                "result_id": result_id, "blocked": True, "content_safety": inspection,
                "content": "", "notice": "Content was withheld because it contained instruction-like or exfiltration-like text.",
            }
        return {
            "result_id": result_id, "blocked": False, "source": record.get("source"),
            "title": record.get("title"), "url": record.get("url"), "content_safety": inspection,
            "published_at": record.get("published_at"), "recency_provenance": record.get("recency_provenance"),
            "content_stats": {"received_bytes": 0, "model_characters": len(text), "snapshot": True},
            "content": f"[UNTRUSTED_WEB_CONTENT id={result_id}]\n{text}\n[/UNTRUSTED_WEB_CONTENT]",
        }

    url = record["url"]
    if not _public_https_url(url):
        raise ResearchError("cached destination is no longer a safe public HTTPS URL")
    headers = {"User-Agent": "ToolGateResearch/2.0", "Accept": "text/html,text/plain,application/json"}
    content_type = ""
    body = bytearray()
    try:
        with public_client(timeout=15, headers=headers) as client:
            current_url = url
            for redirect_count in range(4):
                with client.stream("GET", current_url) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        if redirect_count == 3:
                            raise ResearchError("upstream exceeded the redirect limit")
                        target = urljoin(str(response.url), response.headers.get("location", ""))
                        if not _public_https_url(target):
                            raise ResearchError("upstream redirect left the safe public HTTPS boundary")
                        current_url = target
                        continue
                    response.raise_for_status()
                    content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
                    if content_type not in {"text/html", "text/plain", "application/json", "application/ld+json"}:
                        raise ResearchError(f"unsupported research content type: {content_type or 'unknown'}")
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > 524288:
                            raise ResearchError("research page exceeded the 512 KiB decompressed response limit")
                    encoding = response.encoding or "utf-8"
                    break
    except httpx.HTTPError as exc:
        raise ResearchError(f"research page fetch failed: {type(exc).__name__}") from exc
    raw = bytes(body).decode(encoding, errors="replace")
    published_at = record.get("published_at")
    recency_provenance = record.get("recency_provenance")
    if content_type == "text/html" and not published_at:
        published_at, recency_provenance = extract_published_metadata(raw)
    if content_type == "text/html":
        text = extract_html_text(raw, min(max(int(max_chars), 1000), 20000))
    else:
        text = clean_text(raw, min(max(int(max_chars), 1000), 20000))
    inspection = inspect_text(text)
    if inspection["risk"] == "high":
        control_plane.event("research_content_blocked", "warning", "research_result", result_id, "research_fetch", inspection)
        return {
            "result_id": result_id,
            "blocked": True,
            "content_safety": inspection,
            "content": "",
            "notice": "Content was withheld because it contained instruction-like or exfiltration-like text.",
        }
    return {
        "result_id": result_id,
        "blocked": False,
        "source": record.get("source"),
        "title": record.get("title"),
        "url": record.get("url"),
        "published_at": published_at,
        "recency_provenance": recency_provenance,
        "content_safety": inspection,
        "content_stats": {"received_bytes": len(body), "model_characters": len(text)},
        "content": f"[UNTRUSTED_WEB_CONTENT id={result_id}]\n{text}\n[/UNTRUSTED_WEB_CONTENT]",
    }


def fetch_batch(result_ids: list[str], max_chars: int = 3500) -> dict:
    if not isinstance(result_ids, list) or not 1 <= len(result_ids) <= 8:
        raise ResearchError("research batch must contain 1 to 8 result handles")
    documents = []
    for result_id in result_ids:
        try:
            documents.append(fetch(result_id, max_chars))
        except ResearchError as exc:
            documents.append({
                "result_id": result_id,
                "blocked": True,
                "content": "",
                "error": str(exc)[:240],
                "notice": "This result was withheld; other batch results remain usable.",
            })
    return {"documents": documents, "result_count": len(documents)}
