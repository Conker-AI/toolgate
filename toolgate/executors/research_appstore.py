"""Apple App Store review and catalog search."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import cast

import httpx

from toolgate.executors.research_base import (
    QUERY_STOP_WORDS,
    ResearchError,
    _normalize,
    topic_terms,
)
from toolgate.executors.research_text import clean_text


def _appstore_reviews(
    query: str, _source: str, limit: int, recency_days: int, timeout: float
) -> list[dict]:
    """Read recent reviews for one exact public Apple App Store application ID."""
    app_id = query.strip()
    if not re.fullmatch(r"[0-9]{5,15}", app_id):
        raise ResearchError("App Store review query must be one numeric application ID")
    response = httpx.get(
        f"https://itunes.apple.com/us/rss/customerreviews/id={app_id}/sortBy=mostRecent/json",
        headers={"User-Agent": "ToolGateResearch/2.0", "Accept": "application/json"},
        timeout=timeout,
    )
    response.raise_for_status()
    if len(response.content) > 1048576:
        raise ResearchError("App Store review response exceeded the safe size limit")
    try:
        entries = response.json().get("feed", {}).get("entry", [])
    except (TypeError, ValueError) as exc:
        raise ResearchError("App Store review response was malformed") from exc
    if isinstance(entries, dict):
        entries = [entries]
    cutoff = datetime.now(UTC) - timedelta(days=recency_days)
    results = []
    for entry in entries if isinstance(entries, list) else []:
        if len(results) >= limit or not isinstance(entry, dict):
            break
        rating = clean_text(
            cast(dict, entry.get("im:rating")).get("label")
            if isinstance(entry.get("im:rating"), dict)
            else "",
            2,
        )
        content = clean_text(
            cast(dict, entry.get("content")).get("label")
            if isinstance(entry.get("content"), dict)
            else "",
            6000,
        )
        title = clean_text(
            cast(dict, entry.get("title")).get("label")
            if isinstance(entry.get("title"), dict)
            else "",
            300,
        )
        updated = clean_text(
            cast(dict, entry.get("updated")).get("label")
            if isinstance(entry.get("updated"), dict)
            else "",
            80,
        )
        review_id = clean_text(
            cast(dict, entry.get("id")).get("label") if isinstance(entry.get("id"), dict) else "",
            40,
        )
        if not rating or not rating.isdigit() or int(rating) > 3 or not content or not updated:
            continue
        try:
            published = datetime.fromisoformat(updated.replace("Z", "+00:00")).astimezone(UTC)
        except ValueError:
            continue
        if published < cutoff or published > datetime.now(UTC) + timedelta(days=1):
            continue
        url = f"https://apps.apple.com/us/app/id{app_id}?see-all=reviews"
        if review_id:
            url = f"{url}&reviewId={review_id}"
        item = _normalize(
            title or f"App Store review ({rating}/5)",
            url,
            f"Rating: {rating}/5. {content}",
            "appstore_reviews",
            published.isoformat(),
        )
        if item:
            results.append(
                {
                    **item,
                    "rating": int(rating) if rating.isdigit() else None,
                    "document": f"Apple App Store customer review ({rating}/5): {title}\n{content}",
                    "recency_provenance": {
                        "provider": "apple_appstore_rss",
                        "field": "entry.updated",
                        "max_age_days": recency_days,
                    },
                }
            )
    return results


def _appstore_catalog(
    query: str, _source: str, limit: int, _recency_days: int, timeout: float
) -> list[dict]:
    """Resolve a bounded market query to public iOS app identities."""
    terms = set(topic_terms(query, QUERY_STOP_WORDS))
    if not terms:
        raise ResearchError("App Store catalog query needs a concrete market or workflow term")
    response = httpx.get(
        "https://itunes.apple.com/search",
        params={
            "term": query,
            "country": "us",
            "entity": "software",
            "limit": min(10, max(3, limit)),
        },
        headers={"Accept": "application/json"},
        timeout=timeout,
    )
    response.raise_for_status()
    if len(response.content) > 1048576:
        raise ResearchError("App Store catalog response exceeded the safe size limit")
    ranked: list[tuple[tuple[int, int, int], dict]] = []
    for row in response.json().get("results", []):
        app_id = str(row.get("trackId") or "")
        name = clean_text(row.get("trackName"), 160)
        description = clean_text(row.get("description"), 2400)
        genre = clean_text(row.get("primaryGenreName"), 80)
        if not re.fullmatch(r"[0-9]{5,15}", app_id) or not name:
            continue
        surface = clean_text(f"{name} {genre} {description}", 2800)
        overlap = len(terms & set(re.findall(r"[a-z0-9]+", surface.lower())))
        if overlap == 0:
            continue
        try:
            rating = max(0.0, min(5.0, float(row.get("averageUserRating") or 0)))
        except (TypeError, ValueError):
            rating = 0.0
        try:
            rating_count = max(0, int(row.get("userRatingCount") or 0))
        except (TypeError, ValueError):
            rating_count = 0
        url = f"https://apps.apple.com/us/app/id{app_id}"
        snippet = clean_text(
            f"Category: {genre}. Rating: {rating:.2f}/5 from {rating_count} ratings. {description}",
            2600,
        )
        item = _normalize(
            name, url, snippet, "appstore_catalog", row.get("currentVersionReleaseDate")
        )
        if not item:
            continue
        complaint_opportunity = int(max(0.0, 4.5 - rating) * 1000)
        ranked.append(
            (
                (overlap, complaint_opportunity, min(rating_count, 100000)),
                {
                    **item,
                    "app_id": app_id,
                    "product_name": name,
                    "rating": rating,
                    "rating_count": rating_count,
                    "genre": genre,
                    "catalog_provider": "apple_itunes_search",
                },
            )
        )
    ranked.sort(key=lambda value: value[0], reverse=True)
    return [item for _score, item in ranked[:limit]]
