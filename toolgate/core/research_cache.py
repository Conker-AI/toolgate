"""Short-lived research results: what a search returned, so a fetch can only read those pages."""

import re
import secrets
from datetime import UTC, datetime

from toolgate.core.control_plane import _put, get, list_objects, remove


def cache_research_result(result: dict, expires_at: str) -> dict:
    """Store a short-lived search result for provenance-bound page fetching."""
    result_id = "rr_" + secrets.token_urlsafe(18)
    return _put("research_result", result_id, {
        "title": result.get("title", ""),
        "url": result["url"],
        "source": result.get("source", "general"),
        "published_at": result.get("published_at"),
        "document": str(result.get("document", ""))[:20000] if result.get("document") else None,
        "expires_at": expires_at,
    })


def get_research_result(result_id: str) -> dict | None:
    if not isinstance(result_id, str) or not re.fullmatch(r"rr_[A-Za-z0-9_-]{20,40}", result_id):
        return None
    return get("research_result", result_id)


def purge_expired_research_results(now: datetime | None = None) -> int:
    cutoff = now or datetime.now(UTC)
    removed = 0
    for record in list_objects("research_result"):
        try:
            expired = datetime.fromisoformat(record["expires_at"]) <= cutoff
        except (KeyError, TypeError, ValueError):
            expired = True
        if expired and remove("research_result", record["id"]):
            removed += 1
    return removed
