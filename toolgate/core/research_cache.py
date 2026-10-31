"""Short-lived research results: what a search returned, so a fetch can only read those pages."""

import re
import secrets
from datetime import UTC, datetime

from toolgate.core.control_plane import _conn, _put, get


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
    """Delete expired results on one connection, reading only each row's expiry, not its page."""
    cutoff = now or datetime.now(UTC)
    with _conn() as conn:
        rows = conn.execute(
            "SELECT id, json_extract(body, '$.expires_at') FROM v2_objects"
            " WHERE kind='research_result'"
        ).fetchall()
        expired = [(row[0],) for row in rows if _expired(row[1], cutoff)]
        return conn.executemany(
            "DELETE FROM v2_objects WHERE kind='research_result' AND id=?", expired
        ).rowcount


def _expired(expires_at, cutoff: datetime) -> bool:
    try:
        return datetime.fromisoformat(expires_at) <= cutoff
    except (TypeError, ValueError):
        return True
