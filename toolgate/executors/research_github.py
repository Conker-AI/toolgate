"""GitHub issue and repository search."""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta

import httpx

from toolgate.core import vault
from toolgate.executors.research_base import QUERY_STOP_WORDS, _normalize, json_body, topic_terms
from toolgate.executors.research_text import clean_text


def _github(query: str, _source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    created_after = (datetime.now(UTC) - timedelta(days=recency_days)).date().isoformat()
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "ToolGateResearch/2.0"}
    with contextlib.suppress(KeyError):
        headers["Authorization"] = f"Bearer {vault.get_key('GITHUB_TOKEN')}"
    request_args = {
        "params": {"q": f"{query} is:issue created:>={created_after}", "per_page": limit},
        "timeout": timeout,
    }
    response = httpx.get("https://api.github.com/search/issues", headers=headers, **request_args)
    if response.status_code == 401 and "Authorization" in headers:
        public_headers = {name: value for name, value in headers.items() if name != "Authorization"}
        response = httpx.get(
            "https://api.github.com/search/issues", headers=public_headers, **request_args
        )
    response.raise_for_status()
    rows = json_body(response, "GitHub").get("items", [])
    results = []
    for row in rows[:limit]:
        body = clean_text(row.get("body") or "", 6000)
        item = _normalize(
            row.get("title"), row.get("html_url"), body, "github", row.get("created_at")
        )
        if item:
            results.append(
                {**item, "document": f"GitHub issue: {item['title']}\nIssue body: {body}"}
            )
    return results


def _github_repositories(
    query: str, _source: str, limit: int, recency_days: int, timeout: float
) -> list[dict]:
    """Search active public repositories as product landscape, never pain evidence."""
    pushed_after = (datetime.now(UTC) - timedelta(days=recency_days)).date().isoformat()
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "ToolGateResearch/2.0"}
    with contextlib.suppress(KeyError):
        headers["Authorization"] = f"Bearer {vault.get_key('GITHUB_TOKEN')}"
    terms = topic_terms(query, QUERY_STOP_WORDS)[:3]
    if not terms:
        return []
    request_args = {
        "params": {
            "q": f"{' '.join(terms)} in:name,description pushed:>={pushed_after} stars:>=5",
            "sort": "stars",
            "order": "desc",
            "per_page": limit,
        },
        "timeout": timeout,
    }
    response = httpx.get(
        "https://api.github.com/search/repositories", headers=headers, **request_args
    )
    if response.status_code == 401 and "Authorization" in headers:
        public_headers = {name: value for name, value in headers.items() if name != "Authorization"}
        response = httpx.get(
            "https://api.github.com/search/repositories", headers=public_headers, **request_args
        )
    response.raise_for_status()
    results = []
    for row in json_body(response, "GitHub").get("items", [])[:limit]:
        full_name = clean_text(row.get("full_name"), 160)
        description = clean_text(row.get("description") or "", 1200)
        topics = [
            clean_text(topic, 80) for topic in row.get("topics", [])[:12] if clean_text(topic, 80)
        ]
        stars = max(0, int(row.get("stargazers_count") or 0))
        license_value = row.get("license") if isinstance(row.get("license"), dict) else {}
        license_name = clean_text(license_value.get("spdx_id") or "unknown", 80)
        document = clean_text(
            f"GitHub repository: {full_name}\nDescription: {description}\n"
            f"Topics: {', '.join(topics)}\nStars: {stars}\nLicense: {license_name}",
            3500,
        )
        item = _normalize(
            f"GitHub - {full_name}: {description}",
            row.get("html_url"),
            description,
            "github_repositories",
            row.get("pushed_at") or row.get("updated_at"),
        )
        if item and full_name:
            results.append(
                {
                    **item,
                    "document": document,
                    "repository": full_name,
                    "stars": stars,
                    "license": license_name,
                }
            )
    return results
