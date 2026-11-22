"""Stack Overflow and Stack Exchange search."""

from __future__ import annotations

import contextlib
import re
from datetime import UTC, datetime, timedelta

import httpx

from toolgate.core import vault
from toolgate.executors.research_base import (
    STACKEXCHANGE_QUERY_STOP_WORDS,
    ResearchError,
    _normalize,
    json_body,
)
from toolgate.executors.research_text import extract_html_text


def _stackoverflow(
    query: str, _source: str, limit: int, recency_days: int, timeout: float
) -> list[dict]:
    params = {
        "q": query,
        "site": "stackoverflow",
        "sort": "relevance",
        "order": "desc",
        "pagesize": limit,
        "fromdate": int((datetime.now(UTC) - timedelta(days=recency_days)).timestamp()),
        "filter": "withbody",
    }
    with contextlib.suppress(KeyError):
        params["key"] = vault.get_key("STACKEXCHANGE_KEY")
    response = httpx.get(
        "https://api.stackexchange.com/2.3/search/advanced",
        params=params,
        timeout=timeout,
    )
    response.raise_for_status()
    rows = json_body(response, "Stack Overflow").get("items", [])
    results = []
    for row in rows[:limit]:
        body = extract_html_text(row.get("body") or "", 6000)
        item = _normalize(
            row.get("title"), row.get("link"), body, "stackoverflow", row.get("creation_date")
        )
        if item:
            results.append(
                {
                    **item,
                    "document": f"Stack Overflow question: {item['title']}\nQuestion body: {body}",
                }
            )
    return results


def _stackexchange_sites(query: str) -> tuple[str, ...]:
    terms = set(re.findall(r"[a-z0-9]+", query.lower()))
    if terms & {"accounting", "bookkeeping", "invoice", "invoices", "receipt", "receipts", "tax"}:
        return ("money", "freelancing", "webapps")
    if terms & {"crm", "lead", "leads", "sales", "salesforce"}:
        return ("salesforce", "webapps", "softwareengineering")
    if terms & {"inventory", "orders", "retail", "shop", "store"}:
        return ("magento", "webapps", "softwareengineering")
    if terms & {"ai", "eval", "evaluation", "llm", "model", "prompt", "rag"}:
        return ("ai", "datascience", "softwareengineering")
    if terms & {"auth", "compliance", "credential", "oauth", "permission", "secret", "security"}:
        return ("security", "serverfault", "devops")
    if terms & {"ci", "deploy", "deployment", "infrastructure", "rollback", "server"}:
        return ("devops", "serverfault", "softwareengineering")
    return ("softwareengineering", "webapps", "superuser")


def _stackexchange(
    query: str, _source: str, limit: int, recency_days: int, timeout: float
) -> list[dict]:
    """Search a bounded set of relevant Stack Exchange communities."""
    terms = [
        term
        for term in dict.fromkeys(re.findall(r"[a-z0-9]+", query.lower()))
        if len(term) >= 2 and term not in STACKEXCHANGE_QUERY_STOP_WORDS
    ]
    focused_query = " ".join(terms[:2]) or query
    base_params = {
        "q": focused_query,
        "sort": "relevance",
        "order": "desc",
        "pagesize": min(8, max(2, limit)),
        "fromdate": int((datetime.now(UTC) - timedelta(days=recency_days)).timestamp()),
        "filter": "withbody",
    }
    with contextlib.suppress(KeyError):
        base_params["key"] = vault.get_key("STACKEXCHANGE_KEY")
    buckets: list[list[dict]] = []
    last_error: Exception | None = None
    for site in _stackexchange_sites(query):
        try:
            response = httpx.get(
                "https://api.stackexchange.com/2.3/search/advanced",
                params={**base_params, "site": site},
                timeout=timeout,
            )
            response.raise_for_status()
            payload = json_body(response, "Stack Exchange")
        except (httpx.HTTPError, ResearchError) as exc:
            last_error = exc
            continue
        site_rows = []
        for row in payload.get("items", []):
            body = extract_html_text(row.get("body") or "", 6000)
            item = _normalize(
                row.get("title"), row.get("link"), body, "stackexchange", row.get("creation_date")
            )
            if item:
                site_rows.append(
                    {
                        **item,
                        "community": site,
                        "document": f"Stack Exchange question ({site}): {item['title']}\nQuestion body: {body}",
                    }
                )
        buckets.append(site_rows)
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
    return results
