"""Sites with their own APIs: GitHub, Stack Exchange, app stores, YouTube and Product Hunt."""
from __future__ import annotations

import contextlib
import re
from datetime import UTC, datetime, timedelta

import httpx

from toolgate.core import control_plane, vault
from toolgate.executors.research_base import (
    QUERY_STOP_WORDS,
    STACKEXCHANGE_QUERY_STOP_WORDS,
    ResearchError,
    _normalize,
)
from toolgate.executors.research_text import clean_text, extract_html_text


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
        response = httpx.get("https://api.github.com/search/issues", headers=public_headers, **request_args)
    response.raise_for_status()
    rows = response.json().get("items", [])
    results = []
    for row in rows[:limit]:
        body = clean_text(row.get("body") or "", 6000)
        item = _normalize(row.get("title"), row.get("html_url"), body, "github", row.get("created_at"))
        if item:
            results.append({**item, "document": f"GitHub issue: {item['title']}\nIssue body: {body}"})
    return results


def _github_repositories(query: str, _source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    """Search active public repositories as product landscape, never pain evidence."""
    pushed_after = (datetime.now(UTC) - timedelta(days=recency_days)).date().isoformat()
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "ToolGateResearch/2.0"}
    with contextlib.suppress(KeyError):
        headers["Authorization"] = f"Bearer {vault.get_key('GITHUB_TOKEN')}"
    terms = [
        term for term in dict.fromkeys(re.findall(r"[a-z0-9]+", query.lower()))
        if len(term) >= 3 and term not in QUERY_STOP_WORDS
    ][:3]
    if not terms:
        return []
    request_args = {
        "params": {
            "q": f"{' '.join(terms)} in:name,description pushed:>={pushed_after} stars:>=5",
            "sort": "stars", "order": "desc", "per_page": limit,
        },
        "timeout": timeout,
    }
    response = httpx.get("https://api.github.com/search/repositories", headers=headers, **request_args)
    if response.status_code == 401 and "Authorization" in headers:
        public_headers = {name: value for name, value in headers.items() if name != "Authorization"}
        response = httpx.get("https://api.github.com/search/repositories", headers=public_headers, **request_args)
    response.raise_for_status()
    results = []
    for row in response.json().get("items", [])[:limit]:
        full_name = clean_text(row.get("full_name"), 160)
        description = clean_text(row.get("description") or "", 1200)
        topics = [clean_text(topic, 80) for topic in row.get("topics", [])[:12] if clean_text(topic, 80)]
        stars = max(0, int(row.get("stargazers_count") or 0))
        license_name = clean_text((row.get("license") or {}).get("spdx_id") or "unknown", 80)
        document = clean_text(
            f"GitHub repository: {full_name}\nDescription: {description}\n"
            f"Topics: {', '.join(topics)}\nStars: {stars}\nLicense: {license_name}",
            3500,
        )
        item = _normalize(
            f"GitHub - {full_name}: {description}", row.get("html_url"), description,
            "github_repositories", row.get("pushed_at") or row.get("updated_at"),
        )
        if item and full_name:
            results.append({
                **item, "document": document, "repository": full_name,
                "stars": stars, "license": license_name,
            })
    return results


def _stackoverflow(query: str, _source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    params = {"q": query, "site": "stackoverflow", "sort": "relevance", "order": "desc", "pagesize": limit,
              "fromdate": int((datetime.now(UTC) - timedelta(days=recency_days)).timestamp()),
              "filter": "withbody"}
    with contextlib.suppress(KeyError):
        params["key"] = vault.get_key("STACKEXCHANGE_KEY")
    response = httpx.get(
        "https://api.stackexchange.com/2.3/search/advanced",
        params=params,
        timeout=timeout,
    )
    response.raise_for_status()
    rows = response.json().get("items", [])
    results = []
    for row in rows[:limit]:
        body = extract_html_text(row.get("body") or "", 6000)
        item = _normalize(row.get("title"), row.get("link"), body, "stackoverflow", row.get("creation_date"))
        if item:
            results.append({**item, "document": f"Stack Overflow question: {item['title']}\nQuestion body: {body}"})
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


def _stackexchange(query: str, _source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    """Search a bounded set of relevant Stack Exchange communities."""
    terms = [
        term for term in dict.fromkeys(re.findall(r"[a-z0-9]+", query.lower()))
        if len(term) >= 2 and term not in STACKEXCHANGE_QUERY_STOP_WORDS
    ]
    focused_query = " ".join(terms[:2]) or query
    base_params = {
        "q": focused_query, "sort": "relevance", "order": "desc",
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
                params={**base_params, "site": site}, timeout=timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            last_error = exc
            continue
        site_rows = []
        for row in response.json().get("items", []):
            body = extract_html_text(row.get("body") or "", 6000)
            item = _normalize(row.get("title"), row.get("link"), body, "stackexchange", row.get("creation_date"))
            if item:
                site_rows.append({
                    **item, "community": site,
                    "document": f"Stack Exchange question ({site}): {item['title']}\nQuestion body: {body}",
                })
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


def _appstore_reviews(query: str, _source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
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
        rating = clean_text(entry.get("im:rating", {}).get("label"), 2)
        content = clean_text(entry.get("content", {}).get("label"), 6000)
        title = clean_text(entry.get("title", {}).get("label"), 300)
        updated = clean_text(entry.get("updated", {}).get("label"), 80)
        review_id = clean_text(entry.get("id", {}).get("label"), 40)
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
            title or f"App Store review ({rating}/5)", url,
            f"Rating: {rating}/5. {content}", "appstore_reviews", published.isoformat(),
        )
        if item:
            results.append({
                **item,
                "rating": int(rating) if rating.isdigit() else None,
                "document": f"Apple App Store customer review ({rating}/5): {title}\n{content}",
                "recency_provenance": {
                    "provider": "apple_appstore_rss", "field": "entry.updated",
                    "max_age_days": recency_days,
                },
            })
    return results


def _appstore_catalog(query: str, _source: str, limit: int, _recency_days: int, timeout: float) -> list[dict]:
    """Resolve a bounded market query to public iOS app identities."""
    terms = {
        term for term in re.findall(r"[a-z0-9]+", query.lower())
        if len(term) >= 3 and term not in QUERY_STOP_WORDS
    }
    if not terms:
        raise ResearchError("App Store catalog query needs a concrete market or workflow term")
    response = httpx.get(
        "https://itunes.apple.com/search",
        params={
            "term": query, "country": "us", "entity": "software",
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
        item = _normalize(name, url, snippet, "appstore_catalog", row.get("currentVersionReleaseDate"))
        if not item:
            continue
        complaint_opportunity = int(max(0.0, 4.5 - rating) * 1000)
        ranked.append(((overlap, complaint_opportunity, min(rating_count, 100000)), {
            **item,
            "app_id": app_id,
            "product_name": name,
            "rating": rating,
            "rating_count": rating_count,
            "genre": genre,
            "catalog_provider": "apple_itunes_search",
        }))
    ranked.sort(key=lambda value: value[0], reverse=True)
    return [item for _score, item in ranked[:limit]]


def _youtube(query: str, _source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    api_key = vault.get_key("GOOGLE_API_KEY")
    published_after = (datetime.now(UTC) - timedelta(days=recency_days)).isoformat().replace("+00:00", "Z")
    query_terms = [
        term for term in re.findall(r"[a-z0-9]+", query.lower())
        if len(term) >= 3 and term not in QUERY_STOP_WORDS and term not in {"comments", "frustrating"}
    ]
    focused_query = " ".join(dict.fromkeys(query_terms))[:120] or query
    search_response = httpx.get(
        "https://www.googleapis.com/youtube/v3/search",
        params={
            "key": api_key, "part": "snippet", "type": "video", "q": focused_query,
            "publishedAfter": published_after, "order": "relevance", "maxResults": min(5, max(1, limit)),
            "safeSearch": "moderate", "relevanceLanguage": "en",
        },
        timeout=timeout,
    )
    search_response.raise_for_status()
    videos = search_response.json().get("items", [])
    ranked: list[tuple[int, dict]] = []
    comments_per_video = min(20, max(5, (limit * 2 + max(len(videos), 1) - 1) // max(len(videos), 1)))
    for video in videos:
        video_id = str(video.get("id", {}).get("videoId") or "")
        video_title = clean_text(video.get("snippet", {}).get("title"), 240)
        if not re.fullmatch(r"[A-Za-z0-9_-]{11}", video_id):
            continue
        try:
            comments_response = httpx.get(
                "https://www.googleapis.com/youtube/v3/commentThreads",
                params={
                    "key": api_key, "part": "snippet", "videoId": video_id,
                    "maxResults": comments_per_video, "order": "relevance", "textFormat": "plainText",
                },
                timeout=timeout,
            )
            comments_response.raise_for_status()
        except httpx.HTTPError:
            continue
        for wrapper in comments_response.json().get("items", []):
            top_level = wrapper.get("snippet", {}).get("topLevelComment", {})
            comment_id = str(top_level.get("id") or "")
            snippet = top_level.get("snippet", {})
            comment = clean_text(snippet.get("textOriginal") or snippet.get("textDisplay"), 2400)
            if not comment or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", comment_id):
                continue
            likes = max(0, int(snippet.get("likeCount") or 0))
            url = f"https://www.youtube.com/watch?v={video_id}&lc={comment_id}"
            document = clean_text(f"Video: {video_title}\nViewer comment: {comment}\nComment likes: {likes}", 3500)
            item = _normalize(
                f"{video_title} - viewer comment", url, comment, "youtube",
                snippet.get("publishedAt") or snippet.get("updatedAt"),
            )
            if item:
                ranked.append((likes, {**item, "document": document}))
    ranked.sort(key=lambda value: value[0], reverse=True)
    return [item for _likes, item in ranked[:limit]]


def _producthunt(query: str, _source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    if not control_plane.settings().get("producthunt_commercial_use_approved", False):
        raise ResearchError("Product Hunt API business-use approval has not been confirmed")
    token = vault.get_key("PRODUCTHUNT_TOKEN")
    terms = [
        term for term in dict.fromkeys(re.findall(r"[a-z0-9]+", query.lower()))
        if len(term) >= 3 and term not in QUERY_STOP_WORDS
    ][:4]
    if not terms:
        raise ResearchError("Product Hunt query has no useful topic terms")
    endpoint = "https://api.producthunt.com/v2/api/graphql"
    headers = {"Accept": "application/json", "Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    topic_variables = {f"q{index}": term for index, term in enumerate(terms)}
    topic_declarations = ", ".join(f"$q{index}: String!" for index in range(len(terms)))
    topic_fields = " ".join(
        f"t{index}: topics(first: 3, query: $q{index}) {{ nodes {{ name slug }} }}"
        for index in range(len(terms))
    )
    topic_response = httpx.post(
        endpoint,
        headers=headers,
        json={"query": f"query FindTopics({topic_declarations}) {{ {topic_fields} }}", "variables": topic_variables},
        timeout=timeout,
    )
    topic_response.raise_for_status()
    topic_payload = topic_response.json()
    if topic_payload.get("errors"):
        raise ResearchError("Product Hunt topic lookup returned a GraphQL error")
    topics: list[dict] = []
    seen_slugs: set[str] = set()
    for index in range(len(terms)):
        for topic in topic_payload.get("data", {}).get(f"t{index}", {}).get("nodes", []):
            slug = clean_text(topic.get("slug"), 100)
            if slug and slug not in seen_slugs:
                seen_slugs.add(slug)
                topics.append({"slug": slug, "name": clean_text(topic.get("name"), 120)})
            if len(topics) >= 4:
                break
        if len(topics) >= 4:
            break
    if not topics:
        return []

    product_variables = {
        "after": (datetime.now(UTC) - timedelta(days=recency_days)).isoformat(),
        **{f"topic{index}": topic["slug"] for index, topic in enumerate(topics)},
    }
    product_declarations = ", ".join(
        ["$after: DateTime!", *(f"$topic{index}: String!" for index in range(len(topics)))]
    )
    product_fields = " ".join(
        f"p{index}: posts(first: 20, topic: $topic{index}, postedAfter: $after, order: VOTES) "
        "{ nodes { id name slug tagline description url createdAt votesCount } }"
        for index in range(len(topics))
    )
    product_response = httpx.post(
        endpoint,
        headers=headers,
        json={"query": f"query TopicProducts({product_declarations}) {{ {product_fields} }}", "variables": product_variables},
        timeout=timeout,
    )
    product_response.raise_for_status()
    product_payload = product_response.json()
    if product_payload.get("errors"):
        raise ResearchError("Product Hunt product lookup returned a GraphQL error")

    ranked: list[tuple[int, dict]] = []
    seen_products: set[str] = set()
    query_terms = set(terms)
    for index, topic in enumerate(topics):
        for row in product_payload.get("data", {}).get(f"p{index}", {}).get("nodes", []):
            product_id = str(row.get("id") or row.get("slug") or "")
            if not product_id or product_id in seen_products:
                continue
            seen_products.add(product_id)
            haystack = clean_text(f"{row.get('name', '')} {row.get('tagline', '')} {row.get('description', '')}", 2400).lower()
            overlap = len(query_terms & set(re.findall(r"[a-z0-9]+", haystack)))
            if not overlap and topic.get("name", "").lower() not in haystack:
                continue
            snippet = f"{row.get('tagline', '')}\n{row.get('description', '')}\nProduct Hunt votes: {int(row.get('votesCount') or 0)}"
            item = _normalize(row.get("name"), row.get("url"), snippet, "producthunt", row.get("createdAt"))
            if item:
                ranked.append((overlap * 100000 + int(row.get("votesCount") or 0), {
                    **item,
                    "document": f"Product Hunt product: {item['title']}\n{clean_text(snippet, 6000)}",
                }))
    ranked.sort(key=lambda value: value[0], reverse=True)
    return [item for _score, item in ranked[:limit]]
