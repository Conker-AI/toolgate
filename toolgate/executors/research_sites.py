"""Sites with their own APIs: YouTube and Product Hunt.

GitHub, Stack Exchange and App Store search live in research_github, research_stackexchange and
research_appstore; their names are re-exported here for callers.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import httpx

from toolgate.core import control_plane, vault
from toolgate.executors.research_appstore import _appstore_catalog, _appstore_reviews  # noqa: F401
from toolgate.executors.research_base import (
    QUERY_STOP_WORDS,
    ResearchError,
    _normalize,
    json_body,
    topic_terms,
)
from toolgate.executors.research_github import _github, _github_repositories  # noqa: F401
from toolgate.executors.research_stackexchange import (  # noqa: F401
    _stackexchange,
    _stackexchange_sites,
    _stackoverflow,
)
from toolgate.executors.research_text import clean_text


def _youtube(query: str, _source: str, limit: int, recency_days: int, timeout: float) -> list[dict]:
    # In a header, never the URL: URLs reach httpx's request log and every HTTPStatusError text.
    key_header = {"X-Goog-Api-Key": vault.get_key("GOOGLE_API_KEY")}
    published_after = (
        (datetime.now(UTC) - timedelta(days=recency_days)).isoformat().replace("+00:00", "Z")
    )
    query_terms = [
        term
        for term in re.findall(r"[a-z0-9]+", query.lower())
        if len(term) >= 3
        and term not in QUERY_STOP_WORDS
        and term not in {"comments", "frustrating"}
    ]
    focused_query = " ".join(dict.fromkeys(query_terms))[:120] or query
    search_response = httpx.get(
        "https://www.googleapis.com/youtube/v3/search",
        params={
            "part": "snippet",
            "type": "video",
            "q": focused_query,
            "publishedAfter": published_after,
            "order": "relevance",
            "maxResults": min(5, max(1, limit)),
            "safeSearch": "moderate",
            "relevanceLanguage": "en",
        },
        headers=key_header,
        timeout=timeout,
    )
    search_response.raise_for_status()
    videos = json_body(search_response, "YouTube").get("items", [])
    ranked: list[tuple[int, dict]] = []
    comments_per_video = min(
        20, max(5, (limit * 2 + max(len(videos), 1) - 1) // max(len(videos), 1))
    )
    for video in videos:
        video_id_value = video.get("id") if isinstance(video.get("id"), dict) else {}
        video_id = str(video_id_value.get("videoId") or "")
        video_title = clean_text(video.get("snippet", {}).get("title"), 240)
        if not re.fullmatch(r"[A-Za-z0-9_-]{11}", video_id):
            continue
        try:
            comments_response = httpx.get(
                "https://www.googleapis.com/youtube/v3/commentThreads",
                params={
                    "part": "snippet",
                    "videoId": video_id,
                    "maxResults": comments_per_video,
                    "order": "relevance",
                    "textFormat": "plainText",
                },
                headers=key_header,
                timeout=timeout,
            )
            comments_response.raise_for_status()
            comment_rows = json_body(comments_response, "YouTube").get("items", [])
        except (httpx.HTTPError, ResearchError):
            continue
        for wrapper in comment_rows:
            if not isinstance(wrapper, dict):
                continue
            wrapper_snippet = wrapper.get("snippet", {})
            if not isinstance(wrapper_snippet, dict):
                continue
            top_level = wrapper_snippet.get("topLevelComment", {})
            if not isinstance(top_level, dict):
                continue
            comment_id = str(top_level.get("id") or "")
            snippet = top_level.get("snippet", {})
            if not isinstance(snippet, dict):
                continue
            comment = clean_text(snippet.get("textOriginal") or snippet.get("textDisplay"), 2400)
            if not comment or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", comment_id):
                continue
            likes = max(0, int(snippet.get("likeCount") or 0))
            url = f"https://www.youtube.com/watch?v={video_id}&lc={comment_id}"
            document = clean_text(
                f"Video: {video_title}\nViewer comment: {comment}\nComment likes: {likes}", 3500
            )
            item = _normalize(
                f"{video_title} - viewer comment",
                url,
                comment,
                "youtube",
                snippet.get("publishedAt") or snippet.get("updatedAt"),
            )
            if item:
                ranked.append((likes, {**item, "document": document}))
    ranked.sort(key=lambda value: value[0], reverse=True)
    return [item for _likes, item in ranked[:limit]]


def _producthunt(
    query: str, _source: str, limit: int, recency_days: int, timeout: float
) -> list[dict]:
    if not control_plane.settings().get("producthunt_commercial_use_approved", False):
        raise ResearchError("Product Hunt API business-use approval has not been confirmed")
    token = vault.get_key("PRODUCTHUNT_TOKEN")
    terms = topic_terms(query, QUERY_STOP_WORDS)[:4]
    if not terms:
        raise ResearchError("Product Hunt query has no useful topic terms")
    endpoint = "https://api.producthunt.com/v2/api/graphql"
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    topic_variables = {f"q{index}": term for index, term in enumerate(terms)}
    topic_declarations = ", ".join(f"$q{index}: String!" for index in range(len(terms)))
    topic_fields = " ".join(
        f"t{index}: topics(first: 3, query: $q{index}) {{ nodes {{ name slug }} }}"
        for index in range(len(terms))
    )
    topic_response = httpx.post(
        endpoint,
        headers=headers,
        json={
            "query": f"query FindTopics({topic_declarations}) {{ {topic_fields} }}",
            "variables": topic_variables,
        },
        timeout=timeout,
    )
    topic_response.raise_for_status()
    topic_payload = json_body(topic_response, "Product Hunt")
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
        json={
            "query": f"query TopicProducts({product_declarations}) {{ {product_fields} }}",
            "variables": product_variables,
        },
        timeout=timeout,
    )
    product_response.raise_for_status()
    product_payload = json_body(product_response, "Product Hunt")
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
            haystack = clean_text(
                f"{row.get('name', '')} {row.get('tagline', '')} {row.get('description', '')}", 2400
            ).lower()
            overlap = len(query_terms & set(re.findall(r"[a-z0-9]+", haystack)))
            if not overlap and topic.get("name", "").lower() not in haystack:
                continue
            snippet = f"{row.get('tagline', '')}\n{row.get('description', '')}\nProduct Hunt votes: {int(row.get('votesCount') or 0)}"
            item = _normalize(
                row.get("name"), row.get("url"), snippet, "producthunt", row.get("createdAt")
            )
            if item:
                ranked.append(
                    (
                        overlap * 100000 + int(row.get("votesCount") or 0),
                        {
                            **item,
                            "document": f"Product Hunt product: {item['title']}\n{clean_text(snippet, 6000)}",
                        },
                    )
                )
    ranked.sort(key=lambda value: value[0], reverse=True)
    return [item for _score, item in ranked[:limit]]
