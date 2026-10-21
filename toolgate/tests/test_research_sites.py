"""Research sites with their own APIs: GitHub, Stack Exchange, app stores, YouTube and Product Hunt."""

import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock, patch

from toolgate.api import builtin_capabilities
from toolgate.core import control_plane, research_cache
from toolgate.executors import (
    research,
    research_base,
    research_sites,
    research_web,
)


class ResearchSiteTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db = control_plane.DB_PATH
        control_plane.DB_PATH = Path(self.temp_dir.name) / "toolgate-test.db"

    def tearDown(self):
        control_plane.DB_PATH = self.original_db
        self.temp_dir.cleanup()


    def test_github_bad_token_retries_without_authentication(self):
        rejected = Mock(status_code=401)
        accepted = Mock(status_code=200)
        accepted.raise_for_status.return_value = None
        accepted.json.return_value = {"items": [{
            "title": "Manual reconciliation", "html_url": "https://github.com/example/repo/issues/1",
            "body": "CSV rows are reconciled manually.", "created_at": "2026-07-29T00:00:00Z",
        }]}
        with patch.object(research_web.vault, "get_key", return_value="bad-token"), \
             patch.object(research_base, "_public_https_url", return_value=True), \
             patch.object(research.httpx, "get", side_effect=[rejected, accepted]) as request:
            rows = research._github("CSV reconciliation", "github", 1, 365, 5)
        self.assertEqual(1, len(rows))
        self.assertIn("GitHub issue", rows[0]["document"])
        self.assertIn("Authorization", request.call_args_list[0].kwargs["headers"])
        self.assertNotIn("Authorization", request.call_args_list[1].kwargs["headers"])

    def test_github_repository_search_returns_explicit_product_landscape(self):
        response = Mock(status_code=200)
        response.raise_for_status.return_value = None
        response.json.return_value = {"items": [{
            "full_name": "acme/hook-debugger",
            "description": "Capture and replay failed webhooks",
            "html_url": "https://github.com/acme/hook-debugger",
            "pushed_at": "2026-07-20T00:00:00Z",
            "stargazers_count": 420,
            "topics": ["webhooks", "debugging"],
            "license": {"spdx_id": "MIT"},
        }]}
        with patch.object(research_web.vault, "get_key", return_value="private-token"), \
             patch.object(research.httpx, "get", return_value=response) as request:
            rows = research._github_repositories(
                "webhook replay debugging", "github_repositories", 5, 730, 5,
            )
        self.assertEqual("acme/hook-debugger", rows[0]["repository"])
        self.assertEqual(420, rows[0]["stars"])
        self.assertEqual("MIT", rows[0]["license"])
        self.assertIn("GitHub repository", rows[0]["document"])
        repository_query = request.call_args.kwargs["params"]["q"]
        self.assertIn("in:name,description", repository_query)
        self.assertNotIn("readme", repository_query)
        self.assertIn("stars:>=5", repository_query)

    def test_api_backed_research_results_include_bounded_snapshots(self):
        stack_response = Mock()
        stack_response.raise_for_status.return_value = None
        stack_response.json.return_value = {"items": [{
            "title": "Repeated API problem", "link": "https://stackoverflow.com/questions/1/example",
            "body": "<p>We manually repeat this integration every day.</p>", "creation_date": 1,
        }]}
        with patch.object(research_web.vault, "get_key", side_effect=KeyError), \
             patch.object(research_base, "_public_https_url", return_value=True), \
             patch.object(research.httpx, "get", return_value=stack_response):
            rows = research._stackoverflow("API integration", "stackoverflow", 1, 365, 5)
        self.assertIn("Stack Overflow question", rows[0]["document"])
        self.assertNotIn("<p>", rows[0]["document"])

    def test_stackexchange_search_balances_relevant_communities(self):
        responses = []
        for site in ("ai", "datascience", "softwareengineering"):
            response = Mock()
            response.raise_for_status.return_value = None
            response.json.return_value = {"items": [{
                "title": f"LLM evaluation problem on {site}",
                "link": f"https://{site}.stackexchange.com/questions/1/example",
                "body": "<p>We currently repeat model evaluation after regressions.</p>",
                "creation_date": 1,
            }]}
            responses.append(response)
        with patch.object(research_web.vault, "get_key", return_value="stack-key"), \
             patch.object(research.httpx, "get", side_effect=responses) as request:
            rows = research._stackexchange("llm evaluation regression", "stackexchange", 5, 365, 5)
        self.assertEqual(3, len(rows))
        self.assertEqual({"ai", "datascience", "softwareengineering"}, {row["community"] for row in rows})
        self.assertTrue(all("<p>" not in row["document"] for row in rows))
        self.assertTrue(all(call.kwargs["params"]["q"] == "llm evaluation" for call in request.call_args_list))

    def test_stackexchange_routes_business_workflows_to_relevant_sites(self):
        self.assertEqual(
            ("money", "freelancing", "webapps"),
            research_sites._stackexchange_sites("sole traders receipt invoice spreadsheet"),
        )
        self.assertEqual(
            ("salesforce", "webapps", "softwareengineering"),
            research_sites._stackexchange_sites("sales operations CRM lead import"),
        )

    def test_appstore_reviews_are_exact_bounded_and_dated(self):
        now = datetime.now(UTC).isoformat()
        response = Mock()
        response.raise_for_status.return_value = None
        response.content = b"{}"
        response.json.return_value = {"feed": {"entry": [
            {
                "im:rating": {"label": "2"},
                "title": {"label": "Scheduling keeps losing jobs"},
                "content": {"label": "We repeatedly lose scheduled jobs after dispatch changes."},
                "updated": {"label": now},
                "id": {"label": "review-123"},
            },
            {
                "im:rating": {"label": "5"},
                "title": {"label": "Perfect"},
                "content": {"label": "Everything works."},
                "updated": {"label": now},
                "id": {"label": "review-456"},
            },
        ]}}
        with patch.object(research.httpx, "get", return_value=response):
            rows = research._appstore_reviews("1014146758", "appstore_reviews", 5, 90, 5)
        self.assertEqual(1, len(rows))
        self.assertEqual(2, rows[0]["rating"])
        self.assertEqual("apple_appstore_rss", rows[0]["recency_provenance"]["provider"])
        self.assertIn("App Store customer review", rows[0]["document"])
        with self.assertRaises(research.ResearchError):
            research._appstore_reviews("https://evil.example", "appstore_reviews", 5, 90, 5)

    def test_appstore_catalog_is_bounded_and_returns_numeric_app_identity(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.content = b"{}"
        response.json.return_value = {"results": [{
            "trackId": 123456789,
            "trackName": "Field Dispatch",
            "primaryGenreName": "Business",
            "description": "Scheduling and dispatch for field service technicians.",
            "averageUserRating": 2.5,
            "userRatingCount": 120,
            "currentVersionReleaseDate": datetime.now(UTC).isoformat(),
        }]}
        with patch.object(research.httpx, "get", return_value=response):
            rows = research._appstore_catalog("field service dispatch", "appstore_catalog", 5, 3650, 5)
        self.assertEqual(1, len(rows))
        self.assertEqual("123456789", rows[0]["app_id"])
        self.assertEqual("Field Dispatch", rows[0]["product_name"])
        self.assertEqual("https://apps.apple.com/us/app/id123456789", rows[0]["url"])
        self.assertNotIn("description", rows[0])

    def test_youtube_search_returns_provenance_bound_comment_snapshots(self):
        videos = Mock()
        videos.raise_for_status.return_value = None
        videos.json.return_value = {"items": [{
            "id": {"videoId": "abcdefghijk"},
            "snippet": {"title": "Spreadsheet workflow problems"},
        }]}
        comments = Mock()
        comments.raise_for_status.return_value = None
        comments.json.return_value = {"items": [{"snippet": {"topLevelComment": {
            "id": "comment_12345", "snippet": {
                "textOriginal": "We manually copy every invoice and it takes hours.",
                "likeCount": 12, "publishedAt": "2026-07-29T10:00:00Z",
            },
        }}}]}
        with patch.object(research_web.vault, "get_key", return_value="private-google-key"), \
             patch.object(research_base, "_public_https_url", return_value=True), \
             patch.object(research.httpx, "get", side_effect=[videos, comments]):
            rows = research._youtube("invoice workflow complaints", "youtube", 5, 30, 5)
        self.assertEqual(1, len(rows))
        self.assertEqual("youtube", rows[0]["source"])
        self.assertIn("Viewer comment", rows[0]["document"])
        self.assertNotIn("private-google-key", str(rows))

    def test_cached_provider_snapshot_is_scanned_without_network_fetch(self):
        row = research_cache.cache_research_result({
            "title": "Comment", "url": "https://www.youtube.com/watch?v=abcdefghijk",
            "source": "youtube", "document": "A manual workflow takes three hours every day.",
        }, "2099-01-01T00:00:00+00:00")
        with patch.object(research.httpx, "Client") as client:
            result = research_base.fetch(row["id"], 2000)
        self.assertFalse(result["blocked"])
        self.assertTrue(result["content_stats"]["snapshot"])
        self.assertIn("UNTRUSTED_WEB_CONTENT", result["content"])
        client.assert_not_called()

    def test_builtin_research_tool_includes_new_safe_sources(self):
        builtin_capabilities.ensure_builtin_research_capabilities()
        tool = control_plane.get("tool", "research.search")
        source = next(field for field in tool["inputs"] if field["name"] == "source")
        self.assertIn("youtube", source["allowed_values"])
        self.assertIn("reddit", source["allowed_values"])
        self.assertIn("stackexchange", source["allowed_values"])
        self.assertIn("discourse", source["allowed_values"])
        self.assertEqual(3650, next(field for field in tool["inputs"] if field["name"] == "recency_days")["maximum"])
        self.assertEqual("reddit", control_plane.get("tool", "research.reddit")["execution"]["fixed_source"])
        self.assertEqual(
            "github_repositories",
            control_plane.get("tool", "research.github-repositories")["execution"]["fixed_source"],
        )
        self.assertEqual(
            "stackexchange",
            control_plane.get("tool", "research.stackexchange")["execution"]["fixed_source"],
        )
        self.assertEqual(
            "discourse",
            control_plane.get("tool", "research.discourse")["execution"]["fixed_source"],
        )
        self.assertEqual(
            ["general", "producthunt", "github_repositories"],
            control_plane.get("tool", "research.scan-competition")["execution"]["sources"],
        )

    def test_producthunt_provider_is_permission_gated_and_locally_filtered(self):
        with (
            patch.object(research_base.control_plane, "settings", return_value={}),
            self.assertRaises(research.ResearchError),
        ):
            research._producthunt("invoice automation", "producthunt", 5, 365, 5)

        topics = Mock()
        topics.raise_for_status.return_value = None
        topics.json.return_value = {
            "data": {
                "t0": {"nodes": [{"name": "Accounting", "slug": "accounting"}]},
                "t1": {"nodes": [{"name": "Automation", "slug": "automation"}]},
            }
        }
        products = Mock()
        products.raise_for_status.return_value = None
        products.json.return_value = {
            "data": {
                "p0": {"nodes": [{"id": "one", "name": "Invoice Flow", "tagline": "Invoice automation", "description": "Automates invoice review", "url": "https://www.producthunt.com/products/invoice-flow", "createdAt": "2026-01-01T00:00:00Z", "votesCount": 42}]},
                "p1": {"nodes": []},
            }
        }
        with patch.object(research_base.control_plane, "settings", return_value={"producthunt_commercial_use_approved": True}), \
             patch.object(research_web.vault, "get_key", return_value="private-token"), \
             patch.object(research_base, "_public_https_url", return_value=True), \
             patch.object(research.httpx, "post", side_effect=[topics, products]) as request:
            rows = research._producthunt("invoice automation", "producthunt", 5, 365, 5)
        self.assertEqual(["Invoice Flow"], [row["title"] for row in rows])
        self.assertNotIn("private-token", str(rows))
        self.assertEqual(2, request.call_count)
