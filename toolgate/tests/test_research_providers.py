"""Research search providers: Tavily, Discourse, Hacker News and SearXNG, and their site scoping."""

from unittest.mock import Mock, patch

import httpx

from toolgate.executors import research, research_base, research_web
from toolgate.tests.research_support import ResearchDbTestCase


class ResearchSearchTests(ResearchDbTestCase):
    def test_tavily_search_uses_vault_secret_without_exposing_it(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"results": [{
            "title": "<b>Manual close</b>", "url": "https://example.com/close",
            "content": "Teams <em>manually</em> reconcile exports.", "published_date": "2026-07-29",
        }]}
        with patch.object(research_web.vault, "get_key", return_value="private-tavily-key"), \
             patch.object(research_base, "_public_https_url", return_value=True), \
             patch.object(research.httpx, "post", return_value=response) as request:
            rows = research_web._tavily_unmetered("monthly close pain", "general", 5, 30, 5)
        self.assertEqual("Manual close", rows[0]["title"])
        self.assertIn("Tavily extracted search content", rows[0]["document"])
        self.assertNotIn("private-tavily-key", str(rows))
        payload = request.call_args.kwargs["json"]
        self.assertIn("start_date", payload)
        self.assertNotIn("time_range", payload)
        self.assertEqual(30, rows[0]["recency_provenance"]["max_age_days"])

    def test_tavily_source_fallback_is_domain_scoped(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"results": [{
            "title": "Manual dispatch",
            "url": "https://www.reddit.com/r/smallbusiness/comments/example/topic/",
            "content": "We manually dispatch every job.",
            "published_date": "2026-07-29",
        }]}
        with patch.object(research_web.vault, "get_key", return_value="private-tavily-key"), \
             patch.object(research_base, "_public_https_url", return_value=True), \
             patch.object(research.httpx, "post", return_value=response) as request:
            rows = research_web._tavily_unmetered("field service complaints", "reddit", 5, 30, 5)
        payload = request.call_args.kwargs["json"]
        self.assertEqual(["reddit.com"], payload["include_domains"])
        self.assertNotIn("exclude_domains", payload)
        self.assertEqual("reddit", rows[0]["source"])
        self.assertEqual("Bearer private-tavily-key", request.call_args.kwargs["headers"]["Authorization"])

    def test_discourse_search_is_allowlisted_dated_and_balanced(self):
        host_indexes = {host: index for index, host in enumerate(research_base.DISCOURSE_HOSTS, 1)}

        def fake_get(url, **_kwargs):
            host = next(host for host in research_base.DISCOURSE_HOSTS if host in url)
            index = host_indexes[host]
            response = Mock()
            response.raise_for_status.return_value = None
            if url.endswith("/search.json"):
                response.json.return_value = {
                    "topics": [{
                        "id": index, "title": f"Invoice reconciliation on {host}",
                        "slug": f"invoice-reconciliation-{index}", "archetype": "regular",
                        "created_at": "2026-07-01T00:00:00Z",
                    }],
                    "posts": [{
                        "id": index + 10, "topic_id": index, "post_number": 2,
                        "username": f"helper{index}", "created_at": "2026-07-02T00:00:00Z",
                        "blurb": "<p>Try a scheduled workflow.</p>",
                    }],
                }
            else:
                response.json.return_value = {"post_stream": {"posts": [{
                    "post_number": 1, "username": f"owner{index}",
                    "created_at": "2026-07-01T00:00:00Z",
                    "cooked": "<p>At our company, we manually reconcile invoices every week.</p>",
                }]}}
            return response

        with patch.object(research.httpx, "get", side_effect=fake_get) as request,              patch.object(research.time, "monotonic", return_value=0.0):
            rows = research._discourse("invoice reconciliation workflow", "discourse", 6, 365, 5)
        self.assertEqual(len(research_base.DISCOURSE_HOSTS), len(rows))
        self.assertEqual(set(research_base.DISCOURSE_HOSTS), {row["community"] for row in rows})
        self.assertTrue(all(row["reporter"].startswith("owner") for row in rows))
        self.assertTrue(all(row["post_number"] == 1 for row in rows))
        self.assertTrue(all("manually reconcile" in row["document"] for row in rows))
        self.assertTrue(all("<p>" not in row["document"] for row in rows))
        search_calls = [call for call in request.call_args_list if call.args[0].endswith("/search.json")]
        self.assertTrue(all("after:" in call.kwargs["params"]["q"] for call in search_calls))

    def test_hackernews_web_fallback_is_hydrated_through_json_api(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "created_at": "2026-07-30T12:00:00.000Z",
            "text": "", "children": [{"text": "<p>Token costs doubled this month.</p>"}],
        }
        item = {"title": "Agent costs", "url": "https://news.ycombinator.com/item?id=123", "snippet": "Costs", "source": "hackernews"}
        with patch.object(research.httpx, "get", return_value=response):
            hydrated = research_web._community_snapshot(item, "hackernews", 5)
        self.assertIn("Token costs doubled", hydrated["document"])
        self.assertNotIn("<p>", hydrated["document"])
        self.assertEqual("2026-07-30T12:00:00.000Z", hydrated["published_at"])
        self.assertEqual("hackernews_item", hydrated["recency_provenance"]["provider"])

    def test_hackernews_fallback_keeps_timestamp_without_discussion_text(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"created_at": "2026-07-31T08:30:00.000Z", "text": "", "children": []}
        item = {"title": "Spreadsheet workflow", "url": "https://news.ycombinator.com/item?id=456", "snippet": "Still manual", "source": "hackernews"}
        with patch.object(research.httpx, "get", return_value=response):
            hydrated = research_web._community_snapshot(item, "hackernews", 5)
        self.assertEqual("2026-07-31T08:30:00.000Z", hydrated["published_at"])
        self.assertNotIn("document", hydrated)

    def test_searx_enforces_explicit_site_scope_on_general_search(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"results": [
            {"title": "Wrong", "url": "https://wikipedia.org/wiki/Invoice", "content": "manual invoices"},
            {"title": "Right", "url": "https://forum.accountingweb.co.uk/topic", "content": "manual invoices"},
        ]}
        with patch.object(research.httpx, "get", return_value=response), \
             patch.object(research_base, "_public_https_url", return_value=True), \
             patch.object(research_web, "_community_snapshot", side_effect=lambda item, *_args: item):
            rows = research._searx(
                "site:accountingweb.co.uk manual invoices", "general", 5, 90, 5,
            )
        self.assertEqual(["Right"], [row["title"] for row in rows])

    def test_site_scope_with_a_path_still_enforces_the_host(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"results": [
            {"title": "Wrong", "url": "https://wikipedia.org/wiki/Receipt", "content": "manual receipts"},
            {"title": "Right", "url": "https://reddit.com/r/smallbusiness/comments/example", "content": "manual receipts"},
        ]}
        with patch.object(research.httpx, "get", return_value=response), \
             patch.object(research_base, "_public_https_url", return_value=True), \
             patch.object(research_web, "_community_snapshot", side_effect=lambda item, *_args: item):
            rows = research._searx(
                "site:reddit.com/r/smallbusiness manual receipts", "general", 5, 90, 5,
            )
        self.assertEqual(["Right"], [row["title"] for row in rows])

    def test_searx_enrichment_uses_short_shared_deadline_slices(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"results": [{
            "title": f"Manual workflow {index}",
            "url": f"https://www.reddit.com/r/accounting/comments/topic{index}/post/",
            "content": "We manually reconcile this every month.",
        } for index in range(3)]}
        timeouts = []

        def snapshot(item, _source, timeout):
            timeouts.append(timeout)
            return item

        with patch.object(research.httpx, "get", return_value=response), \
             patch.object(research_base.control_plane, "settings", return_value={}), \
             patch.object(research_base, "_public_https_url", return_value=True), \
             patch.object(research_web, "_community_snapshot", side_effect=snapshot):
            rows = research._searx("manual workflow", "reddit", 3, 90, 8)
        self.assertEqual(3, len(rows))
        self.assertEqual(3, len(timeouts))
        self.assertTrue(all(0 < timeout <= 1.5 for timeout in timeouts))

    def test_tavily_quota_failure_opens_bounded_provider_circuit(self):
        response = Mock(status_code=432)
        response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "quota", request=Mock(), response=response,
        )
        research_base._PROVIDER_COOLDOWNS.clear()
        self.addCleanup(research_base._PROVIDER_COOLDOWNS.clear)
        with patch.object(research_web.vault, "get_key", return_value="private-key"), \
             patch.object(research.httpx, "post", return_value=response) as post:
            with self.assertRaises(httpx.HTTPStatusError):
                research_web._tavily_unmetered("invoice workflow", "general", 5, 30, 5)
            with self.assertRaisesRegex(research.ResearchError, "temporarily unavailable"):
                research_web._tavily_unmetered("another workflow", "general", 5, 30, 5)
        self.assertEqual(1, post.call_count)
