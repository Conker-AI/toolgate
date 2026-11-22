"""Research search for Reddit: Atom and subreddit feeds, bounded snippets and the metasearch fallbacks."""

from datetime import UTC, datetime
from unittest.mock import Mock, patch

import httpx

from toolgate.executors import research, research_base, research_forums, research_web
from toolgate.tests.research_support import ResearchDbTestCase


class ResearchSearchTests(ResearchDbTestCase):
    def test_reddit_rss_uses_original_entry_date_not_feed_update(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.content = b'''<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
          <updated>2026-07-31T20:45:05+00:00</updated>
          <entry><title>Original post</title><updated>2025-05-22T17:17:28+00:00</updated></entry>
        </feed>'''
        with patch.object(research.httpx, "get", return_value=response):
            published = research_web._reddit_rss_published_at(
                "https://www.reddit.com/r/grooming/comments/1kswbmq/topic", 5,
            )
        self.assertEqual("2025-05-22T17:17:28+00:00", published)

    def test_reddit_rss_rejects_non_reddit_destinations(self):
        with patch.object(research.httpx, "get") as get:
            self.assertIsNone(research_web._reddit_rss_published_at("https://example.com/comments/abc/topic", 5))
        get.assert_not_called()

    def test_reddit_atom_search_returns_bounded_dated_snapshots(self):
        now = datetime.now(UTC).isoformat()
        response = Mock()
        response.raise_for_status.return_value = None
        response.content = f'''<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
          <entry><title>Manual dispatch is breaking</title><updated>{now}</updated>
          <link rel="alternate" href="https://www.reddit.com/r/smallbusiness/comments/example/topic/" />
          <content type="html">&lt;p&gt;We manually copy every job and it takes hours.&lt;/p&gt;</content></entry>
        </feed>'''.encode()
        with patch.object(research.httpx, "get", return_value=response), \
             patch.object(research_base, "_public_https_url", return_value=True):
            rows = research._reddit_rss_search("dispatch hours pain", "reddit", 5, 90, 5)
        self.assertEqual(1, len(rows))
        self.assertEqual("reddit_atom", rows[0]["recency_provenance"]["provider"])
        self.assertIn("manually copy", rows[0]["document"])
        self.assertNotIn("<p>", rows[0]["document"])

    def test_reddit_subreddit_feed_is_allowlisted_bounded_and_dated(self):
        now = datetime.now(UTC).isoformat()
        response = Mock()
        response.raise_for_status.return_value = None
        response.content = f'''<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
          <entry><title>Manual receipt workflow</title><updated>{now}</updated>
          <link rel="alternate" href="https://www.reddit.com/r/smallbusiness/comments/example/topic/" />
          <content type="html">&lt;p&gt;I type every receipt into a spreadsheet.&lt;/p&gt;</content></entry>
        </feed>'''.encode()
        with patch.object(research.httpx, "get", return_value=response), \
             patch.object(research_base, "_public_https_url", return_value=True):
            rows = research._reddit_subreddit_feed(
                "subreddit:smallbusiness", "reddit", 5, 90, 5,
            )
        self.assertEqual(1, len(rows))
        self.assertEqual("r/smallbusiness", rows[0]["community"])
        self.assertEqual("reddit_atom_feed", rows[0]["recency_provenance"]["provider"])

    def test_reddit_subreddit_feed_rejects_unapproved_community(self):
        with self.assertRaises(research.ResearchError):
            research._reddit_subreddit_feed("subreddit:notapproved", "reddit", 5, 90, 5)

    def test_reddit_subreddit_falls_back_to_scoped_metasearch(self):
        fallback = [{
            "title": "Manual receipt workflow",
            "url": "https://www.reddit.com/r/accounting/comments/example/manual_receipts/",
            "snippet": "We manually enter every client receipt.",
            "source": "reddit",
            "published_at": datetime.now(UTC).isoformat(),
            "content_safety": {"risk": "low", "flags": []},
        }]
        with patch.object(research, "_reddit_subreddit_feed", side_effect=httpx.HTTPError("blocked")), \
             patch.object(research, "_reddit_subreddit_searx", return_value=fallback), \
             patch.object(research, "_reddit_subreddit_tavily") as remote_fallback:
            result = research.search("subreddit:accounting", "reddit", 5, 14)
        self.assertEqual("searxng_subreddit", result["provider"])
        self.assertEqual(1, result["result_count"])
        self.assertIn("reddit_atom_feed: HTTPError", result["fallback_failures"])
        remote_fallback.assert_not_called()

    def test_research_fallbacks_receive_bounded_shared_deadline_slices(self):
        timeouts = []

        def unavailable(_query, _source, _limit, _recency_days, timeout):
            timeouts.append(timeout)
            raise httpx.HTTPError("unavailable")

        with (
            patch.object(research, "_reddit_subreddit_feed", side_effect=unavailable),
            patch.object(research, "_reddit_subreddit_searx", side_effect=unavailable),
            patch.object(research, "_reddit_subreddit_tavily", side_effect=unavailable),
            self.assertRaises(research.ResearchError),
        ):
            research.search("subreddit:accounting", "reddit", 5, 14)
        self.assertEqual(3, len(timeouts))
        self.assertTrue(all(0 < timeout <= 8 for timeout in timeouts))

    def test_reddit_subreddit_fallback_filters_other_communities(self):
        rows = [
            {"url": "https://www.reddit.com/r/accounting/comments/right/topic/"},
            {"url": "https://www.reddit.com/r/gaming/comments/wrong/topic/"},
        ]
        provider = Mock(return_value=rows)
        result = research_forums._reddit_subreddit_fallback(
            "subreddit:accounting", "reddit", 5, 14, 5, provider,
        )
        self.assertEqual([rows[0]], result)
        self.assertIn("site:reddit.com/r/accounting", provider.call_args.args[0])

    def test_reddit_atom_search_uses_conjunctive_query_and_filters_noise(self):
        now = datetime.now(UTC).isoformat()
        response = Mock()
        response.raise_for_status.return_value = None
        response.content = f'''<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
          <entry><title>Unrelated road project</title><updated>{now}</updated>
          <link rel="alternate" href="https://www.reddit.com/r/games/comments/noise/topic/" />
          <content type="html">A manager approved road maintenance in a video game.</content></entry>
          <entry><title>Property maintenance vendor problem</title><updated>{now}</updated>
          <link rel="alternate" href="https://www.reddit.com/r/property/comments/useful/topic/" />
          <content type="html">Our property managers coordinate every maintenance vendor by email.</content></entry>
        </feed>'''.encode()
        with patch.object(research.httpx, "get", return_value=response) as get, \
             patch.object(research_base, "_public_https_url", return_value=True):
            rows = research._reddit_rss_search("property managers maintenance vendor", "reddit", 5, 90, 5)
        self.assertEqual(1, len(rows))
        self.assertIn("property", rows[0]["title"].lower())
        self.assertEqual("property AND managers AND maintenance", get.call_args.kwargs["params"]["q"])

    def test_reddit_atom_ignores_generic_buyer_language_as_topic_identity(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.content = b'''<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"></feed>'''
        with patch.object(research.httpx, "get", return_value=response) as get:
            research._reddit_rss_search(
                'independent event rental companies inventory damage "how do you" spreadsheet',
                "reddit", 5, 90, 5,
            )
        self.assertEqual("event AND rental AND inventory", get.call_args.kwargs["params"]["q"])

    def test_reddit_atom_preserves_manual_workflow_terms_for_buyer_queries(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.content = b'''<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"></feed>'''
        with patch.object(research.httpx, "get", return_value=response) as get:
            research._reddit_rss_search(
                '"how do you handle" manually spreadsheet', "reddit", 5, 90, 5,
            )
        self.assertEqual(
            '"how do you handle" AND manually AND spreadsheet',
            get.call_args.kwargs["params"]["q"],
        )

    def test_reddit_atom_search_rejects_oversized_or_malformed_feeds(self):
        oversized = Mock()
        oversized.raise_for_status.return_value = None
        oversized.content = b"x" * 524289
        malformed = Mock()
        malformed.raise_for_status.return_value = None
        malformed.content = b"<feed>"
        with patch.object(research.httpx, "get", side_effect=[oversized, malformed]):
            with self.assertRaises(research.ResearchError):
                research._reddit_rss_search("query", "reddit", 5, 90, 5)
            with self.assertRaises(research.ResearchError):
                research._reddit_rss_search("query", "reddit", 5, 90, 5)

    def test_reddit_uses_bounded_search_excerpt_instead_of_direct_scraping(self):
        item = {
            "title": "Field service scheduling recommendations",
            "url": "https://www.reddit.com/r/smallbusiness/comments/example/topic/",
            "snippet": "We still use Google Sheets and have to manually dispatch every job.",
            "source": "reddit",
        }
        snapshot = research_web._community_snapshot(item, "reddit", 1)
        self.assertIn("Reddit discussion excerpt", snapshot["document"])
        self.assertIn("manually dispatch", snapshot["document"])

    def test_reddit_search_uses_public_atom_then_local_fallback(self):
        fallback = [{
            "title": "Manual dispatch", "url": "https://www.reddit.com/r/smallbusiness/comments/example/topic/",
            "snippet": "We manually dispatch every job.", "source": "reddit", "published_at": "2026-07-29T00:00:00Z",
            "content_safety": {"risk": "low", "flags": []},
        }]
        with patch.object(research, "_reddit_rss_search", return_value=[]), \
             patch.object(research, "_searx", return_value=fallback), \
             patch.object(research, "_tavily") as remote_fallback:
            result = research.search("field service dispatch", "reddit", 5, 90)
        self.assertEqual("searxng", result["provider"])
        self.assertTrue(any("reddit_atom: no results" in failure for failure in result["fallback_failures"]))
        remote_fallback.assert_not_called()
