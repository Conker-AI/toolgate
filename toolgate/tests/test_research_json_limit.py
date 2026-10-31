"""Research JSON bodies above the safe size limit are refused before parsing."""

import unittest
from unittest.mock import Mock, patch

import pytest

from toolgate.core import control_plane
from toolgate.executors import research_base, research_forums, research_sites, research_web

# '{"items": []' is 12 bytes, the padding brings the body to JSON_LIMIT bytes, and the
# closing brace makes it one byte over while staying valid JSON (whitespace is insignificant).
OVERSIZED_JSON = b'{"items": []' + b" " * (research_base.JSON_LIMIT - 12) + b"}"


def oversized_response():
    response = Mock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.content = OVERSIZED_JSON
    response.json.side_effect = AssertionError("json() was called on an oversized body")
    return response


class ResearchJsonLimitTests(unittest.TestCase):
    @pytest.fixture(autouse=True)
    def _use_tmp_path(self, tmp_path):  # pytest's temporary directory, set before setUp
        self.tmp_path = tmp_path

    def setUp(self):
        self.original_db = control_plane.DB_PATH
        control_plane.DB_PATH = self.tmp_path / "toolgate-test.db"

    def tearDown(self):
        control_plane.DB_PATH = self.original_db

    def test_json_body_parses_at_limit_and_refuses_one_byte_over(self):
        at_limit = b'{"a": "' + b"x" * 55 + b'"}'
        self.assertEqual(64, len(at_limit))
        with self.subTest("exactly at the limit parses"):
            response = Mock()
            response.content = at_limit
            response.json.return_value = {"a": "x" * 54}
            parsed = research_base.json_body(response, "Example", limit=64)
            self.assertEqual({"a": "x" * 54}, parsed)
        with self.subTest("one byte over is refused unparsed"):
            response = Mock()
            response.content = at_limit + b" "
            with self.assertRaisesRegex(
                research_base.ResearchError, "Example response exceeded the safe size limit",
            ):
                research_base.json_body(response, "Example", limit=64)

    def test_oversized_body_is_refused_without_calling_json(self):
        response = Mock()
        response.content = b"x" * 65
        response.json.side_effect = AssertionError("json() was called on an oversized body")
        with self.assertRaisesRegex(research_base.ResearchError, "safe size limit"):
            research_base.json_body(response, "Example", limit=64)

    def test_github_refuses_oversized_response_unparsed(self):
        response = oversized_response()
        with (
            patch.object(research_sites.vault, "get_key", side_effect=KeyError),
            patch.object(research_sites.httpx, "get", return_value=response),
            self.assertRaisesRegex(research_base.ResearchError, "GitHub"),
        ):
            research_sites._github("invoice workflow", "github", 5, 30, 5)
        response.json.assert_not_called()

    def test_discourse_skips_oversized_host_and_uses_the_next_host(self):
        first, second = research_base.DISCOURSE_HOSTS[0], research_base.DISCOURSE_HOSTS[1]
        normal_search = {
            "topics": [{
                "id": 2, "title": "Invoice reconciliation on community.n8n.io",
                "slug": "invoice-reconciliation-2", "archetype": "regular",
                "created_at": "2026-07-01T00:00:00Z",
            }],
            "posts": [{
                "id": 12, "topic_id": 2, "post_number": 2, "username": "helper2",
                "created_at": "2026-07-02T00:00:00Z", "blurb": "<p>Try a scheduled workflow.</p>",
            }],
        }
        normal_topic = {"post_stream": {"posts": [{
            "post_number": 1, "username": "owner2", "created_at": "2026-07-01T00:00:00Z",
            "cooked": "<p>At our company, we manually reconcile invoices every week.</p>",
        }]}}

        def fake_get(url, **_kwargs):
            response = Mock()
            response.raise_for_status.return_value = None
            if url.startswith("https://" + first + "/"):
                response.content = OVERSIZED_JSON
                response.json.side_effect = AssertionError("oversized host json() was called")
            elif url.startswith("https://" + second + "/"):
                search = url.endswith("/search.json")
                response.json.return_value = normal_search if search else normal_topic
            else:
                response.json.return_value = {"topics": [], "posts": []}
            return response

        with (
            patch.object(research_forums.httpx, "get", side_effect=fake_get),
            patch.object(research_forums.time, "monotonic", return_value=0.0),
        ):
            rows = research_forums._discourse(
                "invoice reconciliation workflow", "discourse", 6, 365, 5,
            )
        self.assertEqual([second], [row["community"] for row in rows])
        self.assertTrue(all("manually reconcile" in row["document"] for row in rows))

    def test_searxng_refuses_oversized_response_unparsed(self):
        response = oversized_response()
        with (
            patch.object(research_web.httpx, "get", return_value=response),
            patch.object(research_web.control_plane, "settings", return_value={}),
            self.assertRaisesRegex(research_base.ResearchError, "SearXNG"),
        ):
            research_web._searx("manual invoice workflow", "general", 5, 90, 5)
        response.json.assert_not_called()

    def test_youtube_skips_a_video_whose_comments_are_oversized(self):
        videos = Mock()
        videos.raise_for_status.return_value = None
        videos.json.return_value = {"items": [
            {"id": {"videoId": "abcdefghijk"}, "snippet": {"title": "Oversized comments"}},
            {"id": {"videoId": "bcdefghijkl"}, "snippet": {"title": "Spreadsheet workflows"}},
        ]}
        comments = Mock()
        comments.raise_for_status.return_value = None
        comments.json.return_value = {"items": [{"snippet": {"topLevelComment": {
            "id": "comment_12345", "snippet": {
                "textOriginal": "We manually copy every invoice and it takes hours.",
                "likeCount": 12, "publishedAt": "2026-07-29T10:00:00Z",
            },
        }}}]}
        with (
            patch.object(research_sites.vault, "get_key", return_value="test-google-key"),
            patch.object(research_base, "_public_https_url", return_value=True),
            patch.object(
                research_sites.httpx, "get", side_effect=[videos, oversized_response(), comments],
            ),
        ):
            rows = research_sites._youtube("invoice workflow complaints", "youtube", 5, 30, 5)
        self.assertEqual(["bcdefghijkl"], [row["url"].split("v=")[1][:11] for row in rows])
