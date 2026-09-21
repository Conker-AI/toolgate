"""/health tests.

The health contract is the one place the owner finds out a dependency is gone,
so nothing here is mocked: the "up" case answers from a real HTTP server on a
real socket, and the "down" cases point at a port nothing is listening on and
at a database that genuinely cannot be opened.
"""
import os
import json
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from toolgate.api import server
from toolgate.core import control_plane, vault


class _AlwaysOk(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's naming
        body = getattr(self.server, "health_body", {"service": "memorygate", "status": "ok"})
        encoded = json.dumps(body).encode()
        self.send_response(getattr(self.server, "response_status", 200))
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *args):
        pass


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.db_patch = patch.object(control_plane, "DB_PATH", self.root / "toolgate-test.db")
        self.db_patch.start()
        self.env_patch = patch.object(vault, "ENV_PATH", self.root / "vault.env")
        self.env_patch.start()

        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), _AlwaysOk)
        self.upstream_url = f"http://127.0.0.1:{self.upstream.server_port}"
        self.thread = threading.Thread(target=self.upstream.serve_forever, daemon=True)
        self.thread.start()

        self.os_patch = patch.dict(os.environ, {
            "TOOLGATE_VAULT_KEY_FILE": str(self.root / "vault.key"),
            "MEMORYGATE_URL": self.upstream_url,
        })
        self.os_patch.start()
        server._health_snapshot = None
        self.client = TestClient(server.app)

    def tearDown(self):
        self.client.close()
        self.upstream.shutdown()
        self.upstream.server_close()
        self.thread.join(timeout=5)
        server._health_snapshot = None
        self.os_patch.stop()
        self.env_patch.stop()
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def point_upstreams_at(self, url: str):
        control_plane.update_settings({"research_searxng_url": url, "generation_url": url}, "test")

    def configure_memorygate(self):
        vault.set_secret("MEMORYGATE_READ_KEY", "mg_read_test_value")

    def health(self) -> dict:
        server._health_snapshot = None
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_health_reports_ok_when_every_dependency_answers(self):
        self.point_upstreams_at(self.upstream_url)
        self.configure_memorygate()

        body = self.health()

        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["degraded"], [])
        # The module contract requires this module's own version, not the API
        # revision - a dashboard reading one field for both is wrong everywhere.
        self.assertEqual(body["service"], "toolgate")
        self.assertEqual(body["version"], server.SERVICE_VERSION)
        self.assertEqual({name: check["status"] for name, check in body["checks"].items()}, {
            "control_plane_db": "ok", "vault": "ok",
            "searxng": "ok", "memorygate": "ok", "generation": "ok",
        })

    def test_health_names_the_dependency_that_stopped_answering(self):
        self.point_upstreams_at(self.upstream_url)
        self.configure_memorygate()
        self.assertEqual(self.health()["status"], "ok")

        self.upstream.shutdown()
        self.upstream.server_close()

        body = self.health()

        self.assertEqual(body["status"], "degraded")
        self.assertEqual(body["degraded"], ["generation", "memorygate", "searxng"])
        self.assertEqual(body["checks"]["searxng"]["status"], "unavailable")
        self.assertEqual(body["checks"]["control_plane_db"]["status"], "ok")

    def test_memorygate_degradation_is_not_hidden_by_http_success(self):
        self.point_upstreams_at(self.upstream_url)
        self.configure_memorygate()
        self.upstream.health_body = {"service": "memorygate", "status": "degraded",
                                     "checks": {"private": "do-not-forward-this"}}
        body = self.health()
        self.assertEqual({"status": "degraded", "reason": "upstream_reports_degraded"},
                         body["checks"]["memorygate"])
        self.assertNotIn("do-not-forward-this", json.dumps(body))

    def test_http_errors_and_redirects_are_not_reported_as_healthy(self):
        for code in (301, 401, 403, 404):
            with self.subTest(code=code):
                self.upstream.response_status = code
                self.assertEqual({"status": "unavailable", "reason": "upstream_http_error"},
                                 server._probe_http(self.upstream_url, "/health"))

    def test_memorygate_probe_rejects_wrong_service_or_health_shape(self):
        for body in ([], {"service": "other", "status": "ok"},
                     {"service": "memorygate", "status": "surprise"}):
            with self.subTest(body=body):
                self.upstream.health_body = body
                self.assertEqual({"status": "unavailable", "reason": "invalid_health_response"},
                                 server._probe_http(self.upstream_url, "/health", "memorygate"))

    def test_health_reports_degraded_when_the_control_plane_database_is_gone(self):
        self.point_upstreams_at(self.upstream_url)
        unopenable = self.root / "not-a-database"
        unopenable.mkdir()

        with patch.object(control_plane, "DB_PATH", unopenable):
            with self.assertRaises(sqlite3.Error):  # the failure is real, not simulated
                control_plane.settings()
            body = self.health()

        self.assertEqual(body["status"], "degraded")
        self.assertIn("control_plane_db", body["degraded"])
        self.assertEqual(body["checks"]["control_plane_db"]["status"], "unavailable")

    def test_health_reports_degraded_when_the_vault_key_no_longer_decrypts(self):
        self.point_upstreams_at(self.upstream_url)
        vault.set_secret("GITHUB_TOKEN", "ghp_value")

        with patch.dict(os.environ, {"TOOLGATE_VAULT_SECRET": "a-different-install-secret"}):
            body = self.health()

        self.assertEqual(body["status"], "degraded")
        self.assertIn("vault", body["degraded"])
        self.assertEqual(body["checks"]["vault"]["status"], "unavailable")

    def test_an_unconfigured_dependency_is_not_reported_as_broken(self):
        control_plane.update_settings({"research_searxng_url": self.upstream_url}, "test")

        body = self.health()

        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["checks"]["memorygate"]["status"], "not_configured")
        self.assertEqual(body["checks"]["generation"]["status"], "not_configured")

    def test_health_answers_from_cache_and_says_how_old_the_answer_is(self):
        self.point_upstreams_at(self.upstream_url)
        first = self.health()

        second = self.client.get("/health").json()

        self.assertEqual(second["checked_at"], first["checked_at"])
        self.assertGreaterEqual(second["age_seconds"], 0.0)

    def test_health_detail_stays_coarse_for_an_unauthenticated_caller(self):
        self.point_upstreams_at(self.upstream_url)
        self.configure_memorygate()
        self.upstream.shutdown()

        rendered = self.client.get("/health").text

        self.assertNotIn(self.upstream_url, rendered)
        self.assertNotIn("127.0.0.1", rendered)
        self.assertNotIn("mg_read_test_value", rendered)
        self.assertNotIn(str(self.root), rendered)


if __name__ == "__main__":
    unittest.main()
