"""/health tests.

The health contract is the one place the owner finds out a dependency is gone,
so nothing here is mocked: the "up" case answers from a real HTTP server on a
real socket, and the "down" cases point at a port nothing is listening on and
at a database that genuinely cannot be opened.
"""
import json
import os
import socket
import sqlite3
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from toolgate.api import server, version
from toolgate.api.routes import health as health_routes
from toolgate.core import control_plane, vault

PI_KEY = "pi-service-key-" + "h" * 40


def _closed_url() -> str:
    """An address with nothing listening: the port was bound once and released."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return f"http://127.0.0.1:{port}"


class _AlwaysOk(BaseHTTPRequestHandler):
    def do_GET(self):  # BaseHTTPRequestHandler's naming
        self.server.seen.append({"path": self.path, "headers": dict(self.headers.items())})
        body = getattr(self.server, "health_body", {"service": "memorygate", "status": "ok"})
        encoded = json.dumps(body).encode()
        self.send_response(getattr(self.server, "response_status", 200))
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *args):
        pass


class HealthTests(unittest.TestCase):
    @pytest.fixture(autouse=True)
    def _use_tmp_path(self, tmp_path):  # pytest's temporary directory, set before setUp
        self.tmp_path = tmp_path

    def setUp(self):
        self.root = self.tmp_path
        self.db_patch = patch.object(control_plane, "DB_PATH", self.root / "toolgate-test.db")
        self.db_patch.start()
        self.env_patch = patch.object(vault, "ENV_PATH", self.root / "vault.env")
        self.env_patch.start()

        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), _AlwaysOk)
        self.upstream.seen = []
        self.upstream_url = f"http://127.0.0.1:{self.upstream.server_port}"
        self.thread = threading.Thread(target=self.upstream.serve_forever, daemon=True)
        self.thread.start()

        self.os_patch = patch.dict(os.environ, {
            "TOOLGATE_VAULT_KEY_FILE": str(self.root / "vault.key"),
            "MEMORYGATE_URL": self.upstream_url,
        })
        self.os_patch.start()
        for name in ("TOOLGATE_PI_URL", "TOOLGATE_PI_SERVICE_KEY"):  # the Ollama path by default
            os.environ.pop(name, None)
        health_routes._health_snapshot = None
        self.client = TestClient(server.app)

    def tearDown(self):
        self.client.close()
        self.upstream.shutdown()
        self.upstream.server_close()
        self.thread.join(timeout=5)
        health_routes._health_snapshot = None
        self.os_patch.stop()
        self.env_patch.stop()
        self.db_patch.stop()

    def point_upstreams_at(self, url: str):
        control_plane.update_settings({"research_searxng_url": url, "generation_url": url}, "test")

    def configure_memorygate(self):
        vault.set_secret("MEMORYGATE_READ_KEY", "mg_read_test_value")

    def health(self) -> dict:
        health_routes._health_snapshot = None
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
        self.assertEqual(body["version"], version.SERVICE_VERSION)
        self.assertEqual({name: check["status"] for name, check in body["checks"].items()}, {
            "control_plane_db": "ok", "vault": "ok",
            "searxng": "ok", "memorygate": "ok", "generation": "ok",
        })
        self.assertEqual(body["checks"]["generation"], {"status": "ok", "via": "ollama"})

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
                                 health_routes._probe_http(self.upstream_url, "/health"))

    def test_memorygate_probe_rejects_wrong_service_or_health_shape(self):
        for body in ([], {"service": "other", "status": "ok"},
                     {"service": "memorygate", "status": "surprise"}):
            with self.subTest(body=body):
                self.upstream.health_body = body
                self.assertEqual({"status": "unavailable", "reason": "invalid_health_response"},
                                 health_routes._probe_http(self.upstream_url, "/health", "memorygate"))

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

    def use_pi(self, url: str):
        os.environ["TOOLGATE_PI_URL"] = url + "/"
        os.environ["TOOLGATE_PI_SERVICE_KEY"] = PI_KEY

    def test_with_pi_configured_generation_is_pi_and_ollama_is_not_probed(self):
        # Ollama is configured and gone; with Pi set, its state is not ToolGate's to report.
        control_plane.update_settings(
            {"research_searxng_url": self.upstream_url, "generation_url": _closed_url()}, "test"
        )
        self.use_pi(self.upstream_url)
        self.upstream.health_body = {"service": "pi", "status": "ok"}

        body = self.health()

        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["checks"]["generation"], {"status": "ok", "via": "pi"})
        paths = [request["path"] for request in self.upstream.seen]
        self.assertIn("/health", paths)  # Pi's health, not /inference: no model call
        self.assertNotIn("/api/tags", paths)
        self.assertNotIn("/inference", paths)

    def test_the_pi_probe_sends_no_key(self):
        self.use_pi(self.upstream_url)
        control_plane.update_settings({"research_searxng_url": self.upstream_url}, "test")
        self.upstream.health_body = {"service": "pi", "status": "ok"}

        rendered = json.dumps(self.health())

        self.assertTrue(self.upstream.seen)
        for request in self.upstream.seen:
            self.assertNotIn(PI_KEY, json.dumps(request["headers"]))
            self.assertNotIn("x-pi-service-key", {name.lower() for name in request["headers"]})
        self.assertNotIn(PI_KEY, rendered)

    def test_pi_unreachable_makes_generation_unavailable_without_naming_the_host(self):
        control_plane.update_settings({"research_searxng_url": self.upstream_url}, "test")
        pi_url = _closed_url()
        self.use_pi(pi_url)

        body = self.health()

        self.assertEqual(body["status"], "degraded")
        self.assertEqual(body["degraded"], ["generation"])
        self.assertEqual(body["checks"]["generation"]["status"], "unavailable")
        self.assertEqual(body["checks"]["generation"]["via"], "pi")
        self.assertNotIn(pi_url, json.dumps(body))

    def test_pi_own_degraded_parts_are_not_reported_as_generation(self):
        control_plane.update_settings({"research_searxng_url": self.upstream_url}, "test")
        self.use_pi(self.upstream_url)
        self.upstream.health_body = {"service": "pi", "status": "degraded",
                                     "checks": {"speech": {"status": "unavailable"}}}

        body = self.health()

        self.assertEqual(body["checks"]["generation"], {"status": "ok", "via": "pi"})
        self.assertNotIn("speech", json.dumps(body))

    def test_an_address_that_does_not_answer_as_pi_is_not_generation(self):
        control_plane.update_settings({"research_searxng_url": self.upstream_url}, "test")
        self.use_pi(self.upstream_url)
        for answer in ({"models": []}, {"service": "memorygate", "status": "ok"}):
            with self.subTest(answer=answer):
                self.upstream.health_body = answer
                self.assertEqual(self.health()["checks"]["generation"], {
                    "status": "unavailable", "reason": "invalid_health_response", "via": "pi",
                })

    def test_pi_needs_both_its_address_and_key_before_it_is_the_generation_path(self):
        self.point_upstreams_at(self.upstream_url)
        os.environ["TOOLGATE_PI_URL"] = _closed_url()

        body = self.health()

        self.assertEqual(body["checks"]["generation"], {"status": "ok", "via": "ollama"})
        self.assertIn("/api/tags", [request["path"] for request in self.upstream.seen])

    def test_a_malformed_pi_address_is_unavailable_not_an_error(self):
        control_plane.update_settings({"research_searxng_url": self.upstream_url}, "test")
        for address in ("http://pi\x7fapi:8050", "http://" + "p" * 70 + ":8050"):
            with self.subTest(address=address):
                self.use_pi(address)

                body = self.health()

                self.assertEqual(body["checks"]["generation"]["status"], "unavailable")
                self.assertNotIn("api:8050", json.dumps(body))
