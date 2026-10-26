"""Tests for sandbox package proxy."""

import http.client
import os
import socket
import threading
import time

import pytest

# Only import on POSIX systems
if os.name != "nt":
    from toolgate.sandbox import proxy
else:
    # Create dummy imports for Windows
    proxy = None


@pytest.mark.skipif(proxy is None, reason="Proxy module not available")
class TestRoute:
    """Test URL routing validation."""

    def test_allowed_pypi_simple_routes(self):
        routes = [
            "/pypi/simple/requests/",
            "/pypi/simple/numpy/",
            "/pypi/simple/flask/",
        ]

        for route_path in routes:
            result = proxy.route(route_path)
            assert result is not None
            upstream_host, upstream_path, cap, kind = result
            assert upstream_host == proxy.PYPI
            assert upstream_path.startswith("/simple/")
            assert cap == proxy.METADATA_MAX
            assert kind == "pypi-index"

    def test_allowed_pypi_files_routes(self):
        routes = [
            "/pypi/files/packages/ab/cd/x-1.0-py3-none-any.whl",
            "/pypi/files/packages/ab/cd/x-1.0.tar.gz.metadata",
            "/pypi/files/packages/00/01/simple-package-2.0.0.tar.gz",
        ]

        for route_path in routes:
            result = proxy.route(route_path)
            assert result is not None
            upstream_host, upstream_path, cap, kind = result
            assert upstream_host == proxy.FILES
            assert upstream_path.startswith("/")
            assert cap == proxy.ARCHIVE_MAX
            assert kind in ("pypi-file", "pypi-file")

    def test_allowed_npm_routes(self):
        routes = [
            "/npm/lodash",
            "/npm/@types%2fnode",
            "/npm/@types/node",
            "/npm/lodash/-/lodash-4.17.21.tgz",
            "/npm/@types/node/-/node-22.0.0.tgz",
        ]

        for route_path in routes:
            result = proxy.route(route_path)
            assert result is not None
            upstream_host, _upstream_path, cap, kind = result
            assert upstream_host == proxy.NPM
            if "tgz" in route_path:
                assert cap == proxy.ARCHIVE_MAX
                assert kind == "npm-tarball"
            else:
                assert cap == proxy.METADATA_MAX
                assert kind == "npm-metadata"

    def test_refused_routes(self):
        refused_routes = [
            "/",  # Root
            "/pypi/simple/",  # No package name
            "/pypi/simple/../x/",  # Path traversal
            "/pypi/files/../../etc/passwd",  # Path traversal
            "http://example.com/",  # Absolute URL
            "/npm/../x",  # Path traversal
            "/npm/-/npm/v1/security/advisories/bulk",  # Not allowed npm path
            "/npm/lodash?write=true",  # Query string
            "//evil.com/x",  # Double slash
            "/pypi/simple/requests",  # Missing trailing slash
            "/github/x",  # Wrong host
            "/pypi/files/packages/a//b",  # Double slash in path
        ]

        for route_path in refused_routes:
            result = proxy.route(route_path)
            assert result is None


@pytest.mark.skipif(proxy is None, reason="Proxy module not available")
class TestRewrite:
    """Test URL rewriting in responses."""

    def test_pypi_index_rewrite(self):
        body = b'https://files.pythonhosted.org/packages/a/b.whl'
        rewritten = proxy.rewrite("pypi-index", body, "example.com:3128")
        assert rewritten == b'/pypi/files/packages/a/b.whl'

    def test_npm_metadata_rewrite_local_host(self):
        body = b'https://registry.npmjs.org/lodash'
        rewritten = proxy.rewrite("npm-metadata", body, "127.0.0.1:3128")
        assert rewritten == b'http://127.0.0.1:3128/npm/lodash'

    def test_npm_metadata_no_rewrite_external_host(self):
        body = b'https://registry.npmjs.org/lodash'
        rewritten = proxy.rewrite("npm-metadata", body, "evil.com:80")
        assert rewritten == body  # Unchanged

    def test_other_kinds_not_rewritten(self):
        body = b'https://example.com/something'
        rewritten = proxy.rewrite("other", body, "localhost:3128")
        assert rewritten == body  # Unchanged


@pytest.mark.skipif(proxy is None, reason="Proxy module not available")
class TestLocation:
    """Test Location header rewriting."""

    def test_allowed_pypi_redirect(self):
        location = "https://pypi.org/simple/foo/"
        rewritten = proxy.location(location)
        assert rewritten == "/pypi/simple/foo/"

    def test_refused_evil_redirect(self):
        location = "https://evil.com/x"
        rewritten = proxy.location(location)
        assert rewritten is None

    def test_refused_pypi_admin(self):
        location = "https://pypi.org/admin"
        rewritten = proxy.location(location)
        assert rewritten is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX only")
@pytest.mark.skipif(proxy is None, reason="Proxy module not available")
class TestPosixOnly:
    """POSIX-only tests with real HTTP server."""

    @pytest.mark.skipif(os.name == "nt", reason="POSIX only")
    def test_real_proxy_server_allowed_methods(self, tmp_path, monkeypatch):
        socket_path = tmp_path / "test.sock"

        # Start proxy server
        clients = {os.getuid()}
        server = proxy.Server(str(socket_path), clients)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        try:
            time.sleep(0.1)  # Let server start

            # Test allowed GET request
            self._make_http_request(socket_path, "GET", "/npm/lodash")

        finally:
            server.shutdown()
            socket_path.unlink(missing_ok=True)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX only")
    def test_real_proxy_server_refused_methods(self, tmp_path, monkeypatch):
        socket_path = tmp_path / "test.sock"

        # Mock HTTPSConnection to track if it's constructed
        original_https = http.client.HTTPSConnection
        https_constructed = []

        def tracking_https(*args, **kwargs):
            https_constructed.append(True)
            raise Exception("Should not construct HTTPS")

        monkeypatch.setattr(http.client, "HTTPSConnection", tracking_https)

        # Start proxy server
        clients = {os.getuid()}
        server = proxy.Server(str(socket_path), clients)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        try:
            time.sleep(0.1)  # Let server start

            # Test refused methods
            for method in ["POST", "PUT", "DELETE"]:
                response = self._make_http_request(socket_path, method, "/npm/lodash")
                assert response.status == 405

            # Test forbidden path
            response = self._make_http_request(socket_path, "GET", "/etc/passwd")
            assert response.status == 404

            # HTTPS connection should not have been constructed
            assert len(https_constructed) == 0

        finally:
            server.shutdown()
            socket_path.unlink(missing_ok=True)
            monkeypatch.setattr(http.client, "HTTPSConnection", original_https)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX only")
    def test_server_refuses_wrong_uid(self, tmp_path, monkeypatch):
        socket_path = tmp_path / "test.sock"

        # Start server with wrong UID
        clients = {os.getuid() + 1}
        server = proxy.Server(str(socket_path), clients)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        try:
            time.sleep(0.1)  # Let server start

            # Try to connect - should be closed without response
            with pytest.raises(ConnectionResetError):
                self._make_http_request(socket_path, "GET", "/npm/lodash")

        finally:
            server.shutdown()
            socket_path.unlink(missing_ok=True)

    def _make_http_request(self, socket_path, method, path):
        """Helper to make HTTP request over Unix socket."""

        class UnixHTTPConnection(http.client.HTTPConnection):
            def __init__(self, path):
                super().__init__("localhost")
                self.path = path

            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(self.path)

        conn = UnixHTTPConnection(str(socket_path))
        try:
            conn.request(method, path)
            return conn.getresponse()
        finally:
            conn.close()


@pytest.mark.skipif(proxy is None, reason="Proxy module not available")
class TestRouteSpecificCases:
    """Additional specific routing tests."""

    def test_npm_scoped_package_encoding(self):
        # Test that %2F encoding is handled correctly
        result = proxy.route("/npm/@types%2fnode")
        assert result is not None
        upstream_host, upstream_path, _cap, kind = result
        assert upstream_host == proxy.NPM
        assert upstream_path == "/@types%2fnode"  # Should preserve encoding for metadata
        assert kind == "npm-metadata"

    def test_npm_tarball_encoding_decode(self):
        # Test that %2F is decoded for tarballs
        result = proxy.route("/npm/@types%2fnode/-/node-22.0.0.tgz")
        assert result is not None
        upstream_host, upstream_path, _cap, kind = result
        assert upstream_host == proxy.NPM
        assert upstream_path == "/@types/node/-/node-22.0.0.tgz"  # Should decode for tarball
        assert kind == "npm-tarball"

    def test_pypi_files_path_validation(self):
        # Test various valid pypi files paths
        valid_paths = [
            "/pypi/files/packages/ab/cd/ef/package-1.0.0-py3-none-any.whl",
            "/pypi/files/packages/00/01/02/simple.tar.gz",
            "/pypi/files/packages/ab/cd/ef/package-1.0.0.tar.gz.metadata",
        ]

        for path in valid_paths:
            result = proxy.route(path)
            assert result is not None
            assert result[0] == proxy.FILES  # Upstream host
            assert result[3] in ("pypi-file", "pypi-file")  # Kind

    def test_npm_name_validation(self):
        # Test various valid npm package names
        valid_names = [
            "lodash",
            "@types/node",
            "@babel/core",
            "react-dom",
            "express",
        ]

        for name in valid_names:
            # Test metadata route
            result = proxy.route(f"/npm/{name}")
            assert result is not None
            assert result[0] == proxy.NPM
            assert result[3] == "npm-metadata"


@pytest.mark.skipif(proxy is None, reason="Proxy module not available")
class TestRewriteEdgeCases:
    """Test edge cases in URL rewriting."""

    def test_empty_body_rewrite(self):
        body = b""
        rewritten = proxy.rewrite("pypi-index", body, "localhost:3128")
        assert rewritten == body

    def test_no_matches_in_body(self):
        body = b"https://example.com/something-else"
        rewritten = proxy.rewrite("pypi-index", body, "localhost:3128")
        assert rewritten == body

    def test_multiple_matches(self):
        body = b"https://files.pythonhosted.org/packages/a.whl and https://files.pythonhosted.org/packages/b.whl"
        rewritten = proxy.rewrite("pypi-index", body, "localhost:3128")
        expected = b"/pypi/files/packages/a.whl and /pypi/files/packages/b.whl"
        assert rewritten == expected

    def test_npm_rewrite_case_sensitivity(self):
        # Test that rewrite is case-sensitive for host matching
        body = b'https://registry.npmjs.org/lodash'
        rewritten = proxy.rewrite("npm-metadata", body, "LOCALHOST:3128")
        assert rewritten == body  # No rewrite due to case mismatch


@pytest.mark.skipif(proxy is None, reason="Proxy module not available")
class TestLocationEdgeCases:
    """Test edge cases in location rewriting."""

    def test_location_without_scheme(self):
        location = "/simple/foo/"
        rewritten = proxy.location(location)
        assert rewritten == "/pypi" + location

    def test_location_malformed(self):
        locations = [
            "not-a-url",
            "https://",
            "ftp://example.com/file",
        ]

        for location in locations:
            rewritten = proxy.location(location)
            assert rewritten is None

    def test_location_query_and_fragment(self):
        # Queries and fragments are never passed on: the proxy serves fixed path shapes only.
        location = "https://pypi.org/simple/foo/?query=1#fragment"
        assert proxy.location(location) is None

    def test_location_subdirectory(self):
        location = "https://pypi.org/simple/foo/bar/"
        rewritten = proxy.location(location)
        assert rewritten is None  # Subdirectory not allowed
