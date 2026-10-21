import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import requests
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.url import parse_url

import gambit.http as http


class FakeResponse:
    def __init__(self, url):
        self.url = url
        self.status_code = 200
        self.headers = {}


@pytest.fixture(autouse=True)
def clean_cache(monkeypatch):
    http.clear_scheme_cache()
    # Real-socket tests pin to a vetted address. A proxy in the environment
    # would skip that pin and send the request somewhere else.
    for name in (
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
        monkeypatch.delenv(name, raising=False)
    yield
    http.clear_scheme_cache()


def test_get_for_host_prefers_https(monkeypatch):
    monkeypatch.setattr(
        http, "request", lambda method, url, **kw: FakeResponse(url)
    )
    response = http.get_for_host("example.com", "/robots.txt")
    assert response.url == "https://example.com/robots.txt"
    assert http.preferred_scheme("example.com") == "https"


def test_get_for_host_falls_back_to_http_and_caches(monkeypatch):
    attempts = []

    def fake_request(method, url, **kwargs):
        attempts.append(url)
        if url.startswith("https://"):
            raise requests.ConnectionError("no tls")
        return FakeResponse(url)

    monkeypatch.setattr(http, "request", fake_request)
    response = http.get_for_host("example.com")
    assert response.url == "http://example.com"
    assert http.preferred_scheme("example.com") == "http"

    # Second call goes straight to the cached scheme.
    attempts.clear()
    http.get_for_host("example.com", "/.env")
    assert attempts == ["http://example.com/.env"]


def test_get_for_host_raises_when_all_schemes_fail(monkeypatch):
    def fake_request(method, url, **kwargs):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(http, "request", fake_request)
    with pytest.raises(requests.ConnectionError):
        http.get_for_host("example.com")


def test_http_error_status_does_not_trigger_fallback(monkeypatch):
    attempts = []

    def fake_request(method, url, **kwargs):
        attempts.append(url)
        response = FakeResponse(url)
        response.status_code = 404
        return response

    monkeypatch.setattr(http, "request", fake_request)
    response = http.get_for_host("example.com", "/missing")
    assert response.status_code == 404
    assert attempts == ["https://example.com/missing"]


def test_request_merges_user_agent_and_headers(monkeypatch):
    captured = {}

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        captured.update(method=method, url=url, headers=headers, timeout=timeout)
        return FakeResponse(url)

    monkeypatch.setattr(http.requests, "request", fake_request)
    http.get("https://example.com", headers={"Origin": "https://x.example"})
    assert captured["method"] == "GET"
    assert captured["headers"]["User-Agent"] == http.USER_AGENT
    assert captured["headers"]["Origin"] == "https://x.example"


def test_options_uses_shared_request(monkeypatch):
    monkeypatch.setattr(
        http, "request", lambda method, url, **kw: (method, url)
    )
    assert http.options_for_host("example.com") == ("OPTIONS", "https://example.com")


def test_ipv6_literal_is_bracketed_in_the_url(monkeypatch):
    monkeypatch.setattr(http, "request", lambda method, url, **kw: FakeResponse(url))
    response = http.get_for_host("2001:db8::1", "/robots.txt")
    assert response.url == "https://[2001:db8::1]/robots.txt"
    response = http.get_for_host("[::1]")
    assert response.url == "https://[::1]"


def test_cross_host_redirect_is_not_followed(monkeypatch):
    calls = []

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        calls.append(url)

        class Response:
            def __init__(self, url):
                self.url = url
                self.status_code = 302
                self.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}

            def close(self):
                pass

        return Response(url)

    monkeypatch.setattr(http.requests, "request", fake_request)
    response = http.get("http://example.com/")
    assert calls == ["http://example.com/"]
    assert response.status_code == 302
    assert response.gambit_redirects == 0


def test_same_host_redirect_followed_when_address_is_public(monkeypatch):
    monkeypatch.setattr(http, "resolve_ips", lambda host, timeout: ["93.184.216.34"])
    calls = []

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        calls.append(url)

        class Response:
            def __init__(self, url):
                self.url = url
                self.status_code = 200 if url.endswith("/next") else 302
                self.headers = {} if self.status_code == 200 else {"Location": "http://example.com/next"}

            def close(self):
                pass

            def iter_content(self, chunk_size=8192):
                yield b"ok"

        return Response(url)

    monkeypatch.setattr(http.requests, "request", fake_request)
    response = http.get("http://example.com/")
    assert calls == ["http://example.com/", "http://example.com/next"]
    assert response.gambit_redirects == 1
    assert response.gambit_final_url == "http://example.com/next"
    note = http.annotate_findings(
        [type("F", (), {"evidence": "Server: nginx"})()],
        response,
    )
    assert "final URL: http://example.com/next" in note[0].evidence


def test_same_host_redirect_to_a_private_address_is_not_followed(monkeypatch):
    monkeypatch.setattr(http, "resolve_ips", lambda host, timeout: ["127.0.0.1"])
    calls = []

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        calls.append(url)

        class Response:
            def __init__(self, url):
                self.url = url
                self.status_code = 302
                self.headers = {"Location": "http://example.com/admin"}

            def close(self):
                pass

        return Response(url)

    monkeypatch.setattr(http.requests, "request", fake_request)
    response = http.get("http://example.com/")
    assert calls == ["http://example.com/"]
    assert response.gambit_redirects == 0


def test_redirect_chain_is_capped(monkeypatch):
    monkeypatch.setattr(http, "resolve_ips", lambda host, timeout: ["93.184.216.34"])
    calls = []

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        calls.append(url)

        class Response:
            def __init__(self, url):
                self.url = url
                self.status_code = 302
                hop = len(calls)
                self.headers = {"Location": f"http://example.com/r{hop}"}

            def close(self):
                pass

        return Response(url)

    monkeypatch.setattr(http.requests, "request", fake_request)
    http.get("http://example.com/start")
    assert len(calls) == http.MAX_REDIRECTS + 1


def test_response_body_is_capped(monkeypatch):
    class Response:
        status_code = 200
        headers = {}
        url = "https://example.com/"

        def iter_content(self, chunk_size=8192):
            yield b"A" * 100
            yield b"B" * 100

        def close(self):
            pass

    monkeypatch.setattr(http.requests, "request", lambda *args, **kwargs: Response())
    response = http.get("https://example.com/", max_bytes=150)
    assert response._content == (b"A" * 100) + (b"B" * 50)


class _RecordingHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._respond()

    def do_HEAD(self):
        self._respond(write_body=False)

    def _respond(self, write_body=True):
        self.server.seen.append((self.path, self.headers.get("Host", "")))
        route = self.server.routes.get(self.path)
        if route is None:
            status, headers, body = 404, {}, b"missing"
        else:
            status, headers, body = route
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if write_body:
            self.wfile.write(body)

    def log_message(self, format, *args):
        return


def _serve(routes):
    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
    server.routes = routes
    server.seen = []
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _close_server(server):
    server.shutdown()
    server.server_close()


class _Listener(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.hits = []
        self._done = threading.Event()

    def run(self):
        while not self._done.is_set():
            try:
                conn, _addr = self.sock.accept()
            except socket.timeout:
                continue
            self.hits.append(conn.getpeername())
            conn.close()

    def close(self):
        self._done.set()
        self.join(timeout=1)
        self.sock.close()


def _redirect_response(location, calls):
    class Response:
        def __init__(self):
            self.url = calls[-1]
            self.status_code = 302 if len(calls) == 1 else 200
            self.headers = {"Location": location} if self.status_code == 302 else {}

        def close(self):
            return None

        def iter_content(self, chunk_size=8192):
            yield b""

    return Response()


def test_backslash_location_is_not_fetched_from_the_real_connection_target(monkeypatch):
    """urlsplit sees example.com; requests connects to 127.0.0.1. Do not follow.

    resolve_ips is the only stand-in, and it reports a public address, which
    is the condition that used to let the check pass. The transport still
    parses the URL the way requests does and dials that host for real.
    """
    listener = _Listener()
    listener.start()
    calls = []
    attempted = []
    location = f"http://127.0.0.1:{listener.port}\\@example.com/secret"

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        calls.append(url)
        prepared = requests.Request("GET", url).prepare().url
        parsed = parse_url(prepared)
        if parsed.host == "127.0.0.1" and parsed.port == listener.port:
            attempted.append(prepared)
            sock = socket.create_connection(("127.0.0.1", listener.port), timeout=1)
            sock.close()
        return _redirect_response(location, calls)

    monkeypatch.setattr(http.requests, "request", fake_request)
    monkeypatch.setattr(http, "resolve_ips", lambda host, timeout: ["93.184.216.34"])
    try:
        response = http.get("http://example.com/")
        time.sleep(0.3)
    finally:
        listener.close()
    assert response.status_code == 302
    assert response.gambit_redirects == 0
    assert calls == ["http://example.com/"]
    assert attempted == []
    assert listener.hits == []


def test_parser_differential_is_blocked_without_the_character_filter(monkeypatch):
    """The prepared-URL host, not the backslash filter, has to stop this."""
    monkeypatch.setattr(http, "_location_is_acceptable", lambda location: bool(location))
    listener = _Listener()
    listener.start()
    calls = []
    attempted = []
    location = f"http://127.0.0.1:{listener.port}\\@example.com/secret"

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        calls.append(url)
        prepared = requests.Request("GET", url).prepare().url
        parsed = parse_url(prepared)
        if parsed.host == "127.0.0.1" and parsed.port == listener.port:
            attempted.append(prepared)
            sock = socket.create_connection(("127.0.0.1", listener.port), timeout=1)
            sock.close()
        return _redirect_response(location, calls)

    monkeypatch.setattr(http.requests, "request", fake_request)
    monkeypatch.setattr(http, "resolve_ips", lambda host, timeout: ["93.184.216.34"])
    try:
        response = http.get("http://example.com/start")
        time.sleep(0.3)
    finally:
        listener.close()
    assert response.gambit_redirects == 0
    assert len(calls) == 1
    assert attempted == []
    assert listener.hits == []
    prepared = requests.Request("GET", location).prepare().url
    assert parse_url(prepared).host == "127.0.0.1"
    assert parse_url(prepared).port == listener.port


def test_percent_encoded_backslash_and_at_sign_do_not_reach_a_private_host(monkeypatch):
    listener = _Listener()
    listener.start()
    cases = [
        f"http://127.0.0.1:{listener.port}%5C@example.com/secret",
        f"http://127.0.0.1:{listener.port}%5c@example.com/secret",
        f"http://example.com@127.0.0.1:{listener.port}/secret",
    ]
    try:
        for location in cases:
            calls = []
            attempted = []

            def fake_request(method, url, headers=None, timeout=None, location=location, **kwargs):
                calls.append(url)
                prepared = requests.Request("GET", url).prepare().url
                parsed = parse_url(prepared)
                if parsed.host == "127.0.0.1" and parsed.port == listener.port:
                    attempted.append(prepared)
                    sock = socket.create_connection(("127.0.0.1", listener.port), timeout=1)
                    sock.close()
                return _redirect_response(location, calls)

            monkeypatch.setattr(http.requests, "request", fake_request)
            monkeypatch.setattr(http, "resolve_ips", lambda host, timeout: ["93.184.216.34"])
            response = http.get("http://example.com/")
            assert response.gambit_redirects == 0 or all(
                parse_url(requests.Request("GET", url).prepare().url).host == "example.com"
                for url in calls
            )
            assert attempted == []
        time.sleep(0.3)
        assert listener.hits == []
    finally:
        listener.close()


def test_whitespace_and_control_characters_in_location_are_not_followed(monkeypatch):
    calls = []

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        calls.append(url)

        class Response:
            status_code = 302
            headers = {"Location": "http://127.0.0.1\t@example.com/"}

            def __init__(self):
                self.url = url

            def close(self):
                return None

        return Response()

    monkeypatch.setattr(http.requests, "request", fake_request)
    monkeypatch.setattr(http, "resolve_ips", lambda host, timeout: ["93.184.216.34"])
    response = http.get("http://example.com/")
    assert calls == ["http://example.com/"]
    assert response.gambit_redirects == 0


def test_private_literals_follow_a_same_host_scheme_change(monkeypatch):
    calls = []

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        calls.append(url)

        class Response:
            def __init__(self, url):
                self.url = url
                https = url.startswith("https://")
                self.status_code = 200 if https else 301
                if https:
                    self.headers = {}
                else:
                    self.headers = {"Location": "https://" + url[len("http://") :]}

            def close(self):
                return None

            def iter_content(self, chunk_size=8192):
                yield b"ok"

        return Response(url)

    monkeypatch.setattr(http.requests, "request", fake_request)
    for origin in (
        "http://127.0.0.1/r",
        "http://10.1.2.3/r",
        "http://192.168.1.9/r",
        "http://[::1]/r",
    ):
        calls.clear()
        response = http.get(origin)
        assert response.gambit_redirects == 1, origin
        assert calls[1].startswith("https://"), calls
        assert response.gambit_final_url == calls[1]


def test_relative_and_scheme_relative_redirects_on_a_private_target():
    server = _serve({})
    port = server.server_address[1]
    host = f"127.0.0.1:{port}"
    server.routes = {
        "/r": (302, {"Location": "/next"}, b""),
        "/next": (302, {"Location": f"//{host}/done"}, b""),
        "/done": (200, {}, b"done"),
    }
    try:
        response = http.get(f"http://127.0.0.1:{port}/r", timeout=2)
    finally:
        _close_server(server)
    assert response.status_code == 200
    assert response.content == b"done"
    assert response.gambit_redirects == 2
    assert [path for path, _host in server.seen] == ["/r", "/next", "/done"]


def test_private_target_does_not_follow_a_cross_host_redirect():
    server = _serve({"/r": (302, {"Location": "http://127.0.0.2/secret"}, b"stay")})
    port = server.server_address[1]
    try:
        response = http.get(f"http://127.0.0.1:{port}/r", timeout=2)
    finally:
        _close_server(server)
    assert response.status_code == 302
    assert response.gambit_redirects == 0
    assert [path for path, _host in server.seen] == ["/r"]


def test_public_name_resolving_private_does_not_follow_redirect(monkeypatch):
    server = _serve({})
    port = server.server_address[1]
    server.routes = {
        "/r": (302, {"Location": f"http://example.com:{port}/secret"}, b""),
        "/secret": (200, {}, b"nope"),
    }
    monkeypatch.setattr(http, "resolve_ips", lambda host, timeout: ["127.0.0.1"])
    try:
        response = http.get(f"http://example.com:{port}/r", timeout=2)
    finally:
        _close_server(server)
    assert response.status_code == 302
    assert response.gambit_redirects == 0
    assert [path for path, _host in server.seen] == ["/r"]


def test_connection_uses_vetted_ips_when_getaddrinfo_changes(monkeypatch):
    server = _serve({"/": (200, {}, b"pinned")})
    port = server.server_address[1]

    def blackhole(host, port, family=0, type=0, proto=0, flags=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.1", port or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", blackhole)
    monkeypatch.setattr(http, "resolve_ips", lambda host, timeout: ["127.0.0.1"])
    try:
        response = http.get(f"http://rebind.example:{port}/", timeout=2)
    finally:
        _close_server(server)
    assert response.status_code == 200
    assert response.content == b"pinned"
    assert server.seen == [("/", f"rebind.example:{port}")]


def test_private_redirect_stays_on_the_vetted_address(monkeypatch):
    server = _serve(
        {
            "/r": (301, {"Location": "/x"}, b""),
            "/x": (200, {}, b"ok"),
        }
    )
    port = server.server_address[1]

    def blackhole(host, port, family=0, type=0, proto=0, flags=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.1", port or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", blackhole)
    try:
        response = http.get(f"http://127.0.0.1:{port}/r", timeout=2)
    finally:
        _close_server(server)
    assert response.status_code == 200
    assert response.content == b"ok"
    assert response.gambit_redirects == 1
    assert response.gambit_final_url == f"http://127.0.0.1:{port}/x"
    assert [path for path, _host in server.seen] == ["/r", "/x"]


def test_configured_proxy_does_not_follow_redirects(monkeypatch):
    calls = []

    def fake_request(method, url, headers=None, timeout=None, **kwargs):
        calls.append(url)

        class Response:
            status_code = 302
            headers = {"Location": "https://example.com/next"}

            def __init__(self):
                self.url = url

            def close(self):
                return None

        return Response()

    monkeypatch.setattr(http.requests, "request", fake_request)
    monkeypatch.setattr(http, "resolve_ips", lambda host, timeout: ["93.184.216.34"])
    response = http.get("http://example.com/", proxies={"http": "http://127.0.0.1:9"})
    assert calls == ["http://example.com/"]
    assert response.gambit_redirects == 0

    calls.clear()
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
    response = http.get("http://example.com/")
    assert calls == ["http://example.com/"]
    assert response.gambit_redirects == 0


def test_private_literal_follows_http_to_https_against_a_local_server():
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is required to mint a certificate")
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        key = directory / "key.pem"
        cert = directory / "cert.pem"
        subprocess.run(
            [
                openssl,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
            ],
            check=True,
            capture_output=True,
        )
        https = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
        https.routes = {"/x": (200, {}, b"secure")}
        https.seen = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        https.socket = context.wrap_socket(https.socket, server_side=True)
        https_port = https.server_address[1]
        https_thread = threading.Thread(target=https.serve_forever, daemon=True)
        https_thread.start()
        http_server = _serve(
            {
                "/r": (
                    301,
                    {"Location": f"https://127.0.0.1:{https_port}/x"},
                    b"",
                )
            }
        )
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InsecureRequestWarning)
                response = http.get(
                    f"http://127.0.0.1:{http_server.server_address[1]}/r",
                    timeout=2,
                    verify=False,
                )
        finally:
            _close_server(http_server)
            https.shutdown()
            https.server_close()
    assert response.status_code == 200
    assert response.content == b"secure"
    assert response.gambit_redirects == 1
    assert response.gambit_final_url == f"https://127.0.0.1:{https_port}/x"
