import pytest
import requests

import gambit.http as http


class FakeResponse:
    def __init__(self, url):
        self.url = url
        self.status_code = 200
        self.headers = {}


@pytest.fixture(autouse=True)
def clean_cache():
    http.clear_scheme_cache()
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
