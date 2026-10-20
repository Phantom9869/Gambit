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
