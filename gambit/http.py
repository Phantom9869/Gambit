"""Shared HTTP plumbing: the single source of truth for how GAMBIT fetches.

Every module goes through the helpers here so the User-Agent and timeout
stay identical (and honest) everywhere, and so tests / downstream modules
have one obvious seam to fake: ``gambit.http.requests.request`` (or the
individual helpers).

Target fetches additionally get an HTTPS -> HTTP fallback
(:func:`get_for_host` / :func:`options_for_host`): a site that serves
only plain HTTP is still worth checking for headers, CORS, and exposed
files. The scheme that works for a host is remembered for the rest of
the process, so only the first module to touch an HTTP-only host pays
for the failed HTTPS attempt.
"""

import requests

USER_AGENT = (
    "GAMBIT/0.1 (+https://github.com/Phantom9869/gambit; authorized testing only)"
)
TIMEOUT = 10  # seconds

# host (as passed in, e.g. "example.com" or "example.com:8080") -> scheme
_SCHEME_BY_HOST: dict[str, str] = {}


def request(method: str, url: str, *, timeout: float = TIMEOUT, headers: dict | None = None, **kwargs):
    """Send ``method`` to ``url`` with GAMBIT's User-Agent and timeout.

    ``headers`` (if given) are merged over the default User-Agent. Every
    other keyword is forwarded verbatim to :func:`requests.request`.
    Network errors propagate as ``requests.RequestException``.
    """
    merged = {"User-Agent": USER_AGENT}
    if headers:
        merged.update(headers)
    return requests.request(method, url, headers=merged, timeout=timeout, **kwargs)


def get(url: str, *, timeout: float = TIMEOUT, headers: dict | None = None, **kwargs):
    """GET ``url``; see :func:`request`. No scheme fallback (exact URL)."""
    return request("GET", url, timeout=timeout, headers=headers, **kwargs)


def options(url: str, *, timeout: float = TIMEOUT, headers: dict | None = None, **kwargs):
    """OPTIONS ``url``; see :func:`request`. No scheme fallback."""
    return request("OPTIONS", url, timeout=timeout, headers=headers, **kwargs)


def preferred_scheme(host: str) -> str | None:
    """Scheme known to work for ``host`` in this process, if any."""
    return _SCHEME_BY_HOST.get(host)


def set_preferred_scheme(host: str, scheme: str) -> None:
    """Remember that ``scheme`` ("https"/"http") works for ``host``."""
    if scheme in ("https", "http"):
        _SCHEME_BY_HOST[host] = scheme


def clear_scheme_cache() -> None:
    """Forget all remembered schemes (mainly for tests)."""
    _SCHEME_BY_HOST.clear()


def _schemes_to_try(host: str) -> list[str]:
    known = _SCHEME_BY_HOST.get(host)
    if known:
        return [known] + [s for s in ("https", "http") if s != known]
    return ["https", "http"]


def _request_for_host(method: str, target: str, path: str = "", **kwargs):
    """``method`` request to ``target`` + ``path``, HTTPS first, HTTP fallback.

    Only connection-level failures (:class:`requests.RequestException`)
    trigger the fallback; an HTTP error status is a real answer and is
    returned as-is. Raises the last exception if every scheme fails.
    """
    last_exc: Exception | None = None
    for scheme in _schemes_to_try(target):
        try:
            response = request(method, f"{scheme}://{target}{path}", **kwargs)
        except requests.RequestException as exc:
            last_exc = exc
            continue
        set_preferred_scheme(target, scheme)
        return response
    assert last_exc is not None  # _schemes_to_try is never empty
    raise last_exc


def get_for_host(target: str, path: str = "", **kwargs):
    """GET ``target`` (a host, optionally with port) with HTTP fallback."""
    return _request_for_host("GET", target, path, **kwargs)


def options_for_host(target: str, path: str = "", **kwargs):
    """OPTIONS ``target`` with HTTP fallback."""
    return _request_for_host("OPTIONS", target, path, **kwargs)


__all__ = [
    "TIMEOUT",
    "USER_AGENT",
    "clear_scheme_cache",
    "get",
    "get_for_host",
    "options",
    "options_for_host",
    "preferred_scheme",
    "request",
    "set_preferred_scheme",
]
