"""Shared HTTP plumbing: the single source of truth for how GAMBIT fetches.

Every module goes through :func:`get` so the User-Agent and timeout stay
identical (and honest) everywhere, and so tests / downstream modules have
one obvious seam to fake: ``gambit.http.requests.get`` or ``gambit.http.get``.
"""

import requests

USER_AGENT = (
    "GAMBIT/0.1 (+https://github.com/Phantom9869/gambit; authorized testing only)"
)
TIMEOUT = 10  # seconds


def get(url: str, *, timeout: float = TIMEOUT, headers: dict | None = None, **kwargs):
    """GET ``url`` with GAMBIT's User-Agent and timeout.

    ``headers`` (if given) are merged over the default User-Agent, so a
    caller can add e.g. an ``Origin`` header or deliberately override the
    User-Agent. Every other keyword (``allow_redirects``, ``stream``, ...)
    is forwarded verbatim to :func:`requests.get`, whose ``Response`` is
    returned unchanged. Network errors propagate as
    ``requests.RequestException`` — callers decide how to report them
    (the established convention is a single INFO finding from ``run()``).
    """
    merged = {"User-Agent": USER_AGENT}
    if headers:
        merged.update(headers)
    return requests.get(url, headers=merged, timeout=timeout, **kwargs)


__all__ = ["USER_AGENT", "TIMEOUT", "get"]
