"""Baseline: check Cross-Origin Resource Sharing (CORS) policy.

A single GET carrying a foreign ``Origin`` header shows whether the site
reflects arbitrary origins or uses a wildcard, and whether credentials
are allowed alongside. The pure :func:`check_cors` function grades the
response headers; ``run`` makes exactly one request.
"""

from collections.abc import Mapping

import requests

from gambit.http import TIMEOUT, USER_AGENT, get_for_host
from gambit.models import Finding, Severity

# Re-exported for backwards compatibility; canonical values live in gambit.http.
__all__ = ["TEST_ORIGIN", "USER_AGENT", "TIMEOUT", "check_cors", "evaluate", "run"]

TEST_ORIGIN = "https://gambit-check.example"


def _header(headers: Mapping, name: str) -> str:
    for key, value in headers.items():
        if str(key).lower() == name:
            return str(value).strip()
    return ""


def check_cors(host, headers=None, origin: str = TEST_ORIGIN) -> list[Finding]:
    """Grade CORS response headers. No network access.

    Canonical call: ``check_cors(host, headers)`` mirroring
    ``check_headers(host, headers)``; ``check_cors(headers)`` (no host)
    is also accepted. ``origin`` is the Origin that was sent with the
    request (defaults to :data:`TEST_ORIGIN`).
    """
    # check_cors(headers): shift when the first argument is the headers.
    if isinstance(host, Mapping):
        headers = host
        host = ""

    headers = headers or {}
    allow_origin = _header(headers, "access-control-allow-origin")
    if not allow_origin:
        return []
    credentials = _header(headers, "access-control-allow-credentials").lower() == "true"
    reflected = allow_origin == origin
    wildcard = allow_origin == "*"

    if reflected and credentials:
        severity = Severity.HIGH
        title = "CORS reflects arbitrary origins with credentials"
        why = (
            "Any website can make credentialed cross-origin requests and "
            "read the responses, which can expose authenticated data."
        )
        next_step = (
            "Confirm manually from a foreign origin, then restrict "
            "Access-Control-Allow-Origin to trusted origins."
        )
    elif wildcard and credentials:
        # Browsers reject "*" together with credentials, so this alone
        # is not exploitable -- but it is a misconfiguration that turns
        # dangerous the moment the server starts reflecting origins.
        severity = Severity.MED
        title = "CORS wildcard origin combined with credentials"
        why = (
            "A wildcard origin combined with credentialed requests is an "
            "unsafe policy: browsers currently block reading such "
            "responses, but the configuration is one reflection change "
            "away from exposing authenticated data."
        )
        next_step = (
            "Confirm the effective policy from a foreign origin, then "
            "replace the wildcard with an allowlist of trusted origins."
        )
    elif reflected:
        severity = Severity.MED
        title = "CORS reflects arbitrary Origin headers"
        why = (
            "Reflecting any Origin lets other websites read responses "
            "cross-origin; the impact grows if credentials are ever allowed."
        )
        next_step = (
            "Test whether credentials are allowed alongside the reflected "
            "origin, then restrict reflection to trusted origins."
        )
    elif wildcard:
        severity = Severity.LOW
        title = "CORS allows any origin"
        why = (
            "Any website can read these responses cross-origin. That is "
            "fine for public data but risky for anything user-specific."
        )
        next_step = (
            "Check whether any wildcard-covered endpoints return "
            "sensitive or user-specific data."
        )
    else:
        # A specific, different origin: not exposed to our test origin.
        return []

    evidence = f"Access-Control-Allow-Origin: {allow_origin}"
    if credentials:
        evidence += "; Access-Control-Allow-Credentials: true"
    evidence += f" (test Origin: {origin})"
    return [
        Finding(
            severity=severity,
            host=host,
            title=title,
            evidence=evidence,
            why=why,
            next_step=next_step,
        )
    ]


# Alias in the style of exposed_files.evaluate().
evaluate = check_cors


def run(target: str) -> list[Finding]:
    """Fetch the target once with a test Origin and grade its CORS headers."""
    try:
        response = get_for_host(
            target,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"Origin": TEST_ORIGIN},
        )
    except requests.RequestException as exc:
        return [
            Finding(
                severity=Severity.INFO,
                host=target,
                title="Could not fetch site",
                evidence=str(exc),
                why="The CORS check could not run.",
                next_step="Check the hostname and whether the site is reachable.",
            )
        ]
    return check_cors(target, response.headers)
