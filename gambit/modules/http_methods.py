"""Baseline: check which HTTP methods the server says it allows.

Only an ``OPTIONS`` request is ever sent -- GAMBIT never actually tries
``PUT``/``DELETE``/``TRACE`` against a target. The ``Allow`` header in
the response is parsed by the pure :func:`check_methods` function:
``TRACE`` is flagged MED and write methods (``PUT``/``DELETE``/``PATCH``)
LOW, because an ``Allow`` header is a claim, not proof the methods work
unauthenticated.
"""

from collections.abc import Mapping

import requests

from gambit.http import TIMEOUT, USER_AGENT, options_for_host
from gambit.models import Finding, Severity

# Re-exported for consistency; canonical values live in gambit.http.
__all__ = [
    "USER_AGENT",
    "TIMEOUT",
    "WRITE_METHODS",
    "parse_allow",
    "check_methods",
    "check_allow",
    "evaluate",
    "run",
]

# POST is deliberately excluded: it is expected on most interactive sites.
WRITE_METHODS = frozenset({"PUT", "DELETE", "PATCH"})


def parse_allow(allow) -> list[str]:
    """Parse an ``Allow`` value into an ordered, deduped method list.

    Accepts a header string (``"GET, POST, OPTIONS"``), a headers
    mapping (its ``Allow`` value is used), an iterable of methods, or
    ``None``. Methods are returned uppercased.
    """
    if allow is None:
        return []
    if isinstance(allow, Mapping):
        value = ""
        for key, item in allow.items():
            if str(key).lower() == "allow":
                value = str(item)
                break
        allow = value
    if isinstance(allow, str):
        parts = allow.split(",")
    else:
        parts = [str(item) for item in allow]

    methods: list[str] = []
    for part in parts:
        tokens = part.strip().upper().split(";", 1)[0].split()
        method = tokens[0] if tokens else ""
        if method and method not in methods:
            methods.append(method)
    return methods


def check_methods(host, allow=None) -> list[Finding]:
    """Flag TRACE / write methods in an ``Allow`` value. No network access.

    Canonical call: ``check_methods(host, allow_header)`` mirroring
    ``check_headers(host, headers)``; the header may be a string, a
    headers mapping, or an iterable of methods. ``check_methods(allow)``
    (no host) is also accepted.
    """
    # check_methods(allow): shift when there is no separate host argument
    # and the first argument cannot be a bare hostname for our purposes
    # (it is a mapping, an iterable, or contains a comma/space).
    if allow is None and (
        isinstance(host, Mapping)
        or not isinstance(host, str)
        or "," in host
        or " " in host
    ):
        allow = host
        host = ""

    methods = parse_allow(allow)
    if not methods:
        return []
    allow_text = ", ".join(methods)
    findings: list[Finding] = []

    if "TRACE" in methods:
        findings.append(
            Finding(
                severity=Severity.MED,
                host=host,
                title="TRACE method enabled (per Allow header)",
                evidence=f"Allow: {allow_text}",
                why=(
                    "TRACE echoes requests back and can help cross-site "
                    "tracing attacks; it is rarely needed in production."
                ),
                next_step=(
                    "Confirm manually whether TRACE actually responds, "
                    "then disable it in the server configuration."
                ),
            )
        )

    write = [method for method in methods if method in WRITE_METHODS]
    if write:
        findings.append(
            Finding(
                severity=Severity.LOW,
                host=host,
                title=f"Write HTTP methods enabled: {', '.join(write)} (per Allow header)",
                evidence=f"Allow: {allow_text}",
                why=(
                    "Write methods can create, replace, or delete "
                    "resources. The Allow header only claims they exist, "
                    "so this is unverified and flagged low."
                ),
                next_step=(
                    "Check manually (without modifying data) whether "
                    "write methods require authentication on sensitive paths."
                ),
            )
        )
    return findings


# Aliases in the style of the other modules' pure functions.
check_allow = check_methods
evaluate = check_methods


def run(target: str) -> list[Finding]:
    """Send one OPTIONS request and flag dangerous methods in ``Allow``."""
    try:
        response = options_for_host(
            target,
            timeout=TIMEOUT,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return [
            Finding(
                severity=Severity.INFO,
                host=target,
                title="Could not fetch site",
                evidence=str(exc),
                why="The HTTP methods check could not run.",
                next_step="Check the hostname and whether the site is reachable.",
            )
        ]
    return check_methods(target, response.headers)
