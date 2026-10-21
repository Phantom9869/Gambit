"""Baseline: check a site's HTTP security headers."""

import requests

from gambit.http import TIMEOUT, USER_AGENT, annotate_findings, get_for_host
from gambit.models import Finding, Severity

# Re-exported for backwards compatibility; canonical values live in gambit.http.
__all__ = ["EXPECTED_HEADERS", "USER_AGENT", "TIMEOUT", "check_headers", "run"]

# header name (lowercase) -> (severity if missing, why it matters, next step)
# Severities are judgment calls; adjust them as you learn more.
EXPECTED_HEADERS = {
    "strict-transport-security": (
        Severity.MED,
        "Without HSTS, browsers can be tricked into using plain HTTP, "
        "which enables downgrade and interception attacks.",
        "Check whether HTTP redirects to HTTPS and whether cookies lack the Secure flag.",
    ),
    "content-security-policy": (
        Severity.MED,
        "With no CSP, the browser has no second line of defense if an XSS bug exists.",
        "Look for injection points; a missing CSP makes XSS easier to exploit.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Browsers may MIME-sniff responses, which can turn uploaded files into scripts.",
        "Check upload and user-content endpoints.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "The site may be framed by other origins, which enables clickjacking.",
        "Test whether sensitive actions (login, payments, settings) can be framed.",
    ),
    "referrer-policy": (
        Severity.INFO,
        "Full URLs, possibly containing tokens, may leak to other sites via the Referer header.",
        "Check whether URLs on this site ever contain sensitive values.",
    ),
}


def check_headers(host: str, headers: dict) -> list[Finding]:
    """Compare response headers against EXPECTED_HEADERS. No network access."""
    present = {name.lower(): value for name, value in headers.items()}
    findings = []

    for name, (severity, why, next_step) in EXPECTED_HEADERS.items():
        if name in present:
            continue
        # CSP's frame-ancestors directive replaces X-Frame-Options.
        if name == "x-frame-options" and "frame-ancestors" in present.get(
            "content-security-policy", ""
        ):
            continue
        findings.append(
            Finding(
                severity=severity,
                host=host,
                title=f"Missing {name} header",
                evidence=f"Header '{name}' not present in the response",
                why=why,
                next_step=next_step,
            )
        )
    return findings


def run(target: str) -> list[Finding]:
    """Fetch the target (HTTPS, falling back to HTTP) and check headers."""
    try:
        response = get_for_host(
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
                why="The headers check could not run.",
                next_step="Check the hostname and whether the site is reachable.",
            )
        ]
    return annotate_findings(check_headers(target, response.headers), response)
