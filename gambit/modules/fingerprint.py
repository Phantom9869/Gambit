"""Analyze: fingerprint the technology stack from headers, cookies, and HTML.

One GET of ``/`` feeds the pure :func:`identify` function, which emits
INFO findings for every technology it can name and a LOW finding when a
header discloses an exact version. Cookie *values* and page contents are
never copied into evidence -- only names and markers are.
"""

import re
from collections.abc import Mapping

import requests

from gambit.http import TIMEOUT, USER_AGENT, get
from gambit.models import Finding, Severity

# Re-exported for backwards compatibility; canonical values live in gambit.http.
__all__ = [
    "COOKIE_TECHNOLOGIES",
    "HTML_MARKERS",
    "USER_AGENT",
    "TIMEOUT",
    "identify",
    "run",
]

# Cookie name (lowercase) -> technology it strongly suggests.
COOKIE_TECHNOLOGIES = {
    "phpsessid": "PHP",
    "jsessionid": "Java (servlet container)",
    "asp.net_sessionid": "ASP.NET",
    "aspsessionid": "Classic ASP",
    "csrftoken": "Django",
    "sessionid": "Django",
    "xsrf-token": "Angular / XSRF-protected app",
    "_xsrf": "Tornado / Jupyter-style app",
    "laravel_session": "Laravel (PHP)",
    "connect.sid": "Express (Node.js)",
    "wordpress_logged_in": "WordPress",
    "wp-settings": "WordPress",
}

# Strong substrings in the HTML body -> technology. Only markers that are
# very unlikely to appear by accident belong here (no bare "react", say).
HTML_MARKERS = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    "__next_data__": "Next.js",
    "data-reactroot": "React",
    "/static/admin/": "Django admin",
    "__nuxt": "Nuxt",
    "_nuxt/": "Nuxt",
    "drupal-settings-json": "Drupal",
    "data-drupal": "Drupal",
}

_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
_GENERATOR_RE = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""",
    re.IGNORECASE,
)
# The generator meta tag may put content before name.
_GENERATOR_REVERSED_RE = re.compile(
    r"""<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']""",
    re.IGNORECASE,
)


def _version_in(value: str) -> str | None:
    """Return the first dotted version number in ``value``, if any."""
    match = _VERSION_RE.search(value or "")
    return match.group(0) if match else None


def _cookie_names(cookies) -> list[str]:
    """Extract cookie names (never values) from any common cookie shape.

    Accepts a mapping (name -> value), a single ``Set-Cookie`` string,
    an iterable of ``Set-Cookie`` strings, an iterable of names, or an
    iterable of cookie objects with a ``name`` attribute (as in a
    ``requests`` cookie jar).
    """
    if cookies is None:
        return []
    if isinstance(cookies, Mapping):
        return [str(name) for name in cookies.keys()]
    if isinstance(cookies, str):
        cookies = [cookies]

    names = []
    for item in cookies:
        name = getattr(item, "name", None)
        if name:
            names.append(str(name))
            continue
        text = str(item).strip()
        if not text:
            continue
        # A Set-Cookie value: the name is everything before the first '='.
        # A bare name contains no '=' at all.
        names.append(text.split("=", 1)[0].strip() if "=" in text else text)
    return names


def identify(host, headers=None, cookies=None, body="") -> list[Finding]:
    """Fingerprint technologies from response parts. No network access.

    The canonical call is ``identify(host, headers, cookies, body)``;
    ``identify(headers, cookies, body)`` (no host) is also accepted, in
    which case findings carry an empty host. ``headers`` is a mapping,
    ``cookies`` anything :func:`_cookie_names` understands, and ``body``
    the response text.
    """
    # identify(headers, cookies, body): shift when the first argument is
    # a headers mapping rather than a hostname string.
    if isinstance(host, Mapping):
        body = cookies if isinstance(cookies, str) else (body or "")
        cookies = headers
        headers = host
        host = ""

    headers = headers or {}
    present = {str(name).lower(): str(value) for name, value in headers.items()}
    body = body or ""
    findings: list[Finding] = []
    seen_titles: set[str] = set()

    def add(severity, title, evidence, why, next_step):
        if title in seen_titles:
            return
        seen_titles.add(title)
        findings.append(
            Finding(
                severity=severity,
                host=host,
                title=title,
                evidence=evidence,
                why=why,
                next_step=next_step,
            )
        )

    # --- Headers -----------------------------------------------------
    for header, label in (("server", "Server"), ("x-powered-by", "X-Powered-By")):
        value = present.get(header, "").strip()
        if not value:
            continue
        add(
            Severity.INFO,
            f"Technology disclosed by {label} header: {value}",
            f"{label}: {value}",
            "The response openly names part of the technology stack, which "
            "helps an attacker focus on relevant exploits and misconfigurations.",
            "Note the technology (and version, if shown) and check it for "
            "known vulnerabilities and insecure defaults.",
        )
        version = _version_in(value)
        if version:
            add(
                Severity.LOW,
                f"Version disclosed in {label} header ({version})",
                f"{label}: {value}",
                "An exact version lets an attacker match the target against "
                "known CVEs instead of probing blindly.",
                "Check the disclosed version for known CVEs; consider "
                "suppressing version details in the server configuration.",
            )

    # Cookies can also arrive as a Set-Cookie header when no jar is given.
    cookie_names = _cookie_names(cookies)
    if not cookie_names and present.get("set-cookie"):
        cookie_names = _cookie_names(present["set-cookie"])

    # --- Cookies -----------------------------------------------------
    seen_cookies: set[str] = set()
    for name in cookie_names:
        key = name.lower()
        if key in seen_cookies:
            continue
        seen_cookies.add(key)
        technology = COOKIE_TECHNOLOGIES.get(key)
        if technology:
            add(
                Severity.INFO,
                f"Technology suggested by cookie '{name}': {technology}",
                f"Cookie name '{name}' present (value not recorded)",
                "Session cookie names often reveal the framework or "
                "language runtime behind the application.",
                f"Note the {technology} stack and check it for known "
                "vulnerabilities and framework-specific misconfigurations.",
            )
        elif key.startswith("wordpress_") or key.startswith("wp-"):
            add(
                Severity.INFO,
                f"Technology suggested by cookie '{name}': WordPress",
                f"Cookie name '{name}' present (value not recorded)",
                "Session cookie names often reveal the framework or "
                "language runtime behind the application.",
                "Note the WordPress stack and check it for known "
                "vulnerabilities and framework-specific misconfigurations.",
            )
        else:
            add(
                Severity.INFO,
                f"Cookie present: {name}",
                f"Cookie name '{name}' present (value not recorded)",
                "Cookie names can reveal session handling and, sometimes, "
                "the framework behind the application.",
                "Check the session cookie's flags (Secure, HttpOnly, "
                "SameSite) in the full response headers.",
            )

    # --- HTML body ---------------------------------------------------
    lowered = body.lower()
    for marker, technology in HTML_MARKERS.items():
        if marker in lowered:
            add(
                Severity.INFO,
                f"Technology suggested by HTML marker '{marker}': {technology}",
                f"Response body contains '{marker}'",
                "Asset paths and framework markers in the HTML reveal the "
                "technology stack to anyone who views the page source.",
                f"Note the {technology} stack and check it for known "
                "vulnerabilities and framework-specific misconfigurations.",
            )

    generator_match = _GENERATOR_RE.search(body) or _GENERATOR_REVERSED_RE.search(body)
    if generator_match:
        generator = generator_match.group(1).strip()
        if generator:
            add(
                Severity.INFO,
                f"Technology disclosed by generator meta tag: {generator}",
                f"Generator meta tag content: {generator}",
                "The page openly names the software (and possibly version) "
                "that generated it.",
                "Note the technology (and version, if shown) and check it "
                "for known vulnerabilities; consider removing the tag.",
            )

    return findings


def run(target: str) -> list[Finding]:
    """Fetch ``/`` over HTTPS once and fingerprint what comes back."""
    url = f"https://{target}"
    try:
        response = get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return [
            Finding(
                severity=Severity.INFO,
                host=target,
                title="Could not fetch site over HTTPS",
                evidence=str(exc),
                why="The fingerprint check could not run.",
                next_step="Check the hostname, and whether the site only serves HTTP.",
            )
        ]
    try:
        body = response.text or ""
    except Exception:
        body = ""
    cookie_names = _cookie_names(getattr(response, "cookies", None))
    return identify(target, response.headers, cookie_names, body)
