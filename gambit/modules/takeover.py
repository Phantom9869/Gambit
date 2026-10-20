"""Takeover: flag dangling CNAMEs that may point at unclaimed services.

A subdomain whose CNAME points at a third-party service (GitHub Pages,
S3, Heroku, ...) is only interesting when the resource behind it looks
abandoned. This module is deliberately conservative:

* HIGH — the CNAME points at a known service *and* the destination does
  not resolve, or the host serves that service's known "unclaimed"
  response fingerprint. The finding says *possible*: evidence never
  claims the resource is unclaimed or takeover-able.
* INFO — the CNAME points at a known service, but it resolves and no
  unclaimed fingerprint is served (still worth an ownership review).
* Nothing — no CNAME, or a CNAME to an unknown service.

Service data lives in ``gambit/data/takeover_fingerprints.json``
(seeded from can-i-take-over-xyz) and is loaded relative to this
package; a missing or corrupt file degrades to "no known services"
rather than an error. The matching core (:func:`evaluate`,
:func:`match_service`, :func:`find_unclaimed_fingerprint`) is pure.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import dns.exception
import dns.resolver
import requests

from gambit.http import TIMEOUT, USER_AGENT, get
from gambit.models import Finding, Severity
from gambit.pipeline import normalize_host

__all__ = [
    "FINGERPRINT_PATH",
    "TIMEOUT",
    "USER_AGENT",
    "Fingerprint",
    "evaluate",
    "find_unclaimed_fingerprint",
    "load_fingerprints",
    "lookup_cname",
    "match_service",
    "run",
]

# gambit/data/takeover_fingerprints.json, relative to the package
# (this file is gambit/modules/takeover.py).
FINGERPRINT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "takeover_fingerprints.json"
)

_MAX_BODY = 64_000  # chars of a response worth searching for fingerprints


@dataclass(frozen=True)
class Fingerprint:
    """One third-party service a dangling CNAME can point at."""

    service: str
    cname_suffixes: tuple[str, ...]
    fingerprints: tuple[str, ...]


def _as_str_tuple(raw) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        raw = [raw]
    try:
        items = list(raw)
    except TypeError:
        return ()
    return tuple(str(item).strip() for item in items if str(item).strip())


def _suffix_tuple(raw) -> tuple[str, ...]:
    return tuple(v.lower().lstrip("*.").rstrip(".") for v in _as_str_tuple(raw) if v)


def load_fingerprints(path=None) -> list[Fingerprint]:
    """Load service fingerprints from JSON; ``[]`` on any problem.

    ``path`` defaults to :data:`FINGERPRINT_PATH`. The file is either a
    list of entries or an object with a ``"services"`` list. Each entry
    uses ``service``, ``cname_suffixes``, and ``fingerprints`` (the
    unclaimed-response strings); ``name``, ``cname``/``suffixes``, and
    ``unclaimed_fingerprints``/``fingerprint`` are accepted as aliases.
    Entries without a service name or any CNAME suffix are skipped;
    a missing, unreadable, or corrupt file returns ``[]``.
    """
    source = Path(path) if path is not None else FINGERPRINT_PATH
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if isinstance(data, dict):
        entries = data.get("services")
    else:
        entries = data
    if not isinstance(entries, (list, tuple)):
        return []

    fingerprints: list[Fingerprint] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        service = entry.get("service") or entry.get("name")
        suffixes = _suffix_tuple(
            entry.get("cname_suffixes")
            or entry.get("cname_suffix")
            or entry.get("cname")
            or entry.get("suffixes")
        )
        if not service or not str(service).strip() or not suffixes:
            continue
        fingerprints.append(
            Fingerprint(
                service=str(service).strip(),
                cname_suffixes=suffixes,
                fingerprints=_as_str_tuple(
                    entry.get("fingerprints")
                    or entry.get("unclaimed_fingerprints")
                    or entry.get("fingerprint")
                ),
            )
        )
    return fingerprints


def match_service(
    cname: str | None, fingerprints: Iterable[Fingerprint] | None = None
) -> Optional[Fingerprint]:
    """Return the known service ``cname`` points at, or ``None``.

    A CNAME matches when, after lowercasing and stripping any trailing
    dot, it equals a suffix or ends with ``"." + suffix`` — so
    ``foo.github.io`` matches GitHub Pages but ``notgithub.io`` and
    ``github.io.example.com`` do not. No network access.
    """
    host = normalize_host(cname or "")
    if not host:
        return None
    for fingerprint in fingerprints if fingerprints is not None else load_fingerprints():
        for suffix in fingerprint.cname_suffixes:
            suffix = suffix.lower().strip().lstrip("*.").rstrip(".")
            if suffix and (host == suffix or host.endswith(f".{suffix}")):
                return fingerprint
    return None


def find_unclaimed_fingerprint(body: str | None, fingerprint: Fingerprint) -> Optional[str]:
    """Return the unclaimed-response string found in ``body``, or ``None``.

    Case-insensitive substring match against
    ``fingerprint.fingerprints``. No network access.
    """
    if not body:
        return None
    haystack = body.casefold()
    for needle in fingerprint.fingerprints:
        if needle and needle.casefold() in haystack:
            return needle
    return None


def evaluate(
    host: str,
    cname: str | None,
    *,
    resolves: bool | None = None,
    body: str | None = None,
    fingerprints: Iterable[Fingerprint] | None = None,
    status_code: int | None = None,
) -> Optional[Finding]:
    """Decide the finding for one host's CNAME. No network access.

    ``resolves`` says whether the CNAME destination resolves
    (``True``/``False``; ``None`` = unknown), ``body`` is the host's
    HTTP response body if one was fetched (``status_code`` is accepted
    for evidence context and does not change the verdict). Returns
    ``None`` when there is no CNAME or it points at an unknown service.
    HIGH requires a known service *plus* an unresolvable destination
    or a served unclaimed fingerprint; anything else for a known
    service is INFO.
    """
    destination = normalize_host(cname or "")
    if not destination:
        return None
    fingerprint = match_service(destination, fingerprints)
    if fingerprint is None:
        return None

    matched = find_unclaimed_fingerprint(body, fingerprint)
    reasons = []
    if matched is not None:
        reasons.append(f"response serves the unclaimed fingerprint {matched!r}")
    if resolves is False:
        reasons.append("the CNAME destination does not resolve")

    if reasons:
        evidence = f"CNAME {host} -> {destination} ({fingerprint.service}); " + "; ".join(reasons)
        if status_code is not None:
            evidence += f"; HTTP status {status_code}"
        return Finding(
            severity=Severity.HIGH,
            host=host,
            title=f"Possible subdomain takeover ({fingerprint.service})",
            evidence=evidence,
            why="A dangling CNAME to a third-party service can let someone else "
            "register the abandoned resource and serve content as this host. "
            "This evidence suggests the resource may be unclaimed; it does not "
            "prove that it is.",
            next_step="Confirm who owns this host and its service resource. If it is "
            "yours and abandoned, remove the CNAME or reclaim the resource. Report "
            "it to the owner; do not claim a resource that is not yours.",
        )
    return Finding(
        severity=Severity.INFO,
        host=host,
        title=f"CNAME points to {fingerprint.service}",
        evidence=f"CNAME {host} -> {destination}; destination resolves and no "
        "unclaimed fingerprint was observed"
        if resolves is True
        else f"CNAME {host} -> {destination}; no unclaimed fingerprint was observed",
        why="Third-party CNAMEs become a takeover risk when the resource behind "
        "them is abandoned, so this dependency is worth tracking.",
        next_step="Confirm the service resource behind this host is still owned "
        "and in use; remove the CNAME if it is ever decommissioned.",
    )


def lookup_cname(host: str) -> Optional[str]:
    """Return the host's first CNAME destination (no trailing dot), or None."""
    name = normalize_host(host)
    if not name:
        return None
    try:
        answers = dns.resolver.resolve(name, "CNAME", lifetime=TIMEOUT)
    except dns.exception.DNSException:
        return None
    for rdata in answers:
        target = normalize_host(str(rdata.target if hasattr(rdata, "target") else rdata))
        if target:
            return target
    return None


def _resolves(name: str) -> bool | None:
    """True if ``name`` has an A/AAAA answer, False if definitively not.

    ``None`` means resolution could not be determined (timeouts, server
    failures), which :func:`evaluate` correctly treats as not-HIGH.
    """
    unknown = False
    for rdtype in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(name, rdtype, lifetime=TIMEOUT)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.DNSException:
            unknown = True
            continue
        if len(answers):
            return True
    return None if unknown else False


def run(target: str) -> list[Finding]:
    """Check the target's CNAME against the takeover fingerprints."""
    host = normalize_host(target) or target
    cname = lookup_cname(host)
    if not cname:
        return []
    fingerprints = load_fingerprints()
    if match_service(cname, fingerprints) is None:
        return []

    resolves = _resolves(cname)
    body = None
    status_code = None
    if resolves is not False:
        try:
            response = get(f"https://{host}", timeout=TIMEOUT, allow_redirects=True)
        except requests.RequestException:
            body = None
        else:
            status_code = response.status_code
            body = (response.text or "")[:_MAX_BODY]

    finding = evaluate(
        host,
        cname,
        resolves=resolves,
        body=body,
        fingerprints=fingerprints,
        status_code=status_code,
    )
    return [finding] if finding else []
