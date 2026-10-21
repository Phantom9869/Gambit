"""Gather: DNS records and crt.sh subdomain discovery for a target.

This is the first stage of the pipeline. It answers two questions about
the apex host: "what does DNS say about it?" (:func:`run`, built on the
pure :func:`evaluate_dns`) and "what subdomains are publicly known?"
(:func:`discover_subdomains`, built on the pure :func:`parse_crtsh`).

``discover_subdomains`` matches the ``discover=`` callable contract of
:func:`gambit.pipeline.discover_hosts`: it is called once with the
normalized target and returns an iterable of host strings. It never
raises — a crt.sh failure yields ``[]`` there, while :func:`run` is
where that failure is reported (as a single INFO finding).
"""

import json
from typing import Iterable, Mapping, Optional

import dns.exception
import dns.resolver
import requests

from gambit.http import TIMEOUT, USER_AGENT, get
from gambit.models import Finding, Severity
from gambit.pipeline import normalize_host, split_host_port

__all__ = [
    "RECORD_TYPES",
    "TIMEOUT",
    "USER_AGENT",
    "clear_crtsh_cache",
    "discover_subdomains",
    "evaluate_dns",
    "lookup_dns",
    "parse_crtsh",
    "run",
]

# DNS record types queried for the apex, in report order.
RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")

_CRT_SH_URL = "https://crt.sh/?q=%25.{host}&output=json"


def parse_crtsh(payload) -> list[str]:
    """Extract hostnames from a crt.sh JSON payload. No network access.

    ``payload`` may be the decoded JSON (a list of entry dicts), a JSON
    string, or UTF-8 bytes. Each entry contributes its ``name_value``
    (which may hold several newline-separated names) and ``common_name``.
    Names are lowercased, stripped of any leading wildcard (``*.``) and
    trailing dot, emptied/deduped, and returned sorted. Malformed input
    (undecodable JSON, wrong types, non-dict entries) yields ``[]`` or
    is skipped rather than raising.
    """
    if isinstance(payload, (bytes, bytearray)):
        try:
            payload = payload.decode("utf-8", errors="replace")
        except Exception:
            return []
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError:
            return []
    if not isinstance(payload, (list, tuple)):
        return []

    names: set[str] = set()
    for entry in payload:
        if isinstance(entry, str):
            raw_values = [entry]
        elif isinstance(entry, dict):
            raw_values = []
            for key in ("name_value", "common_name"):
                value = entry.get(key)
                if isinstance(value, str):
                    raw_values.append(value)
        else:
            continue
        for raw in raw_values:
            for name in raw.splitlines():
                host = normalize_host(name)
                if host and "*" not in host:
                    names.add(host)
    return sorted(names)


def _as_values(raw) -> list[str]:
    """Coerce one records-dict value into a clean list of strings."""
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [raw]
    try:
        items = list(raw)
    except TypeError:
        return []
    return [str(item).strip() for item in items if str(item).strip()]


def _has_txt_marker(values: Iterable[str], marker: str) -> bool:
    marker = marker.lower()
    for value in values:
        cleaned = value.strip().strip('"').strip().lower()
        if cleaned.startswith(marker):
            return True
    return False


def evaluate_dns(
    host: str, records: Mapping[str, Iterable[str] | str | None] | None
) -> list[Finding]:
    """Turn already-fetched DNS records into findings. No network access.

    ``records`` maps a record type (``"A"``, ``"TXT"``, ...) to its
    values; a ``"DMARC"`` key holds the TXT values of ``_dmarc.<host>``
    (see :func:`lookup_dns`). Each non-empty type gets one INFO finding
    summarizing its values. Two absences are flagged INFO as well: no
    TXT value starting ``v=spf1`` (SPF) and no DMARC value starting
    ``v=DMARC1``. An empty ``records`` yields a single "no records"
    INFO finding plus the SPF/DMARC ones.
    """
    normalized: dict[str, list[str]] = {}
    for rtype, raw in (records or {}).items():
        values = _as_values(raw)
        if values:
            normalized[str(rtype).upper()] = values

    findings: list[Finding] = []
    if not normalized:
        findings.append(
            Finding(
                severity=Severity.INFO,
                host=host,
                title="No DNS records found",
                evidence="No A, AAAA, CNAME, MX, NS, or TXT records resolved",
                why="A host with no DNS records cannot be reached normally; "
                "the name may be unregistered, expired, or resolved elsewhere.",
                next_step="Confirm the hostname is correct and still in use.",
            )
        )

    # Stable order: RECORD_TYPES first, other keys (e.g. DMARC) after.
    ordered = [t for t in RECORD_TYPES if t in normalized]
    ordered += [t for t in normalized if t not in RECORD_TYPES]
    for rtype in ordered:
        values = normalized[rtype]
        label = "DMARC" if rtype == "DMARC" else f"DNS {rtype}"
        findings.append(
            Finding(
                severity=Severity.INFO,
                host=host,
                title=f"{label} record(s) found",
                evidence=", ".join(values)[:1000],
                why="Public DNS describes where this host's traffic and mail go; "
                "unexpected values can reveal forgotten services or providers.",
                next_step="Review these values for providers or hosts you no longer use.",
            )
        )

    if not _has_txt_marker(normalized.get("TXT", []), "v=spf1"):
        findings.append(
            Finding(
                severity=Severity.INFO,
                host=host,
                title="No SPF record found",
                evidence="No TXT record starting with 'v=spf1' was found",
                why="Without SPF, other mail servers have less signal to reject "
                "mail spoofed as coming from this domain.",
                next_step="Check how this domain sends mail; if it does, review its SPF setup.",
            )
        )
    if not _has_txt_marker(normalized.get("DMARC", []), "v=dmarc1"):
        findings.append(
            Finding(
                severity=Severity.INFO,
                host=host,
                title="No DMARC record found",
                evidence="No TXT record at _dmarc starting with 'v=DMARC1' was found",
                why="Without DMARC, the domain owner gets no policy enforcement or "
                "reporting for spoofed mail using this domain.",
                next_step="Check how this domain sends mail; if it does, review its DMARC setup.",
            )
        )
    return findings


def _dns_name(host: str) -> str:
    """Hostname only: ``example.com:8080`` is not a DNS name."""
    name, _port = split_host_port(host)
    return name


def _resolve(name: str, rdtype: str) -> list[str]:
    """Resolve one record type; every DNS failure means "no values"."""
    try:
        answers = dns.resolver.resolve(name, rdtype, lifetime=TIMEOUT)
    except dns.exception.DNSException:
        return []
    return [str(rdata).strip() for rdata in answers if str(rdata).strip()]


def lookup_dns(host: str) -> dict[str, list[str]]:
    """Fetch the DNS records :func:`evaluate_dns` consumes.

    Queries each type in :data:`RECORD_TYPES` for ``host`` plus the TXT
    records of ``_dmarc.<host>`` (stored under ``"DMARC"``). Types with
    no answer are omitted. DNS errors never propagate.
    """
    name = _dns_name(host)
    records: dict[str, list[str]] = {}
    if not name:
        return records
    for rdtype in RECORD_TYPES:
        values = _resolve(name, rdtype)
        if values:
            records[rdtype] = values
    dmarc = _resolve(f"_dmarc.{name}", "TXT")
    if dmarc:
        records["DMARC"] = dmarc
    return records


def _fetch_crtsh_subdomains(host: str) -> list[str]:
    """GET crt.sh for ``host`` and parse the response. Raises on failure.

    Results (and failures) are cached per host for the life of the
    process: a scan calls this from both ``run`` (to report) and
    ``discover_subdomains`` (to build the host list), and crt.sh should
    only be queried once per host per scan.
    """
    if host in _CRTSH_CACHE:
        cached = _CRTSH_CACHE[host]
        if isinstance(cached, Exception):
            raise cached
        return cached
    try:
        response = get(
            _CRT_SH_URL.format(host=host),
            timeout=TIMEOUT,
            allow_redirects=False,
        )
        response.raise_for_status()
        names = parse_crtsh(response.json())
    except Exception as exc:
        _CRTSH_CACHE[host] = exc
        raise
    _CRTSH_CACHE[host] = names
    return names


_CRTSH_CACHE: dict[str, list[str] | Exception] = {}


def clear_crtsh_cache() -> None:
    """Forget cached crt.sh results (mainly for tests)."""
    _CRTSH_CACHE.clear()


def _own_subdomains(host: str, names: Iterable[str]) -> list[str]:
    """Keep only true subdomains of ``host`` (not the apex, not others)."""
    return [name for name in names if name != host and name.endswith(f".{host}")]


def discover_subdomains(target: str) -> list[str]:
    """Return crt.sh-known subdomains of ``target``; ``[]`` on any failure.

    Compatible with ``gambit.pipeline.discover_hosts(discover=...)``:
    called with the target, returns host strings (sorted, deduped,
    apex excluded), and never raises.
    """
    host = _dns_name(target)
    if not host:
        return []
    try:
        names = _fetch_crtsh_subdomains(host)
    except Exception:
        return []
    return _own_subdomains(host, names)


def run(target: str) -> list[Finding]:
    """Report DNS records for the target and its crt.sh subdomains."""
    host = normalize_host(target) or target
    dns_host = _dns_name(host) or host
    findings = evaluate_dns(host, lookup_dns(dns_host))

    try:
        names = _fetch_crtsh_subdomains(dns_host)
    except (requests.RequestException, ValueError) as exc:
        findings.append(
            Finding(
                severity=Severity.INFO,
                host=host,
                title="Could not query crt.sh for subdomains",
                evidence=str(exc),
                why="Certificate-transparency discovery could not run, so "
                "publicly known subdomains may be missing from this scan.",
                next_step="Check connectivity to crt.sh, then re-run if needed.",
            )
        )
    else:
        subdomains = _own_subdomains(dns_host, names)
        if subdomains:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    host=host,
                    title="Subdomains discovered via crt.sh",
                    evidence=", ".join(subdomains)[:1000],
                    why="Certificate transparency is public: every listed name "
                    "is known to attackers and worth including in scope.",
                    next_step="Review each subdomain for forgotten or stale services.",
                )
            )
    return findings
