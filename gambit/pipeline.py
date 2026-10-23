"""Pipeline: turn one target into a capped host list, then run modules per host.

This module is deliberately discovery-agnostic. It does *not* know about
DNS or crt.sh (that is Gather's job, built later); it only defines the
contract Gather and the CLI build on:

* :func:`discover_hosts` always returns the normalized apex first, then
  any extra/discovered hosts, deduped and capped.
* A *module* is any object (usually a module in ``gambit.modules``) with
  ``run(target: str) -> list[Finding]`` — see :class:`ModuleLike`.
* :func:`run_pipeline` runs every module for every host. One module
  crashing on one host never aborts the scan: it becomes a single INFO
  finding for that host and everything else keeps going.
"""

import ipaddress
import time
from typing import Callable, Iterable, Optional, Protocol

from gambit.models import Finding, Severity

DEFAULT_MAX_HOSTS = 25
DEFAULT_DELAY = 0.5  # seconds between hosts, so we stay polite (cf. exposed_files.DELAY)
DELAY = DEFAULT_DELAY  # short alias, mirroring exposed_files.DELAY


class ModuleLike(Protocol):
    """Structural type for scan modules: just a ``run`` callable."""

    def run(self, target: str) -> list[Finding]:
        ...


def normalize_host(host: str) -> str:
    """Best-effort canonical form of a host string, or ``""`` if empty.

    Strips whitespace, any scheme (``https://``), userinfo, path/query/
    fragment, a leading wildcard (``*.``), and a trailing dot; lowercases
    the result. A valid port is preserved (``example.com:8080``). IPv6
    literals are rewritten with brackets (``::1`` and ``[::1]`` both
    become ``[::1]``) so they survive being placed in a URL.
    """
    if not host:
        return ""
    value = str(host).strip()
    if "://" in value:
        value = value.split("://", 1)[1]
    # Drop path / query / fragment, whichever comes first.
    for sep in ("/", "?", "#"):
        value = value.split(sep, 1)[0]
    if "@" in value:  # userinfo, e.g. user@example.com
        value = value.rsplit("@", 1)[1]
    value = value.strip().lower()
    if value.startswith("*."):
        value = value[2:]
    if value.endswith("."):
        value = value[:-1]
    return _canonicalize_ip_literal(value.strip())


def _canonicalize_ip_literal(value: str) -> str:
    """Bracket a bare IPv6 literal. Leave hostnames and ``host:port`` alone."""
    if not value:
        return value
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return value
        inner = value[1:end]
        rest = value[end + 1 :]
        try:
            ipaddress.IPv6Address(inner)
        except ValueError:
            return value
        if rest.startswith(":") and rest[1:].isdigit():
            number = int(rest[1:])
            if 1 <= number <= 65535:
                return f"[{inner}]:{number}"
            return f"[{inner}]"
        if rest == "":
            return f"[{inner}]"
        return value
    if value.count(":") >= 2:
        try:
            ipaddress.IPv6Address(value)
        except ValueError:
            return value
        return f"[{value}]"
    return value


def port_out_of_range(host: str) -> bool:
    """True when ``host`` carries a numeric port outside 1–65535.

    ``getaddrinfo`` truncates such ports (99999 becomes 34463). Callers
    must refuse them instead of connecting. Checked on the undecorated
    text, because :func:`normalize_host` drops an invalid bracketed port
    while rewriting an IPv6 literal.
    """
    raw = _host_without_decoration(host)
    if raw.startswith("[") and "]:" in raw:
        rest = raw.split("]", 1)[1]
        if rest.startswith(":") and rest[1:].isdigit():
            number = int(rest[1:])
            return not (1 <= number <= 65535)
        return False
    if raw.count(":") == 1 and not raw.startswith("["):
        name, port = raw.split(":", 1)
        if name and port.isdigit():
            number = int(port)
            return not (1 <= number <= 65535)
    return False


def _host_without_decoration(host: str) -> str:
    """``normalize_host`` steps that do not rewrite IPv6 literals."""
    if not host:
        return ""
    value = str(host).strip()
    if "://" in value:
        value = value.split("://", 1)[1]
    for sep in ("/", "?", "#"):
        value = value.split(sep, 1)[0]
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    value = value.strip().lower()
    if value.startswith("*."):
        value = value[2:]
    if value.endswith("."):
        value = value[:-1]
    return value.strip()


def split_host_port(host: str) -> tuple[str, int | None]:
    """Split a target into (hostname, port-or-None). No network access.

    Accepts anything :func:`normalize_host` accepts (scheme, path,
    userinfo, trailing dot are stripped first). The hostname never
    includes URL brackets or a port: socket calls want ``::1``, not
    ``[::1]``. A bare IPv6 address is not mistaken for ``host:port``.
    A numeric port outside 1–65535 is dropped (returned as ``None``)
    so it cannot be truncated into a different port.
    """
    if port_out_of_range(host):
        normalized = normalize_host(host)
        if normalized.startswith("[") and normalized.endswith("]"):
            return normalized[1:-1], None
        if ":" in normalized and not normalized.startswith("["):
            name, _sep, port = normalized.rpartition(":")
            if port.isdigit() and name:
                return name, None
        return normalized, None
    normalized = normalize_host(host)
    if normalized.startswith("["):
        end = normalized.find("]")
        if end != -1:
            inner = normalized[1:end]
            rest = normalized[end + 1 :]
            if rest.startswith(":") and rest[1:].isdigit():
                number = int(rest[1:])
                if 1 <= number <= 65535:
                    return inner, number
            if rest == "":
                return inner, None
    name, sep, port = normalized.rpartition(":")
    if sep and name and port.isdigit() and ":" not in name:
        number = int(port)
        if 1 <= number <= 65535:
            return name, number
        return name, None
    if normalized.startswith("[") and normalized.endswith("]"):
        return normalized[1:-1], None
    return normalized, None


def format_url_host(name: str, port: int | None = None) -> str:
    """Host text safe to place in an ``http(s)://`` URL.

    IPv6 literals are bracketed. ``port`` is appended only when it is
    inside 1–65535.
    """
    try:
        ipaddress.IPv6Address(name)
        literal = f"[{name}]"
    except ValueError:
        literal = name
    if port is not None and 1 <= int(port) <= 65535:
        return f"{literal}:{int(port)}"
    return literal


def host_reachable(host: str, *, timeout: float = 1.0) -> bool:
    """Cheap liveness pre-flight: does the host answer on any web port?

    Tries the target's explicit port if it has one, else the common web
    ports (443, 8443, 80, 8080, 8000, 3000) with a short timeout. DNS is
    bounded by that same timeout. An explicit port outside 1–65535 is
    refused rather than truncated.

    The open port is remembered for later HTTP fetches: success on 8443
    (or 8080, 8000, 3000) makes those requests use that port, not 443/80.
    Only gates web-fetch modules -- takeover and port checks must run
    even for hosts that answer on no web port.
    """
    from gambit.http import set_preferred_port, set_preferred_scheme
    from gambit.net import ResolverSaturated, connect

    if port_out_of_range(host):
        return False
    name, explicit_port = split_host_port(host)
    if not name:
        return False
    ports = [explicit_port] if explicit_port else [443, 8443, 80, 8080, 8000, 3000]
    for port in ports:
        if port is None:
            continue
        try:
            with connect(name, port, timeout):
                pass
        except ResolverSaturated:
            # Not "offline". The caller reports the saturated pool.
            # Do not try the remaining ports: each one would wait out
            # the same deadline for a resolver slot.
            raise
        except OSError:
            continue
        if explicit_port is None:
            set_preferred_scheme(host, "https" if port in (443, 8443) else "http")
            # 443 and 80 are the scheme defaults. Any other open port has
            # to be written into the URL or the fetch hits a closed port.
            set_preferred_port(host, None if port in (443, 80) else port)
        return True
    return False


def resolver_saturated_finding(host: str, detail: str = "") -> Finding:
    """INFO finding for a lookup skipped because the resolver pool was full.

    This is not a negative cache and not "the name does not resolve".
    """
    evidence = (
        "Every resolver thread was busy in getaddrinfo, so this host was "
        "not looked up. The skip was not cached."
    )
    if detail:
        evidence = f"{evidence} ({detail})"
    return Finding(
        severity=Severity.INFO,
        host=host,
        title="DNS resolver saturated",
        evidence=evidence,
        why=(
            "A hung lookup is still occupying the resolver. This is not "
            "the same as a name that does not resolve."
        ),
        next_step="Re-run the scan. If it persists, a hostname lookup is hanging.",
    )


def dedupe_hosts(
    hosts: Iterable[str] | None, max_hosts: Optional[int] = DEFAULT_MAX_HOSTS
) -> list[str]:
    """Normalize, drop empties, dedupe (first occurrence wins), then cap.

    ``max_hosts=None`` means no cap; ``max_hosts <= 0`` returns ``[]``.
    """
    seen: set[str] = set()
    result: list[str] = []
    for raw in hosts or []:
        host = normalize_host(raw)
        if not host or host in seen:
            continue
        seen.add(host)
        result.append(host)
    if max_hosts is not None:
        result = result[:max_hosts] if max_hosts > 0 else []
    return result


def discover_hosts(
    target: str,
    extra_hosts: Iterable[str] | None = None,
    *,
    discover: Callable[[str], Iterable[str] | None] | None = None,
    max_hosts: Optional[int] = DEFAULT_MAX_HOSTS,
) -> list[str]:
    """Resolve the host list for a scan: apex first, deduped, capped.

    Order is: normalized ``target``, then hosts from ``discover`` (in the
    order it returns them), then ``extra_hosts``. ``discover`` — Gather's
    hook — is called once with the *normalized* target; it may return any
    iterable of host strings (a single string counts as one host). If it
    raises or returns ``None``, discovery degrades gracefully to just the
    hosts already known; reporting *why* discovery failed is the discover
    function's own job (e.g. as an INFO finding from its ``run()``).
    """
    hosts: list[str] = [target]
    if discover is not None:
        try:
            discovered = discover(normalize_host(target))
        except Exception:
            discovered = None
        if isinstance(discovered, str):
            hosts.append(discovered)
        elif discovered:
            hosts.extend(discovered)
    if extra_hosts:
        hosts.extend(extra_hosts)
    return dedupe_hosts(hosts, max_hosts=max_hosts)


def _module_name(module) -> str:
    return getattr(module, "__name__", None) or type(module).__name__


_CONNECTIVITY_PREFIXES = ("Could not fetch", "Could not check TLS")


def _is_connectivity(finding: Finding) -> bool:
    return finding.title.startswith(_CONNECTIVITY_PREFIXES)


def run_for_host(host: str, modules: Iterable[ModuleLike] | None) -> list[Finding]:
    """Run every module against one host, isolating per-module failures.

    A module that raises becomes one INFO ``Finding`` titled
    ``"Module <name> failed"`` (evidence is the exception message); the
    remaining modules for this host still run. Modules returning ``None``
    are treated as returning no findings.

    Connectivity failures ("Could not fetch...", "Could not check
    TLS...") are reported at most once per host: when several modules
    cannot reach the host at all, one INFO finding says so instead of
    four near-duplicates.
    """
    findings: list[Finding] = []
    connectivity_reported = False
    for module in modules or []:
        try:
            result = module.run(host)
        except Exception as exc:  # one bad module must never abort a scan
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    host=host,
                    title=f"Module {_module_name(module)} failed",
                    evidence=str(exc) or repr(exc),
                    why="This check could not run; other checks were unaffected.",
                    next_step="Check the hostname and connectivity, then re-run if needed.",
                )
            )
            continue
        for finding in result or []:
            if _is_connectivity(finding):
                if connectivity_reported:
                    continue
                connectivity_reported = True
            findings.append(finding)
    return findings


# Backwards/forwards-friendly alias: per-host execution under a verb name.
run_modules_for_host = run_for_host


def run_pipeline(
    target: str,
    modules: Iterable[ModuleLike] | None,
    *,
    hosts: Iterable[str] | None = None,
    extra_hosts: Iterable[str] | None = None,
    discover: Callable[[str], Iterable[str] | None] | None = None,
    max_hosts: Optional[int] = DEFAULT_MAX_HOSTS,
    delay: float | None = DEFAULT_DELAY,
    sleep: Callable[[float], None] = time.sleep,
    preflight: Callable[[str], bool] | None = None,
) -> list[Finding]:
    """Run ``modules`` against every host for ``target``; return all findings.

    Host resolution: if ``hosts`` is given it is used (with ``target``
    still guaranteed first), otherwise hosts come from
    :func:`discover_hosts` (apex + ``discover`` + ``extra_hosts``).
    Either way the list is normalized, deduped, and capped at
    ``max_hosts`` (default 25). ``sleep(delay)`` is called *between*
    hosts (never before the first) when ``delay`` is positive; pass
    ``delay=0`` or inject ``sleep`` to disable waiting in tests.

    If ``preflight`` is given, it is called once per host first; a host
    it rejects gets a single INFO "Host did not respond" finding and its
    modules are skipped, so one dead host cannot stack every module's
    full timeout. (:func:`host_reachable` is the production preflight.)
    :class:`gambit.net.ResolverSaturated` from the preflight is reported
    as "DNS resolver saturated" instead, so a full resolver pool is not
    described as an offline host.

    Findings are returned in host-then-module order; ranking for display
    stays Triage's job (``gambit.triage.rank``).
    """
    if hosts is not None:
        resolved = dedupe_hosts([target, *hosts], max_hosts=max_hosts)
    else:
        resolved = discover_hosts(
            target, extra_hosts, discover=discover, max_hosts=max_hosts
        )

    from gambit.net import ResolverSaturated

    findings: list[Finding] = []
    for index, host in enumerate(resolved):
        if index and delay:
            sleep(delay)
        if preflight is not None:
            try:
                reachable = preflight(host)
            except ResolverSaturated as exc:
                findings.append(resolver_saturated_finding(host, str(exc)))
                continue
            if not reachable:
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        host=host,
                        title="Host did not respond to a connection attempt",
                        evidence="TCP connection to the host failed or timed out "
                        "on the checked ports (pre-flight)",
                        why="The host may be offline, filtered, or no longer "
                        "in service, so the per-host checks were skipped.",
                        next_step="Confirm the host is still in use; if it is "
                        "a stale subdomain, consider removing its DNS records.",
                    )
                )
                continue
        findings.extend(run_for_host(host, modules))
    return findings


__all__ = [
    "DEFAULT_MAX_HOSTS",
    "DEFAULT_DELAY",
    "DELAY",
    "ModuleLike",
    "dedupe_hosts",
    "discover_hosts",
    "format_url_host",
    "host_reachable",
    "normalize_host",
    "port_out_of_range",
    "resolver_saturated_finding",
    "run_for_host",
    "run_modules_for_host",
    "run_pipeline",
    "split_host_port",
]
