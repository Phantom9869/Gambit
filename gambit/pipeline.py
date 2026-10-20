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
    the result. A port, if present, is preserved (``example.com:8080``),
    because existing modules interpolate the host straight into a URL.
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
    return value.strip()


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


def run_for_host(host: str, modules: Iterable[ModuleLike] | None) -> list[Finding]:
    """Run every module against one host, isolating per-module failures.

    A module that raises becomes one INFO ``Finding`` titled
    ``"Module <name> failed"`` (evidence is the exception message); the
    remaining modules for this host still run. Modules returning ``None``
    are treated as returning no findings.
    """
    findings: list[Finding] = []
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
        if result:
            findings.extend(result)
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
) -> list[Finding]:
    """Run ``modules`` against every host for ``target``; return all findings.

    Host resolution: if ``hosts`` is given it is used (with ``target``
    still guaranteed first), otherwise hosts come from
    :func:`discover_hosts` (apex + ``discover`` + ``extra_hosts``).
    Either way the list is normalized, deduped, and capped at
    ``max_hosts`` (default 25). ``sleep(delay)`` is called *between*
    hosts (never before the first) when ``delay`` is positive; pass
    ``delay=0`` or inject ``sleep`` to disable waiting in tests.
    Findings are returned in host-then-module order; ranking for display
    stays Triage's job (``gambit.triage.rank``).
    """
    if hosts is not None:
        resolved = dedupe_hosts([target, *hosts], max_hosts=max_hosts)
    else:
        resolved = discover_hosts(
            target, extra_hosts, discover=discover, max_hosts=max_hosts
        )

    findings: list[Finding] = []
    for index, host in enumerate(resolved):
        if index and delay:
            sleep(delay)
        findings.extend(run_for_host(host, modules))
    return findings


__all__ = [
    "DEFAULT_MAX_HOSTS",
    "DEFAULT_DELAY",
    "DELAY",
    "ModuleLike",
    "normalize_host",
    "dedupe_hosts",
    "discover_hosts",
    "run_for_host",
    "run_modules_for_host",
    "run_pipeline",
]
