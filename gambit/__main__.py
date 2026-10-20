"""Command-line entry point: python -m gambit example.com

Flow: confirm authorization, run Gather once on the apex, discover
the (capped) host list, then run the per-host modules (takeover
included) against every live host through
:func:`gambit.pipeline.run_pipeline`, and finally print the ranked
Triage report as text, Markdown, or JSON.
"""

import argparse
import sys
from pathlib import Path

from gambit.modules import (
    baseline_headers,
    cors,
    exposed_files,
    fingerprint,
    gather,
    http_methods,
    ports,
    takeover,
    tls,
)
from gambit.pipeline import (
    DEFAULT_MAX_HOSTS,
    discover_hosts,
    host_reachable,
    run_for_host,
    run_pipeline,
)
from gambit.triage import to_json, to_markdown, to_text

# Run once on the apex target, in this order.
APEX_MODULES = [gather]

# Run against every discovered host, in this order. Takeover lives here,
# not with the apex modules: a dangling CNAME is a subdomain problem,
# and the apex is the host least likely to have a service CNAME.
PER_HOST_MODULES = [
    takeover,
    fingerprint,
    baseline_headers,
    tls,
    cors,
    http_methods,
    exposed_files,
    ports,
]

# Web-fetch modules: gated by the liveness pre-flight, because each one
# can burn a full request timeout on a dead host.
WEB_MODULES = [fingerprint, baseline_headers, tls, cors, http_methods, exposed_files]

# Non-web modules: must run even when no web port answers -- a dangling
# CNAME and an open database port are findings precisely on such hosts.
INFRA_MODULES = [takeover, ports]

# Backwards-compatible alias: the modules run per host.
MODULES = PER_HOST_MODULES

_FORMATTERS = {
    "text": to_text,
    "md": to_markdown,
    "json": to_json,
}


def _positive_int(value: str) -> int:
    """argparse type for --max-hosts: an integer of at least 1."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from None
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def format_report(findings, report_format: str) -> str:
    """Render ``findings`` as ``text``, ``md``, or ``json`` (ranked)."""
    try:
        formatter = _FORMATTERS[report_format]
    except KeyError:
        raise ValueError(f"unknown report format: {report_format!r}") from None
    return formatter(findings)


def collect_findings(target: str, max_hosts: int = DEFAULT_MAX_HOSTS) -> list:
    """Run the full pipeline for ``target`` and return all findings.

    Gather runs once on the apex; host discovery uses Gather's crt.sh
    subdomain discovery (served from Gather's per-process cache, so
    crt.sh is queried once); the per-host modules -- takeover included --
    then run against the discovered (deduped, capped) hosts that pass a
    cheap liveness pre-flight. Per-module failures are isolated by the
    pipeline helpers, so one failing check never aborts the scan.
    """
    findings = []
    findings.extend(run_for_host(target, APEX_MODULES))

    hosts = discover_hosts(
        target, discover=gather.discover_subdomains, max_hosts=max_hosts
    )
    findings.extend(
        run_pipeline(target, INFRA_MODULES, hosts=hosts, max_hosts=max_hosts)
    )
    findings.extend(
        run_pipeline(
            target,
            WEB_MODULES,
            hosts=hosts,
            max_hosts=max_hosts,
            preflight=host_reachable,
        )
    )
    return findings


# Short alias for callers that think of this as running the scan.
run_scan = collect_findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gambit",
        description="Recon-and-triage for the first hour of a web pentest.",
    )
    parser.add_argument("target", help="hostname to check, e.g. example.com")
    parser.add_argument(
        "--format",
        choices=("text", "md", "json"),
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the report as JSON (deprecated alias for --format json)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write the report to FILE instead of stdout",
    )
    parser.add_argument(
        "--max-hosts",
        type=_positive_int,
        default=DEFAULT_MAX_HOSTS,
        metavar="N",
        help=(
            "maximum number of hosts to scan, including the target "
            f"(default: {DEFAULT_MAX_HOSTS})"
        ),
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="confirm you own the target or have written permission to test it",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.yes:
        answer = input(
            f"Do you own {args.target} or have written permission to test it? [y/N] "
        )
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborting: authorization not confirmed.", file=sys.stderr)
            return 1

    findings = collect_findings(args.target, max_hosts=args.max_hosts)

    report_format = "json" if args.json else args.format
    report = format_report(findings, report_format)

    if args.output:
        try:
            Path(args.output).write_text(report + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Could not write report to {args.output}: {exc}", file=sys.stderr)
            return 1
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
