"""Triage: sort findings by severity and format them for humans or JSON."""

import json

from gambit.models import Finding


def rank(findings: list[Finding]) -> list[Finding]:
    """Highest severity first; ties broken by host, then title."""
    return sorted(findings, key=lambda f: (-int(f.severity), f.host, f.title))


def to_text(findings: list[Finding]) -> str:
    """Human-readable report, most severe findings first."""
    if not findings:
        return "No findings."

    blocks = []
    for f in rank(findings):
        blocks.append(
            f"[{f.severity.name}] {f.host}: {f.title}\n"
            f"        Evidence: {f.evidence}\n"
            f"        Why:      {f.why}\n"
            f"        Next:     {f.next_step}"
        )
    return "\n\n".join(blocks)


def to_json(findings: list[Finding]) -> str:
    """Machine-readable report for pipelines."""
    return json.dumps([f.to_dict() for f in rank(findings)], indent=2)
