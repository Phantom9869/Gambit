"""Triage: sort findings by severity and format them for humans or JSON."""

import json
import re

from gambit.models import Finding

# Target-controlled text (headers, generator tags, DNS TXT) must not be
# able to open a new line or a new Markdown construct in the report.
_CONTROLS = re.compile(r"[\x00-\x1f\x7f]")
_MARKDOWN_SPECIAL = set("\\`*_{}[]()#+!<>")


def rank(findings: list[Finding]) -> list[Finding]:
    """Highest severity first; ties broken by host, then title."""
    return sorted(findings, key=lambda f: (-int(f.severity), f.host, f.title))


def _single_line(value: str) -> str:
    """Collapse control characters so one field cannot become two lines."""
    return _CONTROLS.sub(" ", value or "").strip()


def _markdown(value: str) -> str:
    """Escape Markdown and HTML punctuation after collapsing control characters."""
    text = (
        _single_line(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return "".join("\\" + ch if ch in _MARKDOWN_SPECIAL else ch for ch in text)


def to_text(findings: list[Finding]) -> str:
    """Human-readable report, most severe findings first."""
    if not findings:
        return "No findings."

    blocks = []
    for f in rank(findings):
        blocks.append(
            f"[{f.severity.name}] {_single_line(f.host)}: {_single_line(f.title)}\n"
            f"        Evidence: {_single_line(f.evidence)}\n"
            f"        Why:      {_single_line(f.why)}\n"
            f"        Next:     {_single_line(f.next_step)}"
        )
    return "\n\n".join(blocks)


def to_markdown(findings: list[Finding]) -> str:
    """Markdown report, most severe findings first.

    Table-free: a heading per finding in the README example style
    (``[SEVERITY] host: title``) followed by Evidence/Why/Next bullets,
    so the report reads well pasted into notes or an issue. Field values
    are escaped so a target cannot inject headings, links, or HTML.
    """
    if not findings:
        return "# GAMBIT report\n\nNo findings."

    blocks = ["# GAMBIT report"]
    for f in rank(findings):
        blocks.append(
            f"## [{f.severity.name}] {_markdown(f.host)}: {_markdown(f.title)}\n\n"
            f"- **Evidence:** {_markdown(f.evidence)}\n"
            f"- **Why:** {_markdown(f.why)}\n"
            f"- **Next:** {_markdown(f.next_step)}"
        )
    return "\n\n".join(blocks)


def to_json(findings: list[Finding]) -> str:
    """Machine-readable report for pipelines."""
    return json.dumps([f.to_dict() for f in rank(findings)], indent=2)
