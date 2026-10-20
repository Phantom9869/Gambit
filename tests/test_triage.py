import json

from gambit.models import Finding, Severity
from gambit.triage import rank, to_json, to_markdown, to_text


def make(severity, title="t"):
    return Finding(severity, "example.com", title, "e", "w", "n")


def test_rank_puts_highest_severity_first():
    findings = [make(Severity.INFO), make(Severity.HIGH), make(Severity.LOW)]
    ranked = [f.severity for f in rank(findings)]
    assert ranked == [Severity.HIGH, Severity.LOW, Severity.INFO]


def test_to_json_is_valid_and_uses_severity_names():
    data = json.loads(to_json([make(Severity.MED)]))
    assert data[0]["severity"] == "MED"


def test_to_text_handles_no_findings():
    assert to_text([]) == "No findings."


def test_to_text_lists_most_severe_first():
    text = to_text([make(Severity.LOW, "minor"), make(Severity.HIGH, "major")])
    assert text.index("major") < text.index("minor")


def test_to_markdown_handles_no_findings():
    assert to_markdown([]) == "# GAMBIT report\n\nNo findings."


def test_to_markdown_lists_most_severe_first_with_headings_and_bullets():
    findings = [
        Finding(Severity.LOW, "example.com", "minor", "ev-low", "why-low", "next-low"),
        Finding(Severity.HIGH, "example.com", "major", "ev-high", "why-high", "next-high"),
    ]
    text = to_markdown(findings)
    assert text.startswith("# GAMBIT report")
    assert text.index("major") < text.index("minor")
    assert "## [HIGH] example.com: major" in text
    assert "## [LOW] example.com: minor" in text
    assert "- **Evidence:** ev-high" in text
    assert "- **Why:** why-high" in text
    assert "- **Next:** next-high" in text


def test_to_markdown_is_table_free():
    text = to_markdown([make(Severity.MED, "thing")])
    assert "|" not in text
