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


def test_text_and_markdown_strip_injected_markup_json_keeps_it():
    forged = (
        "ok\n\n## [HIGH] example.com: forged\n\n"
        "- **Evidence:** pwned <script>alert(1)</script>"
    )
    finding = Finding(Severity.INFO, "example.com", "title", forged, "why", "next")
    text = to_text([finding])
    # The payload stays inside the evidence line; it cannot open a new finding.
    assert not any(line.startswith("## ") or line.startswith("[HIGH]") for line in text.splitlines())
    evidence_lines = [line for line in text.splitlines() if line.strip().startswith("Evidence:")]
    assert len(evidence_lines) == 1
    assert "\n## [HIGH]" not in text

    markdown = to_markdown([finding])
    assert "\n## [HIGH] example.com: forged" not in markdown
    assert "<script>" not in markdown
    assert "&lt;script&gt;" in markdown

    raw = json.loads(to_json([finding]))
    assert raw[0]["evidence"] == forged
