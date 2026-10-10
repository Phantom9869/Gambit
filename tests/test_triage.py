import json

from gambit.models import Finding, Severity
from gambit.triage import rank, to_json, to_text


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
