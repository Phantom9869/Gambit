from gambit.models import Severity
from gambit.modules.cors import TEST_ORIGIN, check_cors


def one(findings):
    assert len(findings) == 1
    return findings[0]


def test_no_allow_origin_header_is_no_finding():
    assert check_cors("example.com", {}) == []
    assert check_cors("example.com", {"Content-Type": "text/html"}) == []


def test_reflected_origin_with_credentials_is_high():
    headers = {
        "Access-Control-Allow-Origin": TEST_ORIGIN,
        "Access-Control-Allow-Credentials": "true",
    }
    assert one(check_cors("example.com", headers)).severity == Severity.HIGH


def test_reflected_origin_without_credentials_is_med():
    headers = {"Access-Control-Allow-Origin": TEST_ORIGIN}
    assert one(check_cors("example.com", headers)).severity == Severity.MED


def test_wildcard_with_credentials_is_high():
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    assert one(check_cors("example.com", headers)).severity == Severity.HIGH


def test_wildcard_alone_is_low():
    headers = {"Access-Control-Allow-Origin": "*"}
    assert one(check_cors("example.com", headers)).severity == Severity.LOW


def test_wildcard_with_credentials_false_is_low():
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "false",
    }
    assert one(check_cors("example.com", headers)).severity == Severity.LOW


def test_specific_other_origin_is_no_finding():
    headers = {
        "Access-Control-Allow-Origin": "https://trusted.example",
        "Access-Control-Allow-Credentials": "true",
    }
    assert check_cors("example.com", headers) == []


def test_header_names_and_credentials_value_are_case_insensitive():
    headers = {
        "access-control-allow-origin": "*",
        "ACCESS-CONTROL-ALLOW-CREDENTIALS": "True",
    }
    assert one(check_cors("example.com", headers)).severity == Severity.HIGH


def test_custom_origin_is_what_counts_as_reflected():
    headers = {"Access-Control-Allow-Origin": "https://evil.example"}
    assert one(check_cors("example.com", headers, origin="https://evil.example")).severity == Severity.MED
    # Same header is just a specific origin for the default test origin.
    assert check_cors("example.com", headers) == []


def test_evidence_records_policy_and_host():
    finding = one(check_cors("sub.example.com", {"Access-Control-Allow-Origin": "*"}))
    assert finding.host == "sub.example.com"
    assert "*" in finding.evidence
