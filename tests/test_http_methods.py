from gambit.models import Severity
from gambit.modules.http_methods import check_methods, parse_allow


# --- parse_allow -------------------------------------------------------


def test_parse_allow_splits_and_uppercases():
    assert parse_allow("GET, POST, OPTIONS") == ["GET", "POST", "OPTIONS"]
    assert parse_allow("get,post") == ["GET", "POST"]


def test_parse_allow_dedupes_and_ignores_blanks():
    assert parse_allow("GET, GET, , POST,") == ["GET", "POST"]
    assert parse_allow("") == []
    assert parse_allow(None) == []


def test_parse_allow_accepts_mapping_and_iterable():
    assert parse_allow({"Allow": "GET, HEAD", "Server": "x"}) == ["GET", "HEAD"]
    assert parse_allow(["get", "Trace"]) == ["GET", "TRACE"]
    assert parse_allow({}) == []


# --- check_methods -----------------------------------------------------


def test_safe_methods_only_is_no_finding():
    assert check_methods("example.com", "GET, POST, HEAD, OPTIONS") == []


def test_trace_is_med():
    findings = check_methods("example.com", "GET, TRACE")
    assert len(findings) == 1
    assert findings[0].severity == Severity.MED
    assert "TRACE" in findings[0].title


def test_write_methods_are_low_and_post_is_not_write():
    findings = check_methods("example.com", "GET, POST, PUT, DELETE, PATCH")
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    for method in ("PUT", "DELETE", "PATCH"):
        assert method in findings[0].title


def test_post_alone_is_not_flagged_as_write():
    assert check_methods("example.com", "GET, POST") == []


def test_trace_and_write_methods_produce_two_findings():
    findings = check_methods("example.com", "GET, TRACE, DELETE")
    assert [f.severity for f in findings] == [Severity.MED, Severity.LOW]


def test_check_methods_accepts_headers_mapping():
    findings = check_methods("example.com", {"Allow": "GET, TRACE"})
    assert len(findings) == 1
    assert findings[0].host == "example.com"
    assert findings[0].evidence.startswith("Allow:")


def test_empty_allow_is_no_finding():
    assert check_methods("example.com", "") == []
    assert check_methods("example.com", None) == []
