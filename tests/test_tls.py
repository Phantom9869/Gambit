from datetime import datetime, timezone

from gambit.models import Severity
from gambit.modules.tls import days_until_expiry, evaluate, parse_cert_datetime

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def cert(not_after, not_before="Dec  1 00:00:00 2025 GMT"):
    return {"notAfter": not_after, "notBefore": not_before}


def test_parse_cert_datetime_getpeercert_format():
    parsed = parse_cert_datetime("Oct 21 12:00:00 2026 GMT")
    assert parsed == datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)
    # Single-digit days come with a double space.
    assert parse_cert_datetime("Jan  5 00:00:00 2027 GMT").day == 5
    assert parse_cert_datetime("nonsense") is None
    assert parse_cert_datetime(None) is None


def test_days_until_expiry():
    assert days_until_expiry(cert("Jan 11 12:00:00 2026 GMT"), now=NOW) == 10
    assert days_until_expiry(cert("Dec 31 12:00:00 2025 GMT"), now=NOW) == -1
    assert days_until_expiry({}, now=NOW) is None


def test_expired_certificate_is_high():
    findings = evaluate("example.com", cert("Dec  1 00:00:00 2025 GMT"), "TLSv1.3", now=NOW)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "expired" in findings[0].title.lower()


def test_expiring_within_30_days_is_med():
    findings = evaluate("example.com", cert("Jan 20 00:00:00 2026 GMT"), "TLSv1.3", now=NOW)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MED
    assert "expires soon" in findings[0].title.lower()


def test_exactly_30_days_remaining_is_not_flagged():
    # Jan 31 12:00 is exactly 30 days after NOW; the warning is "< 30 days".
    findings = evaluate("example.com", cert("Jan 31 12:00:00 2026 GMT"), "TLSv1.3", now=NOW)
    assert findings == []


def test_healthy_certificate_on_modern_tls_has_no_findings():
    findings = evaluate("example.com", cert("Dec  1 00:00:00 2027 GMT"), "TLSv1.2", now=NOW)
    assert findings == []
    findings = evaluate("example.com", cert("Dec  1 00:00:00 2027 GMT"), "TLSv1.3", now=NOW)
    assert findings == []


def test_tls_below_1_2_is_high():
    for protocol in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"):
        findings = evaluate("example.com", cert("Dec  1 00:00:00 2027 GMT"), protocol, now=NOW)
        assert len(findings) == 1, protocol
        assert findings[0].severity == Severity.HIGH, protocol


def test_not_yet_valid_certificate_is_high():
    findings = evaluate(
        "example.com",
        cert("Dec  1 00:00:00 2027 GMT", not_before="Jun  1 00:00:00 2026 GMT"),
        "TLSv1.3",
        now=NOW,
    )
    assert any(f.severity == Severity.HIGH and "not yet valid" in f.title for f in findings)


def test_no_certificate_info_is_info_not_high():
    findings = evaluate("example.com", {}, "TLSv1.3", now=NOW)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert evaluate("example.com", None, "TLSv1.3", now=NOW)[0].severity == Severity.INFO


def test_hostname_mismatch_and_self_signed_are_info():
    findings = evaluate(
        "example.com",
        cert("Dec  1 00:00:00 2027 GMT"),
        "TLSv1.3",
        now=NOW,
        hostname_mismatch=True,
        self_signed=True,
    )
    assert len(findings) == 2
    assert all(f.severity == Severity.INFO for f in findings)
