import ssl
from datetime import datetime, timezone

import gambit.http as http
from gambit.models import Severity
from gambit.modules import tls as tls_module
from gambit.modules.tls import (
    certificate_from_socket,
    days_until_expiry,
    evaluate,
    parse_cert_datetime,
)

# Self-signed fixture, not valid after 2020-06-01. Generated offline so the
# suite does not shell out to openssl (CI includes Windows).
EXPIRED_PEM = """\
-----BEGIN CERTIFICATE-----
MIICrTCCAZWgAwIBAgIBATANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDDA9leHBp
cmVkLmV4YW1wbGUwHhcNMjAwMTAxMDAwMDAwWhcNMjAwNjAxMDAwMDAwWjAaMRgw
FgYDVQQDDA9leHBpcmVkLmV4YW1wbGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDCOSGTct1N3/vVYqvU1fi/JC2nNgxArQUgbFnMyzv6U5WmWBCYDYq/
YKGBUoJegqaRTMHH4dNizxhtIquhvcqW9mu21gnNE4GIn9ND/n0ixuDx5bUdZKLc
Lw10tOzuT6+t/LxlLTZJP7CV6pC+4eeV0nIOYHpeITUcfA2RhG284jqVPGNWXIbP
tKYJXFQBVrZhIYZGq4vYaiIIepFighzaUKBBJ6XCFm3eBUTDkMA+25LmhnpoHgr8
duPlBUWnhaMN0z3drYlT7AFag7H18y6w/VcHHGzYp1/KTtl9kB8k4NAaOsqkccYo
B8L2f2ADnwJf7JB8X/t8CuI0IP4nwYVtAgMBAAEwDQYJKoZIhvcNAQELBQADggEB
AFE6U80jH5RXlyK+yUeR+gc58RJ+N0rhweU3AxB3OChEoPYkqnLWaV4Lu8wEX5eE
MusQ2yK4GusXTJ9tdn83eTVfrieOAz2jhpcnnlHfK8theu9q0XMSKCVNX/5XXTDd
6z4cXK/w9fhMX0S1mZqKCaub9+Qs11tOrCnZUub2w1o6ttJPhjtI00pQ+vbPCHsE
vDAo78pnJGhg64snxvyfxYoiOgboBjRDOptr7JGvp9W27XtI1nWNBFyoqlAqhB4u
qfyo+FW4cCbvIjr3hxkJGQEoDRmxYC9QgA7HtkofWNE/Tj7Okj2sJ3Lt9LzpC0oN
7lLtSJvVIZ5OQq4Pvy3AR/A=
-----END CERTIFICATE-----
"""

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


def test_getpeercert_empty_dict_is_recovered_from_der():
    der = ssl.PEM_cert_to_DER_cert(EXPIRED_PEM)

    class Sock:
        def getpeercert(self, binary_form=False):
            if binary_form:
                return der
            return {}

    cert = certificate_from_socket(Sock())
    assert cert
    assert cert.get("notAfter")
    findings = evaluate(
        "expired.example",
        cert,
        "TLSv1.2",
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    assert any(f.severity == Severity.HIGH and "expired" in f.title.lower() for f in findings)


def test_handshake_reads_binary_cert_when_getpeercert_returns_empty(monkeypatch):
    der = ssl.PEM_cert_to_DER_cert(EXPIRED_PEM)

    class Raw:
        def close(self):
            pass

    class TLS:
        def getpeercert(self, binary_form=False):
            if binary_form:
                return der
            return {}

        def version(self):
            return "TLSv1.2"

        def close(self):
            pass

    class Context:
        def wrap_socket(self, sock, server_hostname=None):
            return TLS()

    monkeypatch.setattr("gambit.net.connect", lambda *args, **kwargs: Raw())
    from gambit.modules.tls import _handshake

    cert, protocol = _handshake("expired.example", 443, Context())
    assert protocol == "TLSv1.2"
    assert "2020" in cert["notAfter"]


def test_insecure_tls_still_classifies_a_verification_failure(monkeypatch):
    seen = []

    def fake_handshake(hostname, port, context):
        seen.append(context.verify_mode)
        if context.verify_mode != ssl.CERT_NONE:
            raise ssl.SSLCertVerificationError(1, "self-signed certificate")
        return ({"notAfter": "Dec  1 00:00:00 2099 GMT"}, "TLSv1.3")

    monkeypatch.setattr(tls_module, "_handshake", fake_handshake)
    http.set_tls_verification(False)
    try:
        findings = tls_module.run("example.com")
    finally:
        http.set_tls_verification(True)
    assert seen[0] != ssl.CERT_NONE
    assert ssl.CERT_NONE in seen
    assert any("self-signed" in finding.title.lower() for finding in findings)


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
