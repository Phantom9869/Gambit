from gambit.models import Severity
from gambit.modules import gather
from gambit.modules.gather import evaluate_dns, parse_crtsh


def titles(findings):
    return [f.title for f in findings]


# --- parse_crtsh -------------------------------------------------------


def test_parse_crtsh_extracts_name_value_and_common_name():
    payload = [
        {"name_value": "www.example.com", "common_name": "example.com"},
        {"name_value": "api.example.com"},
    ]
    assert parse_crtsh(payload) == ["api.example.com", "example.com", "www.example.com"]


def test_parse_crtsh_splits_multiline_name_value_and_dedupes():
    payload = [{"name_value": "www.example.com\napi.example.com\nwww.example.com"}]
    assert parse_crtsh(payload) == ["api.example.com", "www.example.com"]


def test_parse_crtsh_strips_wildcards_trailing_dots_and_case():
    payload = [
        {"name_value": "*.WWW.Example.COM."},
        {"common_name": "*.api.example.com"},
        {"name_value": "www.example.com"},
    ]
    assert parse_crtsh(payload) == ["api.example.com", "www.example.com"]


def test_parse_crtsh_accepts_json_string_and_bytes():
    text = '[{"name_value": "www.example.com"}]'
    assert parse_crtsh(text) == ["www.example.com"]
    assert parse_crtsh(text.encode()) == ["www.example.com"]


def test_parse_crtsh_tolerates_malformed_input():
    assert parse_crtsh("not json") == []
    assert parse_crtsh('{"name_value": "www.example.com"}') == []
    assert parse_crtsh(None) == []
    assert parse_crtsh(42) == []
    assert parse_crtsh([42, None, {"name_value": 42}, {"other": "x"}]) == []


def test_parse_crtsh_skips_wildcard_only_and_empty_names():
    payload = [{"name_value": "*\n\n  \n*.example.com"}]
    # '*.example.com' normalizes to the apex name; the bare '*' is dropped.
    assert parse_crtsh(payload) == ["example.com"]


# --- evaluate_dns ------------------------------------------------------


def test_evaluate_dns_reports_each_record_type_as_info():
    records = {"A": ["192.0.2.1"], "MX": ["10 mail.example.com"], "NS": ["ns1.example.com"]}
    findings = evaluate_dns("example.com", records)
    assert "DNS A record(s) found" in titles(findings)
    assert "DNS MX record(s) found" in titles(findings)
    assert all(f.severity == Severity.INFO for f in findings)
    assert all(f.host == "example.com" for f in findings)


def test_evaluate_dns_accepts_single_string_values():
    findings = evaluate_dns("example.com", {"A": "192.0.2.1"})
    assert "DNS A record(s) found" in titles(findings)


def test_evaluate_dns_flags_missing_spf_and_dmarc():
    findings = evaluate_dns("example.com", {"A": ["192.0.2.1"]})
    assert "No SPF record found" in titles(findings)
    assert "No DMARC record found" in titles(findings)


def test_evaluate_dns_spf_in_txt_suppresses_spf_finding_only():
    records = {"TXT": ["v=spf1 include:_spf.example.com -all"]}
    findings = evaluate_dns("example.com", records)
    assert "No SPF record found" not in titles(findings)
    assert "No DMARC record found" in titles(findings)


def test_evaluate_dns_quoted_spf_and_dmarc_are_recognised():
    records = {
        "TXT": ['"v=spf1 -all"'],
        "DMARC": ['"v=DMARC1; p=reject"'],
    }
    findings = evaluate_dns("example.com", records)
    assert "No SPF record found" not in titles(findings)
    assert "No DMARC record found" not in titles(findings)
    assert "DMARC record(s) found" in titles(findings)


def test_evaluate_dns_unrelated_txt_does_not_count_as_spf():
    findings = evaluate_dns("example.com", {"TXT": ["google-site-verification=abc"]})
    assert "No SPF record found" in titles(findings)


def test_evaluate_dns_empty_records_reports_no_records_plus_mail_warnings():
    findings = evaluate_dns("example.com", {})
    assert titles(findings)[0] == "No DNS records found"
    assert "No SPF record found" in titles(findings)
    assert "No DMARC record found" in titles(findings)
    assert evaluate_dns("example.com", None) == findings


def test_evaluate_dns_ignores_empty_values():
    findings = evaluate_dns("example.com", {"A": [], "TXT": ["", "  "]})
    assert "DNS A record(s) found" not in titles(findings)
    assert "No DNS records found" in titles(findings)


# --- crt.sh is queried once per host per process -------------------------


def test_crtsh_fetch_is_cached_between_run_and_discovery(monkeypatch):
    gather.clear_crtsh_cache()
    calls = []

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return [{"name_value": "www.example.com\nexample.com"}]

    def fake_get(url, **kwargs):
        calls.append(url)
        return FakeResponse()

    monkeypatch.setattr(gather, "get", fake_get)
    monkeypatch.setattr(gather, "lookup_dns", lambda host: {})

    try:
        assert gather.discover_subdomains("example.com") == ["www.example.com"]
        findings = gather.run("example.com")
        assert "Subdomains discovered via crt.sh" in titles(findings)
        assert len(calls) == 1  # second call served from cache
    finally:
        gather.clear_crtsh_cache()
