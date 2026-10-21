from gambit.models import Severity
from gambit.modules.fingerprint import identify


def titles(findings):
    return [f.title for f in findings]


def test_identify_empty_inputs_find_nothing():
    assert identify("example.com", {}, [], "") == []
    assert identify("example.com") == []


def test_server_header_is_info_without_version_low():
    findings = identify("example.com", {"Server": "nginx"}, [], "")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "nginx" in findings[0].title


def test_server_header_with_version_also_flags_low():
    findings = identify("example.com", {"Server": "nginx/1.24.0"}, [], "")
    severities = {f.title: f.severity for f in findings}
    assert any(s == Severity.INFO for s in severities.values())
    low = [f for f in findings if f.severity == Severity.LOW]
    assert len(low) == 1
    assert "1.24.0" in low[0].title


def test_x_powered_by_with_version_flags_low():
    findings = identify("example.com", {"X-Powered-By": "PHP/8.2.1"}, [], "")
    assert any(f.severity == Severity.LOW and "8.2.1" in f.title for f in findings)


def test_header_names_are_case_insensitive():
    findings = identify("example.com", {"sErVeR": "Apache/2.4.57"}, [], "")
    assert any("Apache" in t for t in titles(findings))


def test_cookie_names_suggest_technology():
    cases = {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java",
        "csrftoken": "Django",
        "laravel_session": "Laravel",
        "connect.sid": "Express",
    }
    for name, tech in cases.items():
        findings = identify("example.com", {}, {name: "whatever"}, "")
        assert any(tech in t for t in titles(findings)), name


def test_cookie_values_never_leak_into_findings():
    secret = "hunter2-super-secret-value"
    findings = identify(
        "example.com",
        {"Set-Cookie": f"PHPSESSID={secret}"},
        {"PHPSESSID": secret, "sessionid": secret},
        "",
    )
    assert findings  # the cookies were recognised
    for finding in findings:
        assert secret not in finding.title
        assert secret not in finding.evidence
        assert secret not in finding.why


def test_cookies_accept_set_cookie_strings():
    findings = identify("example.com", {}, ["PHPSESSID=abc123; Path=/; HttpOnly"], "")
    assert any("PHP" in t for t in titles(findings))
    assert all("abc123" not in f.evidence for f in findings)


def test_unknown_cookie_is_generic_info():
    findings = identify("example.com", {}, {"tracking_id": "x"}, "")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "Cookie present: tracking_id" in findings[0].title


def test_html_markers_identify_technologies():
    cases = {
        '<link href="/wp-content/themes/x/style.css">': "WordPress",
        '<script id="__NEXT_DATA__" type="application/json">{}</script>': "Next.js",
        '<div data-reactroot=""></div>': "React",
        '<a href="/static/admin/css/base.css">admin</a>': "Django",
    }
    for body, tech in cases.items():
        findings = identify("example.com", {}, [], body)
        assert any(tech in t for t in titles(findings)), body


def test_bare_framework_words_in_html_are_not_markers():
    # Strong markers only: merely mentioning a framework must not fire.
    findings = identify("example.com", {}, [], "<p>Built with React and WordPress</p>")
    assert findings == []


def test_generator_meta_tag_both_attribute_orders():
    body1 = '<meta name="generator" content="WordPress 6.4">'
    body2 = '<meta content="Joomla! 4" name="generator">'
    assert any("WordPress 6.4" in t for t in titles(identify("example.com", {}, [], body1)))
    assert any("Joomla! 4" in t for t in titles(identify("example.com", {}, [], body2)))


def test_run_records_final_url_after_a_same_host_redirect(monkeypatch):
    from gambit.modules import fingerprint

    class Response:
        status_code = 200
        headers = {"Server": "nginx"}
        text = ""
        cookies = []
        url = "https://example.com/app"
        gambit_redirects = 1
        gambit_final_url = "https://example.com/app"

    monkeypatch.setattr(fingerprint, "get_for_host", lambda *args, **kwargs: Response())
    findings = fingerprint.run("example.com")
    assert findings
    assert any("final URL: https://example.com/app" in finding.evidence for finding in findings)


def test_findings_carry_host():
    findings = identify("sub.example.com", {"Server": "nginx"}, [], "")
    assert all(f.host == "sub.example.com" for f in findings)
