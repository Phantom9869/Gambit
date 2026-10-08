from gambit.modules.baseline_headers import check_headers


def titles(findings):
    return [f.title for f in findings]


def test_all_headers_missing_are_reported():
    findings = check_headers("example.com", {})
    assert "Missing strict-transport-security header" in titles(findings)
    assert len(findings) == 5


def test_present_header_is_not_reported():
    headers = {"Strict-Transport-Security": "max-age=63072000"}
    findings = check_headers("example.com", headers)
    assert "Missing strict-transport-security header" not in titles(findings)


def test_header_names_are_case_insensitive():
    headers = {"x-content-type-options": "nosniff"}
    findings = check_headers("example.com", headers)
    assert "Missing x-content-type-options header" not in titles(findings)


def test_frame_ancestors_covers_x_frame_options():
    headers = {"Content-Security-Policy": "frame-ancestors 'none'"}
    findings = check_headers("example.com", headers)
    assert "Missing x-frame-options header" not in titles(findings)
