from gambit.models import Severity
from gambit.modules.exposed_files import CHECKS, evaluate


def check_for(path):
    return next(c for c in CHECKS if c.path == path)


def test_git_head_is_detected():
    finding = evaluate("example.com", check_for("/.git/HEAD"), 200, "ref: refs/heads/main\n")
    assert finding is not None
    assert finding.severity == Severity.HIGH


def test_html_page_is_not_a_git_head():
    body = "<!doctype html><html><body>Welcome</body></html>"
    assert evaluate("example.com", check_for("/.git/HEAD"), 200, body) is None


def test_non_200_is_ignored():
    assert evaluate("example.com", check_for("/.git/HEAD"), 404, "ref: refs/heads/main") is None


def test_env_file_is_detected():
    body = "DB_HOST=localhost\nSECRET_KEY=abc123\n"
    finding = evaluate("example.com", check_for("/.env"), 200, body)
    assert finding is not None
    assert finding.severity == Severity.HIGH


def test_html_containing_env_text_is_ignored():
    body = "<html><body>APP_NAME=demo</body></html>"
    assert evaluate("example.com", check_for("/.env"), 200, body) is None


def test_evidence_never_contains_file_contents():
    finding = evaluate("example.com", check_for("/.env"), 200, "SECRET_KEY=hunter2\n")
    assert "hunter2" not in finding.evidence


def test_robots_txt_is_info():
    body = "User-agent: *\nDisallow: /admin\n"
    finding = evaluate("example.com", check_for("/robots.txt"), 200, body)
    assert finding is not None
    assert finding.severity == Severity.INFO
