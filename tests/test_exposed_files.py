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


# --- expanded checks (Step 6) -------------------------------------------


def test_git_config_is_detected():
    body = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://example.com/r.git\n"
    finding = evaluate("example.com", check_for("/.git/config"), 200, body)
    assert finding is not None
    assert finding.severity == Severity.HIGH


def test_html_page_with_core_text_is_not_a_git_config():
    body = "<html><body>[core] repositoryformatversion = 0</body></html>"
    assert evaluate("example.com", check_for("/.git/config"), 200, body) is None


def test_git_config_non_200_is_ignored():
    assert evaluate("example.com", check_for("/.git/config"), 404, "[core]\n") is None


def test_ds_store_magic_at_offset_4_and_0():
    for body in ("\x00\x00\x00\x01Bud1\x00\x00", "Bud1payload"):
        finding = evaluate("example.com", check_for("/.DS_Store"), 200, body)
        assert finding is not None, repr(body)
        assert finding.severity == Severity.LOW


def test_ds_store_without_magic_is_ignored():
    assert evaluate("example.com", check_for("/.DS_Store"), 200, "just some text") is None
    assert evaluate("example.com", check_for("/.DS_Store"), 404, "Bud1payload") is None


def test_directory_listing_is_detected():
    body = (
        "<html><head><title>Index of /uploads/</title></head>"
        "<body><h1>Index of /uploads/</h1><a href=\"secret.txt\">secret.txt</a></body></html>"
    )
    finding = evaluate("example.com", check_for("/uploads/"), 200, body)
    assert finding is not None
    assert finding.severity == Severity.LOW
    # Evidence is a fixed signature string, never page contents / filenames.
    assert "secret.txt" not in finding.evidence


def test_directory_listing_parent_directory_variant():
    body = "<title>Index of /files/</title><a href=\"../\">Parent Directory</a>"
    assert evaluate("example.com", check_for("/files/"), 200, body) is not None


def test_directory_listing_title_alone_is_not_enough():
    body = "<html><head><title>Index of /uploads/</title></head><body>Welcome</body></html>"
    assert evaluate("example.com", check_for("/uploads/"), 200, body) is None


def test_normal_page_is_not_a_directory_listing():
    body = "<html><head><title>Uploads</title></head><body><h1>Uploads</h1></body></html>"
    assert evaluate("example.com", check_for("/uploads/"), 200, body) is None
    assert evaluate("example.com", check_for("/backup/"), 404, body) is None
