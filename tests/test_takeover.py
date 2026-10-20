from gambit.models import Severity
from gambit.modules.takeover import Fingerprint, evaluate, find_unclaimed_fingerprint, match_service

GITHUB = Fingerprint(
    service="GitHub Pages",
    cname_suffixes=("github.io",),
    fingerprints=("There isn't a GitHub Pages site here.",),
)
S3 = Fingerprint(
    service="Amazon S3",
    cname_suffixes=("s3.amazonaws.com",),
    fingerprints=("NoSuchBucket",),
)
SERVICES = [GITHUB, S3]


# --- match_service -----------------------------------------------------


def test_match_service_matches_subdomain_of_suffix():
    assert match_service("foo.github.io", SERVICES) == GITHUB
    assert match_service("deep.foo.github.io", SERVICES) == GITHUB


def test_match_service_matches_exact_suffix_and_normalizes():
    assert match_service("github.io", SERVICES) == GITHUB
    assert match_service("FOO.GitHub.IO.", SERVICES) == GITHUB


def test_match_service_rejects_suffix_lookalikes():
    # Suffix must be a whole label boundary, not a substring.
    assert match_service("notgithub.io", SERVICES) is None
    assert match_service("evilgithub.io", SERVICES) is None
    assert match_service("mygithub.io.example.com", SERVICES) is None
    assert match_service("github.io.example.com", SERVICES) is None
    assert match_service("fakegithub.io", SERVICES) is None


def test_match_service_unknown_empty_and_none():
    assert match_service("example.com", SERVICES) is None
    assert match_service("", SERVICES) is None
    assert match_service(None, SERVICES) is None


def test_match_service_uses_bundled_fingerprints_by_default():
    assert match_service("foo.github.io") is not None
    assert match_service("foo.github.io").service == "GitHub Pages"
    assert match_service("bucket.s3.amazonaws.com").service == "Amazon S3"


# --- find_unclaimed_fingerprint ----------------------------------------


def test_find_unclaimed_fingerprint_is_case_insensitive():
    assert find_unclaimed_fingerprint("error: nosuchbucket here", S3) == "NoSuchBucket"
    assert find_unclaimed_fingerprint("all good", S3) is None
    assert find_unclaimed_fingerprint("", S3) is None
    assert find_unclaimed_fingerprint(None, S3) is None


# --- evaluate ------------------------------------------------------------


def test_evaluate_no_cname_or_unknown_service_returns_none():
    assert evaluate("sub.example.com", None, fingerprints=SERVICES) is None
    assert evaluate("sub.example.com", "", fingerprints=SERVICES) is None
    assert evaluate("sub.example.com", "example.org", resolves=False, fingerprints=SERVICES) is None


def test_evaluate_unresolvable_known_service_is_high():
    finding = evaluate("sub.example.com", "foo.github.io", resolves=False, fingerprints=SERVICES)
    assert finding.severity == Severity.HIGH
    assert "Possible subdomain takeover" in finding.title
    assert "does not resolve" in finding.evidence


def test_evaluate_unclaimed_fingerprint_is_high_even_when_resolving():
    finding = evaluate(
        "sub.example.com",
        "foo.github.io",
        resolves=True,
        body="<html>There isn't a GitHub Pages site here.</html>",
        fingerprints=SERVICES,
    )
    assert finding.severity == Severity.HIGH
    assert "unclaimed fingerprint" in finding.evidence


def test_evaluate_resolving_known_service_without_fingerprint_is_info():
    finding = evaluate(
        "sub.example.com", "foo.github.io", resolves=True, body="Welcome", fingerprints=SERVICES
    )
    assert finding.severity == Severity.INFO
    assert finding.title == "CNAME points to GitHub Pages"


def test_evaluate_unknown_resolution_without_fingerprint_is_info():
    finding = evaluate("sub.example.com", "foo.github.io", fingerprints=SERVICES)
    assert finding.severity == Severity.INFO


def test_evaluate_evidence_never_claims_resource_is_unclaimed():
    finding = evaluate("sub.example.com", "foo.github.io", resolves=False, fingerprints=SERVICES)
    # Title says "Possible"; evidence/why must stay hedged, not definitive.
    assert "possible" in finding.title.lower()
    assert "is unclaimed" not in finding.evidence.lower()
    assert "may be unclaimed" in finding.why or "does not prove" in finding.why
