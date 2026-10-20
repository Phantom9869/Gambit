from gambit.models import Finding, Severity
from gambit.pipeline import dedupe_hosts, discover_hosts, normalize_host, run_for_host, run_pipeline


def make_finding(host, title="found"):
    return Finding(Severity.INFO, host, title, "e", "w", "n")


class GoodModule:
    def run(self, target):
        return [make_finding(target, f"good:{target}")]


class NoneModule:
    def run(self, target):
        return None


class BadModule:
    def run(self, target):
        raise RuntimeError("boom")


# --- normalize / dedupe --------------------------------------------------


def test_normalize_host_strips_scheme_path_wildcard_and_case():
    assert normalize_host("  HTTPS://WWW.Example.COM./path?q=1 ") == "www.example.com"
    assert normalize_host("*.api.example.com") == "api.example.com"
    assert normalize_host("") == ""
    assert normalize_host("user@example.com") == "example.com"


def test_dedupe_hosts_normalizes_and_keeps_first_occurrence_order():
    hosts = ["WWW.Example.com.", "www.example.com", "https://api.example.com/x", "api.example.com"]
    assert dedupe_hosts(hosts) == ["www.example.com", "api.example.com"]


def test_dedupe_hosts_drops_empties_and_handles_none():
    assert dedupe_hosts([None, "", "  ", "a.example.com"]) == ["a.example.com"]
    assert dedupe_hosts(None) == []
    assert dedupe_hosts([]) == []


def test_dedupe_hosts_cap():
    hosts = [f"h{i}.example.com" for i in range(5)]
    assert dedupe_hosts(hosts, max_hosts=2) == hosts[:2]
    assert dedupe_hosts(hosts, max_hosts=0) == []
    assert dedupe_hosts(hosts, max_hosts=None) == hosts


# --- discover_hosts ------------------------------------------------------


def test_discover_hosts_apex_first_then_discovered_deduped():
    hosts = discover_hosts(
        "Example.COM",
        discover=lambda target: ["www.example.com", "example.com", "*.api.example.com"],
    )
    assert hosts == ["example.com", "www.example.com", "api.example.com"]


def test_discover_hosts_passes_normalized_target_to_discover():
    seen = []
    discover_hosts("HTTPS://Example.com/path", discover=lambda t: seen.append(t) or [])
    assert seen == ["example.com"]


def test_discover_hosts_caps_total_including_apex():
    hosts = discover_hosts(
        "example.com",
        discover=lambda target: [f"h{i}.example.com" for i in range(10)],
        max_hosts=3,
    )
    assert hosts == ["example.com", "h0.example.com", "h1.example.com"]


def test_discover_hosts_extra_hosts_come_after_discovered():
    hosts = discover_hosts(
        "example.com",
        extra_hosts=["extra.example.com", "www.example.com"],
        discover=lambda target: ["www.example.com"],
    )
    assert hosts == ["example.com", "www.example.com", "extra.example.com"]


def test_discover_hosts_survives_discover_failure_and_none():
    def boom(target):
        raise RuntimeError("crt.sh down")

    assert discover_hosts("example.com", discover=boom) == ["example.com"]
    assert discover_hosts("example.com", discover=lambda t: None) == ["example.com"]


def test_discover_hosts_single_string_discovery_counts_as_one_host():
    assert discover_hosts("example.com", discover=lambda t: "www.example.com") == [
        "example.com",
        "www.example.com",
    ]


# --- run_for_host --------------------------------------------------------


def test_run_for_host_collects_findings_in_module_order():
    findings = run_for_host("example.com", [GoodModule(), GoodModule()])
    assert [f.title for f in findings] == ["good:example.com", "good:example.com"]


def test_run_for_host_isolates_module_failure():
    findings = run_for_host("example.com", [BadModule(), GoodModule()])
    assert len(findings) == 2
    failure, good = findings
    assert failure.severity == Severity.INFO
    assert "failed" in failure.title
    assert "boom" in failure.evidence
    assert failure.host == "example.com"
    assert good.title == "good:example.com"


def test_run_for_host_treats_none_result_and_no_modules_as_empty():
    assert run_for_host("example.com", [NoneModule()]) == []
    assert run_for_host("example.com", []) == []
    assert run_for_host("example.com", None) == []


# --- run_pipeline ----------------------------------------------------------


def test_run_pipeline_caps_hosts_and_sleeps_only_between_hosts():
    sleeps = []
    findings = run_pipeline(
        "example.com",
        [GoodModule()],
        hosts=["a.example.com", "b.example.com", "c.example.com"],
        max_hosts=2,
        sleep=sleeps.append,
    )
    assert [f.host for f in findings] == ["example.com", "a.example.com"]
    assert sleeps == [0.5]  # default delay, once between the two hosts


def test_run_pipeline_failure_on_one_host_does_not_stop_others():
    class FlakyModule:
        def run(self, target):
            if target == "example.com":
                raise RuntimeError("apex boom")
            return [make_finding(target)]

    findings = run_pipeline(
        "example.com", [FlakyModule()], hosts=["a.example.com"], delay=0, sleep=lambda s: None
    )
    assert len(findings) == 2
    assert findings[0].severity == Severity.INFO and "failed" in findings[0].title
    assert findings[1].host == "a.example.com"
