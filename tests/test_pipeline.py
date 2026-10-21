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


# --- split_host_port / preflight / connectivity dedupe --------------------


def test_split_host_port():
    from gambit.pipeline import split_host_port

    assert split_host_port("example.com") == ("example.com", None)
    assert split_host_port("https://example.com:8443/path") == ("example.com", 8443)
    assert split_host_port("example.com:notaport") == ("example.com:notaport", None)


def test_split_host_port_ipv6_and_out_of_range_ports():
    from gambit.pipeline import normalize_host, port_out_of_range, split_host_port

    assert normalize_host("2001:db8::1") == "[2001:db8::1]"
    assert normalize_host("[::1]") == "[::1]"
    assert normalize_host("HTTPS://[2001:db8::1]:8443/path") == "[2001:db8::1]:8443"
    assert dedupe_hosts(["::1", "[::1]"]) == ["[::1]"]

    assert split_host_port("[::1]") == ("::1", None)
    assert split_host_port("2001:db8::1") == ("2001:db8::1", None)
    assert split_host_port("[2001:db8::1]:8443") == ("2001:db8::1", 8443)
    assert split_host_port("https://[2001:db8::1]:8443/x") == ("2001:db8::1", 8443)

    # 99999 must not survive as a port: getaddrinfo would wrap it to 34463.
    assert port_out_of_range("example.com:99999")
    assert split_host_port("example.com:99999") == ("example.com", None)
    assert split_host_port("example.com:65536") == ("example.com", None)
    assert split_host_port("example.com:0") == ("example.com", None)
    assert split_host_port("example.com:65535") == ("example.com", 65535)
    assert split_host_port("[2001:db8::1]:99999") == ("2001:db8::1", None)


def test_out_of_range_port_does_not_connect(monkeypatch):
    from gambit.pipeline import host_reachable

    called = []

    def fake_connect(*args, **kwargs):
        called.append(args)
        raise OSError("should not be called")

    monkeypatch.setattr("gambit.net.connect", fake_connect)
    assert host_reachable("example.com:99999", timeout=0.1) is False
    assert called == []


def test_preflight_open_alt_port_is_used_in_the_url(monkeypatch):
    import gambit.http as http
    from gambit.pipeline import host_reachable

    http.clear_scheme_cache()

    def fake_connect(hostname, port, timeout):
        if port not in (8443, 8080):
            raise OSError("closed")

        class Sock:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        # 8443 is tried before 8080, so this host looks HTTPS-on-8443.
        if port == 8443 and hostname == "alt.example":
            return Sock()
        if port == 8080 and hostname == "dev.example":
            return Sock()
        raise OSError("closed")

    monkeypatch.setattr("gambit.net.connect", fake_connect)
    assert host_reachable("alt.example", timeout=0.2) is True
    assert host_reachable("dev.example", timeout=0.2) is True

    seen = []

    def fake_request(method, url, **kwargs):
        seen.append(url)

        class Response:
            def __init__(self, url):
                self.url = url

        return Response(url)

    monkeypatch.setattr(http, "request", fake_request)
    http.get_for_host("alt.example")
    http.get_for_host("dev.example")
    assert seen[0] == "https://alt.example:8443"
    assert seen[1] == "http://dev.example:8080"
    http.clear_scheme_cache()


def test_run_pipeline_preflight_skips_dead_hosts():
    findings = run_pipeline(
        "example.com",
        [GoodModule()],
        hosts=["dead.example.com"],
        delay=0,
        sleep=lambda s: None,
        preflight=lambda host: host != "dead.example.com",
    )
    assert [f.host for f in findings] == ["example.com", "dead.example.com"]
    assert findings[0].title == "good:example.com"
    assert "did not respond" in findings[1].title


def test_run_for_host_reports_connectivity_failure_only_once():
    class FetchFailModule:
        def run(self, target):
            return [
                Finding(
                    Severity.INFO,
                    target,
                    "Could not fetch site",
                    "boom",
                    "w",
                    "n",
                )
            ]

    class TlsFailModule:
        def run(self, target):
            return [
                Finding(
                    Severity.INFO,
                    target,
                    "Could not check TLS",
                    "boom",
                    "w",
                    "n",
                )
            ]

    findings = run_for_host("example.com", [FetchFailModule(), TlsFailModule()])
    assert len(findings) == 1
    assert findings[0].title == "Could not fetch site"
