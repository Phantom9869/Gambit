from gambit.models import Severity
from gambit.modules.ports import (
    ALT_WEB_PORTS,
    DATABASE_PORTS,
    PORTS,
    TIMEOUT,
    WEB_PORTS,
    evaluate,
    run,
    service_for_port,
    severity_for_port,
)


def test_standard_web_ports_are_info():
    assert severity_for_port(80) == Severity.INFO
    assert severity_for_port(443) == Severity.INFO


def test_alt_web_ports_are_low():
    for port in ALT_WEB_PORTS:
        assert severity_for_port(port) == Severity.LOW


def test_database_ports_are_med():
    for port in DATABASE_PORTS:
        assert severity_for_port(port) == Severity.MED
    assert severity_for_port(3306) == Severity.MED
    assert severity_for_port(6379) == Severity.MED


def test_unknown_port_defaults_to_info():
    assert severity_for_port(9999) == Severity.INFO
    assert severity_for_port(22) == Severity.INFO


def test_port_list_is_polite_deduped_and_covers_groups():
    assert len(PORTS) == len(set(PORTS))
    assert set(PORTS) == set(WEB_PORTS) | set(ALT_WEB_PORTS) | set(DATABASE_PORTS)
    assert len(PORTS) <= 12


def test_service_for_port():
    assert service_for_port(443) == "HTTPS"
    assert service_for_port(5432) == "PostgreSQL"
    assert service_for_port(12345) == "unknown"


def test_explicit_port_is_probed_and_out_of_range_port_is_not(monkeypatch):
    tried = []

    def fake_connect(hostname, port, timeout, resolved=None):
        tried.append((hostname, port, resolved))
        raise OSError("closed")

    monkeypatch.setattr("gambit.net.connect", fake_connect)
    monkeypatch.setattr("gambit.net.resolve_ips", lambda host, timeout: ["203.0.113.1"])
    assert run("example.com:9090") == []
    assert ("example.com", 9090, ["203.0.113.1"]) in tried
    tried.clear()
    assert run("example.com:99999") == []
    assert all(port != 99999 and port != 34463 for _host, port, _ips in tried)
    assert ("example.com", 443, ["203.0.113.1"]) in tried


def test_run_resolves_the_host_once(monkeypatch):
    resolved_calls = []
    connect_calls = []

    def fake_resolve(host, timeout):
        resolved_calls.append((host, timeout))
        return ["203.0.113.1"]

    def fake_connect(hostname, port, timeout, resolved=None):
        connect_calls.append(resolved)
        raise OSError("closed")

    monkeypatch.setattr("gambit.net.resolve_ips", fake_resolve)
    monkeypatch.setattr("gambit.net.connect", fake_connect)
    assert run("example.com") == []
    assert resolved_calls == [("example.com", TIMEOUT)]
    assert len(connect_calls) == len(PORTS)
    assert all(ips == ["203.0.113.1"] for ips in connect_calls)


def test_evaluate_builds_finding_for_open_port():
    finding = evaluate("example.com", 6379)
    assert finding.severity == Severity.MED
    assert finding.host == "example.com"
    assert "6379" in finding.title and "Redis" in finding.title
    assert "never be" in finding.why or "never" in finding.why

    finding = evaluate("example.com", 8080)
    assert finding.severity == Severity.LOW
    assert "8080" in finding.title
