import socket
import threading
import time

import pytest

import logging

from gambit.net import (
    MAX_RESOLVER_THREADS,
    ResolverSaturated,
    clear_resolution_cache,
    connect,
    is_public_ip,
    resolution_saturated,
    resolve_ips,
)


def _resolver_threads() -> list[threading.Thread]:
    return [
        thread
        for thread in threading.enumerate()
        if thread.name.startswith("gambit-resolve") and thread.is_alive()
    ]


def _join_resolver_threads(timeout: float = 2.0) -> None:
    """Wait out lookups left in ``getaddrinfo`` so they release their slot.

    The resolver cap is process-wide. A sleeper from an earlier test still
    occupies one slot, and on a slow scheduler that slot can free in the
    middle of the next test.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        alive = _resolver_threads()
        if not alive:
            return
        remaining = deadline - time.monotonic()
        for thread in alive:
            thread.join(min(0.1, max(0.0, remaining)))


@pytest.fixture(autouse=True)
def _clear_dns_cache():
    clear_resolution_cache()
    yield
    clear_resolution_cache()
    _join_resolver_threads(2.0)


def test_public_address_check_rejects_metadata_and_private_ranges():
    assert is_public_ip("93.184.216.34")
    assert is_public_ip("2606:4700:4700::1111")
    assert not is_public_ip("169.254.169.254")
    assert not is_public_ip("127.0.0.1")
    assert not is_public_ip("10.1.1.1")
    assert not is_public_ip("100.64.0.1")
    assert not is_public_ip("not-an-ip")


def test_connect_resolves_with_a_deadline_then_dials_the_ip(monkeypatch):
    seen = {}

    def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        seen.setdefault("hosts", []).append(host)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))
        ]

    def fake_create_connection(address, timeout=None):
        seen["address"] = address
        seen["timeout"] = timeout

        class Sock:
            def close(self):
                pass

        return Sock()

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    sock = connect("example.com", 443, 1.25)
    assert sock is not None
    assert seen["address"] == ("93.184.216.34", 443)
    assert seen["timeout"] == 1.25
    # One system lookup covers every family. The deadline is not paid per record type.
    assert seen["hosts"] == ["example.com"]


def test_resolve_ips_uses_one_deadline_for_every_family(monkeypatch):
    calls = []
    release = threading.Event()

    def slow_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        calls.append(host)
        # One second unless the test is done. Leaving the thread in sleep
        # would hold a resolver slot into the next test.
        release.wait(1.0)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 0, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", slow_getaddrinfo)
    try:
        started = time.monotonic()
        assert resolve_ips("example.com", 0.3) == []
        elapsed = time.monotonic() - started
        assert elapsed < 0.8
        assert calls == ["example.com"]
    finally:
        release.set()
        _join_resolver_threads()


def test_resolve_ips_localhost_uses_the_system_resolver():
    ips = resolve_ips("localhost", 2.0)
    assert any(ip in {"127.0.0.1", "::1"} for ip in ips)


def test_connect_reaches_localhost_from_the_system_resolver():
    ips = resolve_ips("localhost", 2.0)
    assert ips
    first = ips[0]
    family = socket.AF_INET6 if ":" in first.split("%", 1)[0] else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    if family == socket.AF_INET6:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listener.bind((first, 0))
    listener.listen(1)
    listener.settimeout(2)
    port = listener.getsockname()[1]
    client = None
    accepted = None
    try:
        client = connect("localhost", port, 2)
        accepted, _addr = listener.accept()
    finally:
        if accepted is not None:
            accepted.close()
        if client is not None:
            client.close()
        listener.close()


def test_connect_uses_supplied_addresses_without_resolving(monkeypatch):
    seen = []

    def fail_getaddrinfo(*args, **kwargs):
        raise AssertionError("getaddrinfo should not be called")

    def fake_create_connection(address, timeout=None):
        seen.append((address, timeout))

        class Sock:
            def close(self):
                pass

        return Sock()

    monkeypatch.setattr(socket, "getaddrinfo", fail_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    sock = connect("example.com", 80, 1.5, resolved=["203.0.113.5"])
    assert sock is not None
    assert seen == [(("203.0.113.5", 80), 1.5)]
    with pytest.raises(OSError):
        connect("example.com", 80, 1.5, resolved=[])


def test_resolve_ips_reuses_a_finished_lookup(monkeypatch):
    calls = []

    def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.9", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert resolve_ips("Cache.Example", 1) == ["203.0.113.9"]
    assert resolve_ips("cache.example", 1) == ["203.0.113.9"]
    assert calls == ["Cache.Example"]
    clear_resolution_cache()
    assert resolve_ips("cache.example", 1) == ["203.0.113.9"]
    assert calls == ["Cache.Example", "cache.example"]


def test_hanging_resolver_across_many_hosts_does_not_grow_threads(monkeypatch):
    release = threading.Event()
    entered = []
    entered_lock = threading.Lock()

    def hang(host, port, family=0, type=0, proto=0, flags=0):
        with entered_lock:
            entered.append(host)
        # Loop so a spurious wakeup cannot drop the slot mid-test.
        while not release.is_set():
            release.wait(0.2)
        return []

    monkeypatch.setattr(socket, "getaddrinfo", hang)
    before = {
        thread.ident
        for thread in threading.enumerate()
        if thread.name.startswith("gambit-resolve")
    }
    hosts = [f"hung-{index}.example" for index in range(MAX_RESOLVER_THREADS + 20)]
    errors = []

    def lookup(host):
        try:
            if resolve_ips(host, 0.4) != []:
                errors.append(host)
        except Exception as exc:  # the resolver must not raise
            errors.append(repr(exc))

    callers = [threading.Thread(target=lookup, args=(host,)) for host in hosts]
    try:
        for caller in callers:
            caller.start()
        for caller in callers:
            caller.join(3)
        assert errors == []
        assert all(not caller.is_alive() for caller in callers)
        alive = [
            thread
            for thread in threading.enumerate()
            if thread.name.startswith("gambit-resolve")
            and thread.is_alive()
            and thread.ident not in before
        ]
        assert len(hosts) > MAX_RESOLVER_THREADS
        assert 1 <= len(entered) <= MAX_RESOLVER_THREADS
        assert len(alive) <= MAX_RESOLVER_THREADS
        # A host that is already hung must not start a second lookup.
        hung_host = entered[0]
        with entered_lock:
            before_count = entered.count(hung_host)
        assert resolve_ips(hung_host, 0.1) == []
        with entered_lock:
            assert entered.count(hung_host) == before_count
    finally:
        release.set()
        for caller in callers:
            caller.join(2)
        _join_resolver_threads(3)


def test_transient_resolver_failure_is_not_cached(monkeypatch):
    calls = []

    def flaky(host, port, family=0, type=0, proto=0, flags=0):
        calls.append(host)
        if len(calls) == 1:
            raise socket.gaierror(socket.EAI_AGAIN, "temporary failure in name resolution")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.7", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", flaky)
    assert resolve_ips("flaky.example", 1) == []
    assert resolution_saturated("flaky.example") is False
    assert resolve_ips("flaky.example", 1) == ["203.0.113.7"]
    assert calls == ["flaky.example", "flaky.example"]


def test_saturated_resolver_is_signalled_and_not_cached(monkeypatch, caplog):
    # A lookup still running from an earlier test holds one shared slot.
    # On Windows that straggler can finish between two probes and make the
    # second probe look like a real lookup instead of a saturated skip.
    _join_resolver_threads(2.0)
    release = threading.Event()
    entered = []
    entered_lock = threading.Lock()
    full = threading.Event()

    def hang(host, port, family=0, type=0, proto=0, flags=0):
        with entered_lock:
            entered.append(host)
            if len(entered) >= MAX_RESOLVER_THREADS:
                full.set()
        while not release.is_set():
            release.wait(0.2)
        return []

    def fill(prefix: str) -> list[threading.Thread]:
        full.clear()
        threads = [
            threading.Thread(target=resolve_ips, args=(f"{prefix}-{index}.example", 5))
            for index in range(MAX_RESOLVER_THREADS)
        ]
        for thread in threads:
            thread.start()
        assert full.wait(5), "resolver pool did not fill"
        return threads

    monkeypatch.setattr(socket, "getaddrinfo", hang)
    holders: list[threading.Thread] = []
    try:
        holders = fill("hold")
        with entered_lock:
            assert len(entered) >= MAX_RESOLVER_THREADS
        with caplog.at_level(logging.WARNING, logger="gambit.net"):
            assert resolve_ips("healthy.example", 0.3) == []
        assert resolution_saturated("healthy.example") is True
        assert any(
            "saturated" in record.message.lower() and "healthy.example" in record.message
            for record in caplog.records
        )
        assert any("not cached" in record.message.lower() for record in caplog.records)
        # The pool is still full, so this is another skip, not a cached miss.
        assert resolve_ips("healthy.example", 0.3) == []
        assert resolution_saturated("healthy.example") is True
        with entered_lock:
            assert entered.count("healthy.example") == 0
    finally:
        release.set()
        for holder in holders:
            holder.join(2)
        _join_resolver_threads(2.0)

    def answer(host, port, family=0, type=0, proto=0, flags=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.8", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", answer)
    assert resolve_ips("healthy.example", 1) == ["198.51.100.8"]
    assert resolution_saturated("healthy.example") is False

    # connect distinguishes a full pool from an unresolvable name.
    release.clear()
    with entered_lock:
        entered.clear()
    monkeypatch.setattr(socket, "getaddrinfo", hang)
    blockers: list[threading.Thread] = []
    try:
        blockers = fill("block")
        with pytest.raises(ResolverSaturated):
            connect("again.example", 80, 0.3)
        assert resolution_saturated("again.example") is True
    finally:
        release.set()
        for blocker in blockers:
            blocker.join(2)
        _join_resolver_threads(2.0)


def test_slow_burst_finishes_inside_one_deadline(monkeypatch):
    def slow(host, port, family=0, type=0, proto=0, flags=0):
        time.sleep(0.3)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", slow)
    hosts = [f"slow-{index}.example" for index in range(20)]
    results: dict[str, list[str]] = {}

    def lookup(host):
        results[host] = resolve_ips(host, 1.0)

    callers = [threading.Thread(target=lookup, args=(host,)) for host in hosts]
    for caller in callers:
        caller.start()
    for caller in callers:
        caller.join(3)
    assert all(not caller.is_alive() for caller in callers)
    assert [results.get(host) for host in hosts] == [["203.0.113.10"]] * len(hosts)


def test_connect_refuses_a_port_that_would_wrap(monkeypatch):
    called = []
    monkeypatch.setattr(
        socket, "create_connection", lambda *args, **kwargs: called.append(args)
    )
    with pytest.raises(OSError):
        connect("example.com", 99999, 0.2)
    assert called == []
