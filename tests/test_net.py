import socket
import threading
import time

import pytest

from gambit.net import (
    MAX_RESOLVER_THREADS,
    clear_resolution_cache,
    connect,
    is_public_ip,
    resolve_ips,
)


@pytest.fixture(autouse=True)
def _clear_dns_cache():
    clear_resolution_cache()
    yield
    clear_resolution_cache()


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

    def slow_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        calls.append(host)
        time.sleep(1.0)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 0, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", slow_getaddrinfo)
    started = time.monotonic()
    assert resolve_ips("example.com", 0.3) == []
    elapsed = time.monotonic() - started
    assert elapsed < 0.8
    assert calls == ["example.com"]


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
        release.wait(10)
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
        for thread in threading.enumerate():
            if thread.name.startswith("gambit-resolve") and thread.ident not in before:
                thread.join(2)


def test_connect_refuses_a_port_that_would_wrap(monkeypatch):
    called = []
    monkeypatch.setattr(
        socket, "create_connection", lambda *args, **kwargs: called.append(args)
    )
    with pytest.raises(OSError):
        connect("example.com", 99999, 0.2)
    assert called == []
