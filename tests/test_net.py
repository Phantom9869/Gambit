import socket
import time

import pytest

from gambit.net import connect, is_public_ip, resolve_ips


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


def test_connect_refuses_a_port_that_would_wrap(monkeypatch):
    called = []
    monkeypatch.setattr(
        socket, "create_connection", lambda *args, **kwargs: called.append(args)
    )
    with pytest.raises(OSError):
        connect("example.com", 99999, 0.2)
    assert called == []
