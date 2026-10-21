import socket

import dns.resolver
import pytest

from gambit.net import connect, is_public_ip


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

    def fake_resolve(name, rdtype, lifetime=None):
        seen.setdefault("queries", []).append((name, rdtype, lifetime))
        if rdtype == "AAAA":
            raise dns.resolver.NoAnswer()

        class Answer:
            address = "93.184.216.34"

        return [Answer()]

    def fake_create_connection(address, timeout=None):
        seen["address"] = address
        seen["timeout"] = timeout

        class Sock:
            def close(self):
                pass

        return Sock()

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    sock = connect("example.com", 443, 1.25)
    assert sock is not None
    assert seen["address"] == ("93.184.216.34", 443)
    assert seen["timeout"] == 1.25
    assert ("example.com", "A", 1.25) in seen["queries"]
    assert all(item[2] == 1.25 for item in seen["queries"])


def test_connect_refuses_a_port_that_would_wrap(monkeypatch):
    called = []
    monkeypatch.setattr(
        socket, "create_connection", lambda *args, **kwargs: called.append(args)
    )
    with pytest.raises(OSError):
        connect("example.com", 99999, 0.2)
    assert called == []
