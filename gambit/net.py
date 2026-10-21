"""Network helpers with a deadline on DNS, not only on the TCP handshake.

``socket.create_connection`` resolves names with ``getaddrinfo`` before it
starts the connect timer, so a stuck resolver can hang a scan forever.
Callers here resolve with dnspython's ``lifetime`` first, then connect to
the resulting address.
"""

import ipaddress
import socket

import dns.exception
import dns.resolver


def is_ip_address(hostname: str) -> bool:
    """True when ``hostname`` is an IPv4 or IPv6 literal."""
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


def is_public_ip(ip: str) -> bool:
    """True when ``ip`` is a globally routable unicast address.

    Loopback, private, link-local (including cloud metadata), reserved,
    and documentation ranges are rejected. ``ipaddress``'s ``is_global``
    is the single check so CGNAT and TEST-NET stay on the private side.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(getattr(addr, "is_global", False))


def resolve_ips(hostname: str, timeout: float) -> list[str]:
    """Resolve ``hostname`` to IP strings within ``timeout`` seconds.

    An address literal is returned as itself, with no DNS query. DNS
    failures and an empty answer both yield ``[]``; they never raise.
    """
    if is_ip_address(hostname):
        return [hostname]
    found: list[str] = []
    seen: set[str] = set()
    for rdtype in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(hostname, rdtype, lifetime=timeout)
        except dns.exception.DNSException:
            continue
        for rdata in answers:
            ip = getattr(rdata, "address", None) or str(rdata).strip()
            if ip and ip not in seen:
                seen.add(ip)
                found.append(ip)
    return found


def connect(hostname: str, port: int, timeout: float):
    """TCP-connect to ``hostname``:``port`` with DNS bounded by ``timeout``.

    The socket is connected to a resolved address, never to a name, so
    ``getaddrinfo`` is only asked to parse an IP literal. Ports outside
    1–65535 raise ``OSError`` instead of being truncated by the resolver.
    Raises ``OSError`` when the name does not resolve or every address
    refuses the connection.
    """
    number = int(port)
    if number < 1 or number > 65535:
        raise OSError(f"port out of range: {port}")
    ips = resolve_ips(hostname, timeout)
    if not ips:
        raise OSError(f"could not resolve {hostname}")
    last: OSError | None = None
    for ip in ips:
        try:
            return socket.create_connection((ip, number), timeout=timeout)
        except OSError as exc:
            last = exc
    if last is None:
        raise OSError(f"could not connect to {hostname}:{number}")
    raise last


__all__ = ["connect", "is_ip_address", "is_public_ip", "resolve_ips"]
