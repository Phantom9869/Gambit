"""Network helpers with a deadline on DNS, not only on the TCP handshake.

``socket.create_connection`` resolves names with ``getaddrinfo`` before it
starts the connect timer, so a stuck resolver can hang a scan forever.
:func:`resolve_ips` asks the system resolver (so ``/etc/hosts``, mDNS, and
NSS apply) inside a daemon thread and stops waiting at ``timeout``. One
lookup covers both address families; the deadline is not spent twice.

A lookup that outruns the deadline is abandoned. The thread keeps running
until the libc call returns — Python cannot cancel ``getaddrinfo`` — but
the scan does not wait for it, and the thread is a daemon so it will not
hold the process open.
"""

import ipaddress
import socket
import threading


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

    An address literal is returned as itself, with no name lookup. The
    system resolver (``getaddrinfo``) is used for every other name, so
    hosts-file and NSS answers are visible. Failures, an empty answer,
    and a lookup that exceeds ``timeout`` all yield ``[]``; they never
    raise. The whole lookup shares one deadline.
    """
    if is_ip_address(hostname):
        return [hostname]
    if not hostname or not str(hostname).strip():
        return []
    try:
        budget = float(timeout)
    except (TypeError, ValueError):
        return []
    if budget <= 0:
        return []

    box: dict = {}

    def worker() -> None:
        try:
            box["ips"] = _resolve_system(hostname)
        except Exception as exc:
            box["error"] = exc

    thread = threading.Thread(target=worker, name="gambit-resolve", daemon=True)
    thread.start()
    thread.join(budget)
    if thread.is_alive() or "ips" not in box:
        return []
    return list(box["ips"])


def _resolve_system(hostname: str) -> list[str]:
    """One ``getaddrinfo`` call: hosts file, then DNS, A and AAAA together."""
    try:
        infos = socket.getaddrinfo(
            hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except OSError:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for _family, socktype, _proto, _canon, sockaddr in infos:
        if socktype != socket.SOCK_STREAM:
            continue
        ip = sockaddr[0]
        if ip and ip not in seen:
            seen.add(ip)
            found.append(ip)
    return found


def connect(
    hostname: str,
    port: int,
    timeout: float,
    *,
    resolved: list[str] | None = None,
):
    """TCP-connect to ``hostname``:``port`` with DNS bounded by ``timeout``.

    The socket is connected to a resolved address, never to a name, so
    the second ``getaddrinfo`` only parses an IP literal. Ports outside
    1–65535 raise ``OSError`` instead of being truncated by the resolver.
    Pass ``resolved`` to dial addresses already looked up (one lookup
    for many ports). ``None`` resolves ``hostname``; an empty list does
    not, and raises. Raises ``OSError`` when the name does not resolve
    or every address refuses the connection.
    """
    number = int(port)
    if number < 1 or number > 65535:
        raise OSError(f"port out of range: {port}")
    ips = list(resolved) if resolved is not None else resolve_ips(hostname, timeout)
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
