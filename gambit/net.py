"""Network helpers with a deadline on DNS, not only on the TCP handshake.

``socket.create_connection`` resolves names with ``getaddrinfo`` before it
starts the connect timer, so a stuck resolver can hang a scan forever.
:func:`resolve_ips` asks the system resolver (so ``/etc/hosts``, mDNS, and
NSS apply) inside a daemon thread and stops waiting at ``timeout``. One
lookup covers both address families; the deadline is not spent twice.

A lookup that outruns the deadline is abandoned. Python cannot cancel
``getaddrinfo``, so the thread keeps running until libc returns, but the
scan does not wait for it. At most :data:`MAX_RESOLVER_THREADS` of those
threads exist at once. A further lookup waits for a free slot only until
its own deadline, then returns ``[]`` without caching that skip.
:func:`resolution_saturated` is true for that host until a later call
actually runs, and a warning is logged, so a full pool is not reported
as a name that does not resolve. Only a non-empty answer is remembered
until :func:`clear_resolution_cache`. The threads are daemons and do
not hold the process open.
"""

import ipaddress
import logging
import socket
import threading
import time

# Hung getaddrinfo calls cannot be cancelled. The cap has to be large
# enough that a burst of slow-but-healthy lookups still finishes inside
# one deadline; a handful of hung names must not crowd everyone else out.
MAX_RESOLVER_THREADS = 16

_log = logging.getLogger("gambit.net")
_slots = threading.BoundedSemaphore(MAX_RESOLVER_THREADS)
_state_lock = threading.Lock()
_cache: dict[str, tuple[str, ...]] = {}
_pending: dict[str, threading.Event] = {}
# Hosts whose latest attempt did not run because every slot was busy.
# This is a signal, not a negative cache: the next call tries again.
_saturated: set[str] = set()
_generation = 0


class ResolverSaturated(OSError):
    """The name was not looked up; every resolver thread is still in libc.

    Distinct from an empty answer. Nothing was cached, so the next call
    tries again. :func:`connect` raises this; :func:`resolve_ips` still
    returns ``[]`` and never raises.
    """


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


def clear_resolution_cache() -> None:
    """Forget cached DNS answers so the next scan resolves names again.

    A lookup already blocked in ``getaddrinfo`` keeps its slot until libc
    returns. If this is called first, that late answer is not cached.
    """
    global _generation
    with _state_lock:
        _generation += 1
        _cache.clear()
        _pending.clear()
        _saturated.clear()


def resolve_ips(hostname: str, timeout: float) -> list[str]:
    """Resolve ``hostname`` to IP strings within ``timeout`` seconds.

    An address literal is returned as itself, with no name lookup. The
    system resolver (``getaddrinfo``) is used for every other name, so
    hosts-file and NSS answers are visible. Failures, an empty answer,
    and a lookup that exceeds ``timeout`` all yield ``[]``; they never
    raise. The whole lookup shares one deadline.

    A finished lookup that returned at least one address is reused until
    :func:`clear_resolution_cache`. An empty answer or a resolver error
    (including a transient ``EAI_AGAIN``) is not cached, so the next call
    tries again. The same host never occupies more than one resolver
    thread. When every slot is already taken, this waits only until
    ``timeout``, logs a warning, marks the host via
    :func:`resolution_saturated`, and returns ``[]`` without caching.
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

    name = str(hostname).strip()
    key = _resolution_key(name)
    deadline = time.monotonic() + budget

    with _state_lock:
        cached = _cache.get(key)
        if cached is not None:
            return list(cached)
        event = _pending.get(key)
        generation = _generation
        if event is None:
            event = threading.Event()
            _pending[key] = event
            owner = True
        else:
            owner = False

    if not owner:
        return _wait_for_resolution(key, event, deadline)

    remaining = deadline - time.monotonic()
    if remaining <= 0 or not _slots.acquire(timeout=remaining):
        with _state_lock:
            if _generation == generation:
                _saturated.add(key)
        _abandon_resolution(key, event, generation)
        _log.warning(
            "DNS resolver saturated (%d lookups in flight); skipped %s. "
            "The skip is not cached.",
            MAX_RESOLVER_THREADS,
            name,
        )
        return []

    with _state_lock:
        _saturated.discard(key)

    def worker() -> None:
        ips: tuple[str, ...] = ()
        try:
            ips = tuple(_resolve_system(name))
        except Exception:
            ips = ()
        finally:
            try:
                with _state_lock:
                    if _generation == generation and _pending.get(key) is event:
                        # Empty and failed answers stay uncached so a
                        # transient EAI_AGAIN can succeed on the next call.
                        if ips:
                            _cache[key] = ips
                        _pending.pop(key, None)
                        _saturated.discard(key)
                event.set()
            finally:
                _slots.release()

    thread = threading.Thread(target=worker, name="gambit-resolve", daemon=True)
    try:
        thread.start()
    except Exception:
        _slots.release()
        _abandon_resolution(key, event, generation)
        raise
    return _wait_for_resolution(key, event, deadline)


def _abandon_resolution(key: str, event: threading.Event, generation: int) -> None:
    """Drop a lookup that never started so later calls can try again."""
    with _state_lock:
        if _generation == generation and _pending.get(key) is event:
            _pending.pop(key, None)
    event.set()


def _wait_for_resolution(
    key: str, event: threading.Event, deadline: float
) -> list[str]:
    """Wait until ``deadline`` for ``key`` to land in the cache."""
    remaining = deadline - time.monotonic()
    if remaining > 0:
        event.wait(remaining)
    with _state_lock:
        cached = _cache.get(key)
    if cached is None:
        return []
    return list(cached)


def _resolution_key(hostname: str) -> str:
    return str(hostname).strip().lower()


def resolution_saturated(hostname: str) -> bool:
    """True when the latest lookup for ``hostname`` was skipped.

    The pool was full, so no ``getaddrinfo`` ran and nothing was cached.
    A later :func:`resolve_ips` tries again and clears this once a lookup
    actually starts. An empty answer from the resolver does not set it.
    """
    with _state_lock:
        return _resolution_key(hostname) in _saturated


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
    not, and raises. Raises :class:`ResolverSaturated` when the lookup
    was skipped because every resolver thread was busy, and ``OSError``
    when the name does not resolve or every address refuses the connection.
    """
    number = int(port)
    if number < 1 or number > 65535:
        raise OSError(f"port out of range: {port}")
    ips = list(resolved) if resolved is not None else resolve_ips(hostname, timeout)
    if not ips:
        if resolved is None and resolution_saturated(hostname):
            raise ResolverSaturated(
                f"DNS resolver saturated; could not resolve {hostname}"
            )
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


__all__ = [
    "MAX_RESOLVER_THREADS",
    "ResolverSaturated",
    "clear_resolution_cache",
    "connect",
    "is_ip_address",
    "is_public_ip",
    "resolution_saturated",
    "resolve_ips",
]
