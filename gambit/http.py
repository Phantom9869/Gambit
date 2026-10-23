"""Shared HTTP plumbing: the single source of truth for how GAMBIT fetches.

Every module goes through the helpers here so the User-Agent and timeout
stay identical (and honest) everywhere, and so tests / downstream modules
have one obvious seam to fake: ``gambit.http.requests.request`` (or the
individual helpers).

Target fetches additionally get an HTTPS -> HTTP fallback
(:func:`get_for_host` / :func:`options_for_host`): a site that serves
only plain HTTP is still worth checking for headers, CORS, and exposed
files. The scheme that works for a host is remembered for the rest of
the process, so only the first module to touch an HTTP-only host pays
for the failed HTTPS attempt.

Redirects are followed only up to :data:`MAX_REDIRECTS` hops, and only
when the host *requests will connect to* stays the same. That host is
taken from ``requests``' prepared URL parsed with ``urllib3``, because
``urllib.parse`` and urllib3 disagree on some Location values (a
backslash in the authority is the one that turns into an SSRF). The
TCP connection is opened to the addresses vetted for that host, not to
whatever a second lookup would return. The redirect port must be the
original port, or the other side of the 80/443 pair. A hop that fails
returns the redirect response already in hand.

A same-host redirect whose addresses are all public is followed. So is
one whose addresses are all non-public, when the original target is a
non-public literal **or** a name whose own first resolution was entirely
non-public (a hosts-file lab name, or ``localhost``). The redirect is
resolved again; a later private answer is not allowed to ride a first
answer that was public or mixed. Mixed addresses are refused either
way, so a public name cannot pivot into a private network.

``HTTP(S)_PROXY`` / ``proxies=`` skips the pin for URLs that would
actually use the proxy: a proxy resolves the name itself. ``NO_PROXY``
is applied per URL, and a bypassed host keeps the pin and may follow
redirects. The pinned session does not trust the environment for
proxies (that would undo the pin) but still honours
``REQUESTS_CA_BUNDLE`` / ``CURL_CA_BUNDLE`` when the caller did not pass
``verify=False`` or an explicit bundle path. A TLS *verification*
failure is not retried over plain HTTP. :func:`set_tls_verification`
can turn verification off for a scan (the ``--insecure`` flag). That
still speaks HTTPS; it does not downgrade a certificate failure to
plain HTTP.

DNS lookups are bounded, cached for the scan, and capped at a few
in-flight resolver threads. One that outruns its deadline does not
block the scan; see :mod:`gambit.net`.

Response bodies are streamed and capped at :data:`MAX_BODY` bytes unless
the caller is reading the stream itself.
"""

import ipaddress
import os
import socket
import ssl
import warnings
from typing import NamedTuple
from urllib.parse import urljoin

import requests
import urllib3.connection
import urllib3.exceptions
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.url import parse_url

from gambit.net import is_ip_address, is_public_ip, resolve_ips

# Identity of the real requests entry point. Tests replace
# ``gambit.http.requests.request``; when they have, pinning is skipped
# and that double is called instead.
_ORIGINAL_REQUEST = requests.request

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_HTTP_HTTPS_PORTS = frozenset((80, 443))

USER_AGENT = (
    "GAMBIT/0.1 (+https://github.com/Phantom9869/gambit; authorized testing only)"
)
TIMEOUT = 10  # seconds
MAX_REDIRECTS = 5
MAX_BODY = 1_048_576  # bytes buffered from a response that the caller does not stream

# host (as passed in, e.g. "example.com" or "example.com:8080") -> scheme
_SCHEME_BY_HOST: dict[str, str] = {}
# host -> non-default TCP port discovered by the liveness pre-flight
_PORT_BY_HOST: dict[str, int] = {}
# Safer default: verify certificates unless the operator opts out.
_tls_verification_enabled = True


def tls_verification_enabled() -> bool:
    """True when HTTPS fetches still check certificates."""
    return _tls_verification_enabled


def set_tls_verification(enabled: bool) -> None:
    """Turn TLS certificate verification on or off for later fetches.

    Off is the ``--insecure`` opt-in. Hostname and chain checks are
    skipped (``verify=False``) when a caller did not pass ``verify``
    itself. A certificate failure is still not retried over plain HTTP.
    """
    global _tls_verification_enabled
    _tls_verification_enabled = bool(enabled)
    # requests warns once per unverified call. The CLI surfaces one note
    # instead of a warning per host.
    warnings.simplefilter(
        "default" if _tls_verification_enabled else "ignore",
        InsecureRequestWarning,
    )


def request(
    method: str,
    url: str,
    *,
    timeout: float = TIMEOUT,
    headers: dict | None = None,
    **kwargs,
):
    """Send ``method`` to ``url`` with GAMBIT's User-Agent and timeout.

    ``headers`` (if given) are merged over the default User-Agent. Every
    other keyword is forwarded to :func:`requests.request`, except:

    * ``allow_redirects`` (default True) follows only same-host redirects
      on the same port (or the 80/443 pair) whose vetted addresses are
      all public — or all non-public when the original target is a
      non-public literal or a name that resolved only to non-public
      addresses — and at most :data:`MAX_REDIRECTS` of them. The host
      compared is the one the next request connects to. A cross-host
      redirect, a public-to-private pivot, a port change, or a Location
      containing a backslash, whitespace, or a control character is
      returned as the redirect response and is not fetched. Each
      connection uses the addresses that decision vetted. A followed hop
      that errors returns that redirect response instead of raising.
    * ``max_bytes`` (default :data:`MAX_BODY`) caps how much of the final
      body is buffered. Ignored when ``stream=True``; the caller then
      reads the body itself.
    * ``stream=True`` leaves the body unread.

    The final response carries ``gambit_redirects`` (hops actually
    followed) and ``gambit_final_url``. Network errors propagate as
    ``requests.RequestException``.
    """
    merged = {"User-Agent": USER_AGENT}
    if headers:
        merged.update(headers)
    allow_redirects = bool(kwargs.pop("allow_redirects", True))
    caller_streams = bool(kwargs.pop("stream", False))
    max_bytes = _as_limit(kwargs.pop("max_bytes", MAX_BODY))
    kwargs["allow_redirects"] = False
    kwargs["stream"] = True
    proxies = kwargs.get("proxies")

    current = url
    current_method = method
    original_host: str | None = None
    original_port: int | None = None
    # None until the first resolution of the scan target is classified.
    # A later hop must not overwrite it: public-then-private is a pivot.
    original_private: bool | None = None
    # Addresses the next pinned send must dial. Set only after a redirect
    # was allowed, so the connect cannot look the name up again.
    pending_ips: list[str] | None = None
    hops = 0
    response = None
    previous = None
    while True:
        target = _prepare_target(current)
        send_url = current
        proxied = _uses_proxy(target.url if target is not None else current, proxies)
        # Tests replace requests.request. Honour that double, and do not
        # pin through a proxy: the proxy would resolve the name itself.
        use_pin = requests.request is _ORIGINAL_REQUEST and not proxied
        if original_host is None:
            if target is not None:
                original_host = target.host
                original_port = target.port
            else:
                original_host = ""
        try:
            if use_pin:
                if target is None:
                    raise requests.InvalidURL(f"refusing ambiguous URL {current!r}")
                send_url = target.url
                if pending_ips is None:
                    ips = resolve_ips(_dns_name(target.host), _timeout_seconds(timeout))
                    if not ips:
                        raise requests.ConnectionError(
                            f"could not resolve {target.host}"
                        )
                    if original_private is None:
                        original_private = _is_private_target(original_host, ips)
                else:
                    ips = pending_ips
                    pending_ips = None
                response = _request_pinned(
                    current_method,
                    send_url,
                    headers=merged,
                    timeout=timeout,
                    ips=ips,
                    **kwargs,
                )
            else:
                response = requests.request(
                    current_method,
                    current,
                    headers=merged,
                    timeout=timeout,
                    **_apply_tls_verification(kwargs),
                )
                send_url = current
        except requests.RequestException:
            if previous is not None:
                response = previous
                break
            raise
        if previous is not None:
            _close_quietly(previous)
            previous = None
            hops += 1
        _stamp_redirect(response, hops, send_url)
        if not allow_redirects or proxied or hops >= MAX_REDIRECTS:
            break
        status = getattr(response, "status_code", 0) or 0
        location = _location_header(response)
        if status not in _REDIRECT_STATUSES or not _location_is_acceptable(location):
            break
        nxt = _prepare_target(urljoin(send_url, location.strip()))
        if (
            nxt is None
            or not original_host
            or original_port is None
            or not _ports_compatible(original_port, nxt.port)
            or _host_key(original_host) != _host_key(nxt.host)
            or _uses_proxy(nxt.url, proxies)
        ):
            break
        if original_private is None:
            try:
                snapshot = resolve_ips(
                    _dns_name(original_host), _timeout_seconds(timeout)
                )
            except Exception:
                break
            original_private = _is_private_target(original_host, snapshot)
        vetted = _vetted_redirect_ips(
            original_host, original_private, nxt.host, timeout
        )
        if vetted is None:
            break
        if status == 303:
            current_method = "GET"
        # Keep the redirect until the next hop succeeds. A failure
        # returns this response instead of raising.
        previous = response
        current = nxt.url
        if requests.request is _ORIGINAL_REQUEST:
            pending_ips = vetted
    if response is not None and not caller_streams:
        _buffer_limited(response, max_bytes)
    return response


def get(url: str, *, timeout: float = TIMEOUT, headers: dict | None = None, **kwargs):
    """GET ``url``; see :func:`request`. No scheme fallback (exact URL)."""
    return request("GET", url, timeout=timeout, headers=headers, **kwargs)


def options(url: str, *, timeout: float = TIMEOUT, headers: dict | None = None, **kwargs):
    """OPTIONS ``url``; see :func:`request`. No scheme fallback."""
    return request("OPTIONS", url, timeout=timeout, headers=headers, **kwargs)


def preferred_scheme(host: str) -> str | None:
    """Scheme known to work for ``host`` in this process, if any."""
    return _SCHEME_BY_HOST.get(host)


def preferred_port(host: str) -> int | None:
    """Non-default port discovered for ``host``, if the pre-flight found one."""
    return _PORT_BY_HOST.get(host)


def set_preferred_scheme(host: str, scheme: str) -> None:
    """Remember that ``scheme`` ("https"/"http") works for ``host``."""
    if scheme in ("https", "http"):
        _SCHEME_BY_HOST[host] = scheme


def set_preferred_port(host: str, port: int | None) -> None:
    """Remember a non-default port for ``host``, or forget it when ``None``."""
    if port is None:
        _PORT_BY_HOST.pop(host, None)
        return
    number = int(port)
    if 1 <= number <= 65535 and number not in (80, 443):
        _PORT_BY_HOST[host] = number
    else:
        _PORT_BY_HOST.pop(host, None)


def clear_scheme_cache() -> None:
    """Forget remembered schemes and discovered ports (mainly for tests)."""
    _SCHEME_BY_HOST.clear()
    _PORT_BY_HOST.clear()


def _schemes_to_try(host: str) -> list[str]:
    known = _SCHEME_BY_HOST.get(host)
    if known:
        return [known] + [s for s in ("https", "http") if s != known]
    return ["https", "http"]


def url_authority(target: str, scheme: str) -> str:
    """``host`` or ``host:port`` (IPv6 bracketed) for ``target``.

    An explicit valid port on ``target`` is always kept. Otherwise a port
    remembered by the pre-flight is included when it is not the default
    for ``scheme``. An out-of-range explicit port is omitted.
    """
    from gambit.pipeline import format_url_host, port_out_of_range, split_host_port

    if port_out_of_range(target):
        name, _port = split_host_port(target)
        return format_url_host(name or target, None)
    name, explicit = split_host_port(target)
    if not name:
        return target
    if explicit is not None:
        return format_url_host(name, explicit)
    discovered = preferred_port(target)
    if discovered is None:
        return format_url_host(name, None)
    if (scheme == "https" and discovered == 443) or (scheme == "http" and discovered == 80):
        return format_url_host(name, None)
    return format_url_host(name, discovered)


def _request_for_host(method: str, target: str, path: str = "", **kwargs):
    """``method`` request to ``target`` + ``path``, HTTPS first, HTTP fallback.

    Connection failures (:class:`requests.RequestException`) trigger the
    fallback; an HTTP error status is a real answer and is returned
    as-is. A TLS certificate verification failure is not a dead port:
    it is re-raised, and plain HTTP is not tried. That keeps an internal
    CA problem (or a hostname mismatch) from being silently downgraded.
    With verification disabled (:func:`set_tls_verification`), those
    certificates are accepted on HTTPS instead, and plain HTTP is still
    not used as a substitute. Raises the last exception if every scheme
    fails.
    """
    if path and not path.startswith("/"):
        path = "/" + path
    last_exc: Exception | None = None
    for scheme in _schemes_to_try(target):
        url = f"{scheme}://{url_authority(target, scheme)}{path}"
        try:
            response = request(method, url, **kwargs)
        except requests.RequestException as exc:
            if _is_tls_verify_failure(exc):
                raise requests.exceptions.SSLError(
                    "TLS certificate verification failed for "
                    f"{target}; not retrying over HTTP: {exc}"
                ) from exc
            last_exc = exc
            continue
        set_preferred_scheme(target, scheme)
        return response
    if last_exc is None:
        raise requests.RequestException(f"no request attempted for {target}")
    raise last_exc


def get_for_host(target: str, path: str = "", **kwargs):
    """GET ``target`` (a host, optionally with port) with HTTP fallback."""
    return _request_for_host("GET", target, path, **kwargs)


def options_for_host(target: str, path: str = "", **kwargs):
    """OPTIONS ``target`` with HTTP fallback."""
    return _request_for_host("OPTIONS", target, path, **kwargs)


def read_limited(response, limit: int) -> bytes:
    """Read at most ``limit`` bytes from a response body.

    Uses ``iter_content`` when the response has it, so a multi-gigabyte
    body is not buffered. A response with no streaming helper contributes
    its ``content`` attribute, still sliced to ``limit``.
    """
    if limit < 0:
        limit = 0
    reader = getattr(response, "iter_content", None)
    if not callable(reader):
        raw = getattr(response, "content", b"") or b""
        if isinstance(raw, str):
            raw = raw.encode("utf-8", errors="replace")
        return bytes(raw[:limit])
    chunks: list[bytes] = []
    total = 0
    for chunk in reader(chunk_size=8192):
        if not chunk:
            continue
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8", errors="replace")
        remaining = limit - total
        if remaining <= 0:
            break
        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def annotate_findings(findings, response):
    """Append the final URL when this response followed a redirect.

    Findings are unchanged when no redirect was followed, so graders that
    never see a live response keep their evidence text.
    """
    if not findings:
        return findings or []
    hops = int(getattr(response, "gambit_redirects", 0) or 0)
    final = getattr(response, "gambit_final_url", "") or ""
    if hops <= 0 or not final:
        return findings
    for finding in findings:
        if final not in (finding.evidence or ""):
            finding.evidence = f"{finding.evidence} (final URL: {final})"
    return findings


def _as_limit(value) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return MAX_BODY
    if number < 0:
        return 0
    return number


def _timeout_seconds(timeout) -> float:
    if isinstance(timeout, (tuple, list)) and timeout:
        return float(timeout[0])
    return float(timeout)


def _stamp_redirect(response, hops: int, url: str) -> None:
    try:
        response.gambit_redirects = hops
        response.gambit_final_url = url
    except Exception:
        return


def _location_header(response) -> str:
    headers = getattr(response, "headers", None) or {}
    getter = getattr(headers, "get", None)
    if not callable(getter):
        return ""
    for name in ("Location", "location"):
        value = getter(name)
        if value:
            return str(value)
    return ""


def _uses_proxy(url: str, proxies) -> bool:
    """True when ``url`` would be sent through a proxy.

    ``NO_PROXY`` / ``no_proxy`` is checked for this URL. A bypassed host
    is direct even when a proxy variable is set for other hosts. Any
    other configured proxy counts: the proxy would resolve the name, so
    the pin would not be the address that is contacted.
    """
    if isinstance(proxies, dict):
        mapping = proxies
    elif proxies:
        return True
    else:
        mapping = {}
    no_proxy = mapping.get("no_proxy")
    try:
        if requests.utils.should_bypass_proxies(url, no_proxy=no_proxy):
            return False
    except Exception:
        return True
    for key, value in mapping.items():
        if key == "no_proxy" or not value:
            continue
        return True
    try:
        return bool(requests.utils.get_environ_proxies(url, no_proxy=no_proxy))
    except Exception:
        return True


def _is_tls_verify_failure(exc: BaseException) -> bool:
    """True when ``exc`` is a certificate verification failure.

    Hostname mismatch, an untrusted internal CA, and an expired
    certificate all surface as ``CERTIFICATE_VERIFY_FAILED``. A protocol
    mismatch (plain HTTP on the HTTPS port) does not, and still falls
    back.
    """
    seen: set[int] = set()
    stack: list[BaseException] = [exc]
    while stack:
        current = stack.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        message = str(current).lower()
        if (
            "certificate_verify_failed" in message
            or "certificate verify failed" in message
        ):
            return True
        for attr in ("__cause__", "__context__", "reason"):
            nested = getattr(current, attr, None)
            if isinstance(nested, BaseException):
                stack.append(nested)
        for arg in getattr(current, "args", ()):
            if isinstance(arg, BaseException):
                stack.append(arg)
    return False


def _apply_tls_verification(kwargs: dict) -> dict:
    """Copy ``kwargs`` and apply the process verification policy.

    An explicit ``verify`` argument always wins, including ``verify=False``
    and a bundle path. When the caller left it unset and verification is
    disabled, certificate checks are turned off.
    """
    copied = dict(kwargs)
    if "verify" not in copied and not _tls_verification_enabled:
        copied["verify"] = False
    return copied


def _with_env_ca_bundle(kwargs: dict) -> dict:
    """Copy ``kwargs`` and apply ``REQUESTS_CA_BUNDLE`` / ``CURL_CA_BUNDLE``.

    The pinned session keeps ``trust_env`` false so an environment proxy
    cannot replace the dialed address. requests reads the CA bundle only
    when ``trust_env`` is true, so copy it into ``verify`` here.
    ``verify=False`` and an explicit bundle path are left alone. With
    verification disabled and no explicit ``verify``, the result is
    ``verify=False`` and the environment bundle is not consulted.
    """
    copied = _apply_tls_verification(kwargs)
    copied.pop("proxies", None)
    if "verify" not in copied:
        verify = True
    else:
        verify = copied.get("verify")
    if verify is False or (isinstance(verify, str) and verify):
        return copied
    if verify is True or verify is None:
        bundle = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get(
            "CURL_CA_BUNDLE"
        )
        if bundle:
            copied["verify"] = bundle
        elif verify is None:
            copied["verify"] = True
    return copied


def _location_is_acceptable(location: str) -> bool:
    """Reject Location values whose bytes parsers disagree on.

    A raw backslash ends the authority for urllib3 and is only userinfo
    for ``urllib.parse``, so ``http://127.0.0.1\\@example.com/`` is
    checked as example.com and fetched as 127.0.0.1. Whitespace and
    controls are stripped by one parser and kept by the other. Outer
    header whitespace is ignored; anything inside the value is refused.
    """
    if not location:
        return False
    value = location.strip()
    if not value:
        return False
    for char in value:
        code = ord(char)
        if char == "\\" or char.isspace() or code < 32 or code == 127:
            return False
    return True


class _Target(NamedTuple):
    url: str
    host: str
    port: int
    scheme: str


def _prepare_target(url: str) -> _Target | None:
    """Return the URL requests would connect to, plus host and port.

    ``PreparedRequest.url`` is what the adapter sends, and urllib3 parses
    that string again with :func:`urllib3.util.parse_url`. The host of
    that parse is the connection host. A URL that does not survive a
    second prepare unchanged is ambiguous and is refused. A missing port
    becomes 80 or 443 from the scheme, which is the port that is dialed.
    """
    try:
        prepared_url = requests.Request("GET", url).prepare().url
        if not isinstance(prepared_url, str) or not prepared_url:
            return None
        if requests.Request("GET", prepared_url).prepare().url != prepared_url:
            return None
        parsed = parse_url(prepared_url)
    except (
        requests.RequestException,
        urllib3.exceptions.LocationParseError,
        ValueError,
    ):
        return None
    if parsed.scheme not in ("http", "https") or not parsed.host:
        return None
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return _Target(prepared_url, parsed.host, int(port), parsed.scheme)


def _ports_compatible(origin: int, nxt: int) -> bool:
    """Same port, or the HTTP/HTTPS pair (80 and 443)."""
    return origin == nxt or {origin, nxt} == _HTTP_HTTPS_PORTS


def _host_key(host: str) -> str:
    """Comparable host: lower-case, no trailing dot, no IPv6 brackets."""
    name = host.strip().lower().rstrip(".")
    if len(name) >= 2 and name.startswith("[") and name.endswith("]"):
        name = name[1:-1]
    try:
        return ipaddress.ip_address(name).compressed
    except ValueError:
        return name


def _dns_name(host: str) -> str:
    """Host to resolve. Brackets are stripped; a trailing dot stays on names.

    The dot marks an absolute DNS name (no search-list suffix). It is
    removed only when what remains is an address literal.
    """
    name = host.strip()
    if len(name) >= 2 and name.startswith("[") and name.endswith("]"):
        name = name[1:-1]
    stripped = name.rstrip(".")
    if is_ip_address(stripped):
        return stripped
    return name


def _policy_ip(ip: str) -> str:
    """Address without an IPv6 zone id, for :func:`is_public_ip`."""
    return ip.split("%", 1)[0]


def _is_private_literal(host: str) -> bool:
    """True when ``host`` is an address literal that is not globally routable."""
    key = _host_key(host)
    return is_ip_address(key) and not is_public_ip(key)


def _is_private_target(host: str, ips: list[str]) -> bool:
    """True when the scan target itself is non-public.

    A non-public literal qualifies on its spelling. A name qualifies
    only when every address from its first resolution is non-public, so
    ``localhost`` and a hosts-file lab name follow same-host redirects.
    An empty answer does not: there is nothing to call private.
    """
    if _is_private_literal(host):
        return True
    if not ips:
        return False
    return all(not is_public_ip(_policy_ip(ip)) for ip in ips)


def _redirect_ips_allowed(original_private: bool, ips: list[str]) -> bool:
    """Whether ``ips`` may be dialed for a same-host redirect.

    All-public is the normal case. All-non-public is allowed only when
    the original target was itself private, so a public name cannot
    pivot. Mixed answers fail closed.
    """
    if not ips:
        return False
    public = [is_public_ip(_policy_ip(ip)) for ip in ips]
    if all(public):
        return True
    return original_private and not any(public)


def _vetted_redirect_ips(
    original_host: str, original_private: bool, next_host: str, timeout
) -> list[str] | None:
    """Addresses the redirect may be connected to, or None to stop.

    The next host must be the original host. It is resolved again; the
    first snapshot is only the privacy classification of the target.
    """
    if not original_host or not next_host:
        return None
    if _host_key(original_host) != _host_key(next_host):
        return None
    try:
        ips = resolve_ips(_dns_name(next_host), _timeout_seconds(timeout))
    except Exception:
        return None
    if not _redirect_ips_allowed(original_private, ips):
        return None
    return list(ips)


def _open_tcp_socket(ip: str, port: int, timeout, source_address, socket_options):
    """Connect to ``ip`` without another name lookup."""
    raw = ip
    scope = 0
    if "%" in ip:
        raw, zone = ip.split("%", 1)
        if zone.isdigit():
            scope = int(zone)
        else:
            try:
                scope = socket.if_nametoindex(zone)
            except OSError:
                scope = 0
    addr = ipaddress.ip_address(raw)
    family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        if socket_options:
            for level, opt, value in socket_options:
                sock.setsockopt(level, opt, value)
        if timeout is not None:
            sock.settimeout(float(timeout))
        if source_address:
            sock.bind(source_address)
        if addr.version == 6:
            sock.connect((raw, int(port), 0, scope))
        else:
            sock.connect((raw, int(port)))
        return sock
    except BaseException:
        sock.close()
        raise


def _pinned_connection_class(base, ips: tuple[str, ...]):
    """Connection class that dials ``ips`` and keeps ``host`` for Host/SNI."""

    class Pinned(base):
        def _new_conn(self):
            last: Exception | None = None
            for ip in ips:
                try:
                    return _open_tcp_socket(
                        ip,
                        self.port,
                        self.timeout,
                        self.source_address,
                        self.socket_options,
                    )
                except TimeoutError as exc:
                    last = urllib3.exceptions.ConnectTimeoutError(
                        self,
                        f"Connection to {ip} timed out. (connect timeout={self.timeout}): {exc}",
                    )
                except OSError as exc:
                    last = urllib3.exceptions.NewConnectionError(
                        self, f"Failed to establish a new connection: {exc}"
                    )
            if last is None:
                raise urllib3.exceptions.NewConnectionError(
                    self, "no vetted address to connect to"
                )
            raise last

    Pinned.__name__ = f"Pinned{base.__name__}"
    return Pinned


class _PinnedHTTPConnectionPool(urllib3.HTTPConnectionPool):
    def __init__(self, host, port=None, *, gambit_pinned_ips=None, **kwargs):
        super().__init__(host, port, **kwargs)
        if gambit_pinned_ips:
            self.ConnectionCls = _pinned_connection_class(
                urllib3.connection.HTTPConnection, tuple(gambit_pinned_ips)
            )


class _PinnedHTTPSConnectionPool(urllib3.HTTPSConnectionPool):
    def __init__(self, host, port=None, *, gambit_pinned_ips=None, **kwargs):
        super().__init__(host, port, **kwargs)
        if gambit_pinned_ips:
            self.ConnectionCls = _pinned_connection_class(
                urllib3.connection.HTTPSConnection, tuple(gambit_pinned_ips)
            )


class _PinnedPoolManager(urllib3.PoolManager):
    def __init__(self, pinned_ips, **kwargs):
        super().__init__(**kwargs)
        self._gambit_pinned_ips = tuple(pinned_ips)
        self.pool_classes_by_scheme = {
            "http": _PinnedHTTPConnectionPool,
            "https": _PinnedHTTPSConnectionPool,
        }

    def _new_pool(self, scheme, host, port, request_context=None):
        context = (
            self.connection_pool_kw.copy()
            if request_context is None
            else request_context.copy()
        )
        context["gambit_pinned_ips"] = self._gambit_pinned_ips
        return super()._new_pool(scheme, host, port, context)


class _PinnedAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, pinned_ips, **kwargs):
        self._pinned_ips = tuple(pinned_ips)
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = _PinnedPoolManager(
            self._pinned_ips,
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )


def _request_pinned(method, url, *, headers, timeout, ips, **kwargs):
    """Send one request, dialing ``ips`` instead of resolving ``url`` again.

    ``trust_env`` stays false so environment proxies are not applied on
    top of the pin. The CA bundle is copied in explicitly; see
    :func:`_with_env_ca_bundle`.
    """
    session = requests.Session()
    session.trust_env = False
    adapter = _PinnedAdapter(ips)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    send_kwargs = _with_env_ca_bundle(kwargs)
    try:
        return session.request(
            method, url, headers=headers, timeout=timeout, **send_kwargs
        )
    finally:
        session.close()


def _close_quietly(response) -> None:
    closer = getattr(response, "close", None)
    if not callable(closer):
        return
    try:
        closer()
    except Exception:
        return


def _buffer_limited(response, limit: int) -> None:
    if not callable(getattr(response, "iter_content", None)):
        return
    try:
        data = read_limited(response, limit)
    except Exception:
        return
    try:
        response._content = data
        response._content_consumed = True
    except Exception:
        return
    _close_quietly(response)


__all__ = [
    "MAX_BODY",
    "MAX_REDIRECTS",
    "TIMEOUT",
    "USER_AGENT",
    "annotate_findings",
    "clear_scheme_cache",
    "get",
    "get_for_host",
    "options",
    "options_for_host",
    "preferred_port",
    "preferred_scheme",
    "read_limited",
    "request",
    "set_preferred_port",
    "set_preferred_scheme",
    "set_tls_verification",
    "tls_verification_enabled",
    "url_authority",
]
