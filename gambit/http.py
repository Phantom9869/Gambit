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

Redirects are followed only when the next URL stays on the same host and
every resolved address is globally routable, and only up to
:data:`MAX_REDIRECTS` hops. Response bodies are streamed and capped at
:data:`MAX_BODY` bytes unless the caller is reading the stream itself.
"""

from urllib.parse import urljoin, urlsplit

import requests

from gambit.net import is_public_ip, resolve_ips

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
      whose resolved addresses are all public, and at most
      :data:`MAX_REDIRECTS` of them. A cross-host or private redirect is
      returned as the redirect response and is not fetched.
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

    current = url
    current_method = method
    hops = 0
    while True:
        response = requests.request(
            current_method, current, headers=merged, timeout=timeout, **kwargs
        )
        _stamp_redirect(response, hops, current)
        if not allow_redirects or hops >= MAX_REDIRECTS:
            break
        status = getattr(response, "status_code", 0) or 0
        location = _location_header(response)
        if status not in (301, 302, 303, 307, 308) or not location:
            break
        nxt = urljoin(current, location.strip())
        if not _redirect_is_safe(current, nxt, timeout):
            break
        _close_quietly(response)
        if status == 303:
            current_method = "GET"
        current = nxt
        hops += 1
    if not caller_streams:
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

    Only connection-level failures (:class:`requests.RequestException`)
    trigger the fallback; an HTTP error status is a real answer and is
    returned as-is. Raises the last exception if every scheme fails.
    """
    if path and not path.startswith("/"):
        path = "/" + path
    last_exc: Exception | None = None
    for scheme in _schemes_to_try(target):
        url = f"{scheme}://{url_authority(target, scheme)}{path}"
        try:
            response = request(method, url, **kwargs)
        except requests.RequestException as exc:
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


def _redirect_is_safe(current: str, nxt: str, timeout) -> bool:
    """Same host, http(s) only, and every resolved address globally routable."""
    new = urlsplit(nxt)
    old = urlsplit(current)
    if new.scheme not in ("http", "https") or not new.hostname:
        return False
    current_host = (old.hostname or "").lower().rstrip(".")
    next_host = new.hostname.lower().rstrip(".")
    if not current_host or current_host != next_host:
        return False
    try:
        ips = resolve_ips(next_host, _timeout_seconds(timeout))
    except Exception:
        return False
    return bool(ips) and all(is_public_ip(ip) for ip in ips)


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
    "url_authority",
]
