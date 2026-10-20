"""Baseline: check TLS certificate validity and protocol version.

Standard library only (``ssl`` + ``socket``). The pure :func:`evaluate`
function does the date/version maths on a certificate dict like the one
``ssl.SSLSocket.getpeercert()`` returns, so tests never need a network.
``run`` performs a single verified handshake; a certificate that fails
verification (hostname mismatch, self-signed, ...) is reported as INFO
evidence rather than a vulnerability claim, and its details are still
collected over an unverified handshake for the expiry/version checks.
"""

import socket
import ssl
from collections.abc import Mapping
from datetime import date, datetime, time, timezone

from gambit.http import TIMEOUT, USER_AGENT
from gambit.models import Finding, Severity

__all__ = [
    "USER_AGENT",
    "TIMEOUT",
    "EXPIRY_WARNING_DAYS",
    "MINIMUM_TLS",
    "evaluate",
    "check_tls",
    "evaluate_tls",
    "parse_cert_datetime",
    "days_until_expiry",
    "run",
]

EXPIRY_WARNING_DAYS = 30
MINIMUM_TLS = (1, 2)  # TLS 1.2

# Protocol label -> comparable (major, minor); anything below MINIMUM_TLS
# is flagged. SSLv2/SSLv3 predate TLS 1.0, so they sort below (1, 0) --
# encoding them as (2, 0)/(3, 0) would rank them *above* TLS 1.2.
_PROTOCOL_VERSIONS = {
    "sslv2": (0, 2),
    "sslv3": (0, 3),
    "tlsv1": (1, 0),
    "tlsv1.0": (1, 0),
    "tlsv1.1": (1, 1),
    "tlsv1.2": (1, 2),
    "tlsv1.3": (1, 3),
}


def parse_cert_datetime(value) -> datetime | None:
    """Parse a certificate date/time into an aware UTC datetime.

    Accepts the ``getpeercert()`` string format (``'Oct 21 12:00:00 2026
    GMT'``), ISO strings, ``datetime``/``date`` objects, and POSIX
    timestamps. Returns ``None`` when the value cannot be understood.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime.combine(value, time.min, tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(text), tz=timezone.utc)
    except Exception:
        pass
    # Normalise the double space cert dates use before single-digit days.
    normalized = " ".join(text.replace("GMT", "UTC").split())
    for fmt in (
        "%b %d %H:%M:%S %Y %Z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            parsed = datetime.strptime(normalized, fmt)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _cert_value(cert: Mapping, *names: str):
    for name in names:
        if name in cert and cert[name] not in (None, ""):
            return cert[name]
        # getpeercert() keys are exact, but be forgiving about casing.
        for key, value in cert.items():
            if str(key).lower() == name.lower() and value not in (None, ""):
                return value
    return None


def days_until_expiry(cert, now: datetime | None = None) -> int | None:
    """Whole days until the certificate expires, or ``None`` if unknown.

    Negative when the certificate has already expired.
    """
    expiry = parse_cert_datetime(
        _cert_value(cert, "notAfter", "not_after", "expires", "expiry", "expire")
        if isinstance(cert, Mapping)
        else None
    )
    if expiry is None:
        return None
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    delta = expiry - now
    # timedelta.days floors, which is what "days left" means for negatives too.
    return delta.days


def _protocol_tuple(protocol) -> tuple[int, int] | None:
    if protocol is None:
        return None
    # ssl.TLSVersion members and plain numbers (e.g. TLSVersion.TLSv1_2).
    value = getattr(protocol, "value", protocol)
    numeric = {
        0x0300: (0, 3),  # SSLv3 wire version; predates TLS 1.0, see above
        0x0301: (1, 0),
        0x0302: (1, 1),
        0x0303: (1, 2),
        0x0304: (1, 3),
        769: (1, 0),
        770: (1, 1),
        771: (1, 2),
        772: (1, 3),
    }
    if isinstance(value, int) and value in numeric:
        return numeric[value]
    text = str(protocol).strip().lower().replace(" ", "").replace("_", "")
    text = text.removeprefix("ssl.tlsversion.")
    if text in _PROTOCOL_VERSIONS:
        return _PROTOCOL_VERSIONS[text]
    # Fall back to spotting a "1.x" version number in the label.
    if "tls" in text:
        for minor in (0, 1, 2, 3):
            if f"1.{minor}" in text:
                return (1, minor)
    return None


def evaluate(
    host,
    cert=None,
    protocol_version=None,
    *,
    now: datetime | None = None,
    hostname_mismatch: bool = False,
    self_signed: bool = False,
) -> list[Finding]:
    """Evaluate a certificate dict and protocol version. No network access.

    Canonical call: ``evaluate(host, cert, protocol_version)`` where
    ``cert`` is a ``getpeercert()``-style mapping. The certificate may
    instead carry its protocol under a ``protocol``/``version`` key, and
    ``evaluate(cert, protocol_version)`` (no host) is also accepted.
    A healthy certificate on TLS 1.2+ yields no findings.
    """
    # evaluate(cert, protocol): shift when the first argument is the cert.
    if isinstance(host, Mapping):
        if isinstance(cert, (str, int)) and protocol_version is None:
            protocol_version = cert
        cert = host
        host = ""

    cert = cert if isinstance(cert, Mapping) else {}
    if protocol_version is None and cert:
        protocol_version = _cert_value(cert, "protocol", "tls_version", "version")
    if cert and _cert_value(cert, "self_signed", "self-signed"):
        self_signed = True
    if cert and _cert_value(cert, "hostname_mismatch", "hostname-mismatch"):
        hostname_mismatch = True

    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    findings: list[Finding] = []

    def add(severity, title, evidence, why, next_step):
        findings.append(
            Finding(
                severity=severity,
                host=host,
                title=title,
                evidence=evidence,
                why=why,
                next_step=next_step,
            )
        )

    if not cert:
        add(
            Severity.INFO,
            "No TLS certificate information available",
            "No certificate was presented or it could not be read",
            "Without certificate details, expiry and issuer checks cannot run.",
            "Check whether the site serves HTTPS on port 443 at all.",
        )
    else:
        expiry = parse_cert_datetime(
            _cert_value(cert, "notAfter", "not_after", "expires", "expiry", "expire")
        )
        not_before = parse_cert_datetime(
            _cert_value(cert, "notBefore", "not_before", "issued", "valid_from")
        )
        expiry_text = expiry.strftime("%Y-%m-%d") if expiry else "unknown date"
        if expiry is not None and expiry <= now:
            add(
                Severity.HIGH,
                "TLS certificate expired",
                f"Certificate expired on {expiry_text}",
                "An expired certificate breaks the trust and encryption "
                "guarantees of HTTPS and trains users to click through "
                "browser warnings.",
                "Renew the certificate and check why automated renewal failed.",
            )
        elif expiry is not None:
            remaining = (expiry - now).days
            if remaining < EXPIRY_WARNING_DAYS:
                add(
                    Severity.MED,
                    "TLS certificate expires soon",
                    f"Certificate expires on {expiry_text} ({remaining} days remaining)",
                    "A certificate about to expire risks an outage and "
                    "browser warnings if renewal is not automated.",
                    "Renew the certificate now and verify automated renewal works.",
                )
        if not_before is not None and not_before > now:
            add(
                Severity.HIGH,
                "TLS certificate not yet valid",
                f"Certificate is not valid before {not_before.strftime('%Y-%m-%d')}",
                "Browsers will reject a certificate before its validity "
                "period starts, just as they reject an expired one.",
                "Check the server clock and reissue the certificate if needed.",
            )

    protocol = _protocol_tuple(protocol_version)
    if protocol is not None and protocol < MINIMUM_TLS:
        add(
            Severity.HIGH,
            f"Outdated TLS protocol version ({protocol_version})",
            f"Negotiated protocol: {protocol_version} (minimum expected: TLS 1.2)",
            "TLS versions below 1.2 have known weaknesses and are "
            "deprecated; modern browsers and clients may refuse them.",
            "Disable SSL/TLS versions below 1.2 in the server configuration.",
        )

    if hostname_mismatch:
        add(
            Severity.INFO,
            "TLS certificate hostname mismatch",
            "The certificate does not match the requested hostname (verification evidence only)",
            "Browsers will warn users, but this is reported as evidence "
            "rather than a confirmed exploitable weakness.",
            "Confirm the certificate's SANs cover this hostname and renew "
            "or reissue it if they do not.",
        )
    if self_signed:
        add(
            Severity.INFO,
            "Self-signed TLS certificate",
            "The certificate appears to be self-signed (verification evidence only)",
            "A self-signed certificate is not trusted by browsers, but "
            "this is reported as evidence rather than a confirmed "
            "exploitable weakness.",
            "Replace it with a certificate from a trusted CA if this "
            "host is meant to be publicly trusted.",
        )

    return findings


# Aliases mirroring the naming used by the other Baseline modules.
check_tls = evaluate
evaluate_tls = evaluate


def _split_host_port(target: str) -> tuple[str, int]:
    from gambit.pipeline import split_host_port

    name, port = split_host_port(target)
    return name, port if port is not None else 443


def _handshake(hostname: str, port: int, context: ssl.SSLContext):
    with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            return tls_sock.getpeercert(), tls_sock.version()


def _unverified_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def run(target: str) -> list[Finding]:
    """Check the target's TLS certificate and protocol over one handshake."""
    hostname, port = _split_host_port(target)
    try:
        cert, protocol = _handshake(hostname, port, ssl.create_default_context())
    except ssl.SSLCertVerificationError as exc:
        message = str(exc).lower()
        hostname_mismatch = "hostname" in message or "doesn't match" in message or "does not match" in message
        self_signed = "self-signed" in message or "self signed" in message
        # Still collect cert details without verification for expiry/version.
        try:
            cert, protocol = _handshake(
                hostname, port, _unverified_context()
            )
        except Exception:
            return [
                Finding(
                    severity=Severity.INFO,
                    host=target,
                    title="TLS certificate verification failed",
                    evidence=str(exc),
                    why="The certificate could not be verified, so the TLS check could not complete.",
                    next_step="Inspect the certificate chain, hostname coverage, and issuer manually.",
                )
            ]
        findings = evaluate(
            target,
            cert,
            protocol,
            hostname_mismatch=hostname_mismatch,
            self_signed=self_signed,
        )
        if not hostname_mismatch and not self_signed:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    host=target,
                    title="TLS certificate verification failed",
                    evidence=str(exc),
                    why="The certificate chain could not be verified by a trusted CA.",
                    next_step="Inspect the certificate chain and issuer manually.",
                )
            )
        return findings
    except (OSError, ssl.SSLError) as exc:
        return [
            Finding(
                severity=Severity.INFO,
                host=target,
                title="Could not check TLS",
                evidence=str(exc),
                why="The TLS check could not run.",
                next_step="Check the hostname, and whether the site serves HTTPS on port 443.",
            )
        ]
    return evaluate(target, cert, protocol)
