"""Map: probe a small, polite set of common TCP ports with stdlib sockets.

Only a bare TCP connect is attempted -- no banner grab and no payload --
so an "open" result means nothing more than that something accepted the
connection. Severity is a pure function of the port number, which keeps
the interesting logic testable without any network access.
"""

from gambit.models import Finding, Severity

__all__ = [
    "ALT_WEB_PORTS",
    "CONNECT_TIMEOUT",
    "DATABASE_PORTS",
    "PORTS",
    "PORT_SERVICES",
    "TIMEOUT",
    "WEB_PORTS",
    "evaluate",
    "run",
    "service_for_port",
    "severity_for",
    "severity_for_port",
]

TIMEOUT = 1.0  # seconds per connect; short so a filtered port stays cheap
CONNECT_TIMEOUT = TIMEOUT

# port -> service commonly found there
PORT_SERVICES = {
    80: "HTTP",
    443: "HTTPS",
    3000: "HTTP-alt (often a dev/app server)",
    8000: "HTTP-alt",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
}

WEB_PORTS = (80, 443)
ALT_WEB_PORTS = (3000, 8000, 8080, 8443)
DATABASE_PORTS = (3306, 5432, 6379, 27017, 9200)

# The full polite list: standard + alternate web ports, then DB/admin ports.
PORTS = WEB_PORTS + ALT_WEB_PORTS + DATABASE_PORTS


def severity_for_port(port: int) -> Severity:
    """Severity for an open ``port``. Pure: no network, no I/O.

    Standard web ports are expected on a web host (INFO), alternate web
    ports often expose dev/admin surfaces (LOW), and database ports
    should never be internet-facing (MED). Unknown ports default to INFO.
    """
    if port in DATABASE_PORTS:
        return Severity.MED
    if port in ALT_WEB_PORTS:
        return Severity.LOW
    return Severity.INFO


# Short alias for the pure severity-mapping function.
severity_for = severity_for_port


def service_for_port(port: int) -> str:
    """Name of the service commonly found on ``port`` (or 'unknown')."""
    return PORT_SERVICES.get(port, "unknown")


def evaluate(host: str, port: int) -> Finding:
    """Build the finding for a port already known to be open. No network."""
    severity = severity_for_port(port)
    service = service_for_port(port)
    if port in DATABASE_PORTS:
        why = (
            f"{service} is a database/admin service that should never be "
            "internet-facing; anyone can attempt to connect to it."
        )
        next_step = (
            "Confirm manually whether the service requires authentication, "
            "then recommend firewalling it so only the application can reach it."
        )
    elif port in ALT_WEB_PORTS:
        why = (
            f"An alternate web port ({service}) is open; such ports often "
            "expose development, staging, or admin surfaces with weaker controls."
        )
        next_step = "Visit the port manually and identify what is served there."
    else:
        why = f"Port {port} ({service}) is open, as expected for a web host."
        next_step = "Note the service in the host inventory; no action needed on its own."
    return Finding(
        severity=severity,
        host=host,
        title=f"Open port {port} ({service})",
        evidence=f"TCP connection to {host}:{port} succeeded",
        why=why,
        next_step=next_step,
    )


def run(target: str) -> list[Finding]:
    """Try one TCP connect per port in PORTS and report the open ones.

    An explicit port on ``target`` (``example.com:9090``) is probed too,
    in addition to :data:`PORTS`. DNS for each connect is bounded by
    :data:`TIMEOUT`. A port outside 1–65535 is not probed: the platform
    resolver would otherwise truncate it into a different port.
    """
    from gambit.net import connect
    from gambit.pipeline import split_host_port

    hostname, explicit_port = split_host_port(target)
    host = hostname or target
    ports = list(PORTS)
    if explicit_port and explicit_port not in ports:
        ports.append(explicit_port)
    findings = []
    for port in ports:
        try:
            with connect(host, port, TIMEOUT):
                pass  # connected == open; send nothing, read nothing
        except OSError:
            continue  # refused, filtered, timed out, or unresolvable
        findings.append(evaluate(host, port))
    return findings
