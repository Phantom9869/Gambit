"""Inspect: look for commonly exposed files with a single GET request each."""

import re
import time
from dataclasses import dataclass
from typing import Callable, Optional

import requests

from gambit.http import TIMEOUT, USER_AGENT, get_for_host
from gambit.models import Finding, Severity

# Re-exported for backwards compatibility; canonical values live in gambit.http.
__all__ = ["CHECKS", "Check", "DELAY", "MAX_BYTES", "TIMEOUT", "USER_AGENT", "evaluate", "run"]

MAX_BYTES = 512  # enough to recognize a file; never download more
DELAY = 0.5  # seconds between requests, so we stay polite


def _is_git_head(body: str) -> bool:
    """A real .git/HEAD is either 'ref: refs/...' or a bare 40-char commit hash."""
    return body.startswith("ref: refs/") or re.fullmatch(r"[0-9a-f]{40}\s*", body) is not None


def _is_env_file(body: str) -> bool:
    """KEY=value lines, and not an HTML page that happens to contain one."""
    if "<html" in body.lower():
        return False
    return re.search(r"^[A-Z][A-Z0-9_]*=", body, re.MULTILINE) is not None


def _is_robots_txt(body: str) -> bool:
    return "user-agent:" in body.lower() and "<html" not in body.lower()


def _is_git_config(body: str) -> bool:
    """A real .git/config has a [core] section, and is not an HTML page."""
    if "<html" in body.lower():
        return False
    return re.search(r"^\[core\]", body, re.MULTILINE) is not None


def _is_ds_store(body: str) -> bool:
    """A real .DS_Store starts with four bytes then the 'Bud1' magic.

    Those leading bytes survive the lossy UTF-8 decode in run() as control
    characters, so the magic still sits at offset 4. Accepting it at offset
    0 too keeps the matcher usable on a body that lost its leading bytes.
    """
    return body.startswith("Bud1") or body[4:8] == "Bud1"


def _is_directory_listing(body: str) -> bool:
    """Apache/nginx/lighttpd autoindex pages title themselves 'Index of /...'."""
    lowered = body.lower()
    if "<title>index of /" not in lowered:
        return False
    return "<h1>index of /" in lowered or "parent directory" in lowered


@dataclass(frozen=True)
class Check:
    path: str
    severity: Severity
    matches: Callable[[str], bool]
    title: str
    why: str
    next_step: str


CHECKS = [
    Check(
        path="/.git/HEAD",
        severity=Severity.HIGH,
        matches=_is_git_head,
        title="Git repository exposed (/.git/HEAD)",
        why="The .git directory is publicly readable, so source code and history may be recoverable.",
        next_step="Confirm manually and check commit history for credentials. Report it; do not mirror the repo.",
    ),
    Check(
        path="/.env",
        severity=Severity.HIGH,
        matches=_is_env_file,
        title="Environment file exposed (/.env)",
        why="A .env file usually holds secrets such as API keys and database passwords.",
        next_step="Confirm the file is real, then report it right away. Do not use any credentials it contains.",
    ),
    Check(
        path="/robots.txt",
        severity=Severity.INFO,
        matches=_is_robots_txt,
        title="robots.txt present",
        why="Disallow rules often point at admin panels and other areas the owner hoped to hide.",
        next_step="Read the Disallow entries and note any paths worth a closer look.",
    ),
    Check(
        path="/.git/config",
        severity=Severity.HIGH,
        matches=_is_git_config,
        title="Git config exposed (/.git/config)",
        why="A readable .git/config confirms the .git directory is exposed and may reveal the origin remote URL. Source code and history may be recoverable.",
        next_step="Confirm manually and check commit history for credentials. Report it; do not mirror the repo.",
    ),
    Check(
        path="/.DS_Store",
        severity=Severity.LOW,
        matches=_is_ds_store,
        title=".DS_Store file exposed (/.DS_Store)",
        why="A .DS_Store file can disclose directory and file names the owner did not intend to publish.",
        next_step="Note any filenames it reveals and check whether those paths are also reachable.",
    ),
] + [
    Check(
        path=directory,
        severity=Severity.LOW,
        matches=_is_directory_listing,
        title=f"Directory listing enabled ({directory})",
        why="The server lists every file in this directory, disclosing filenames and structure that may include backups, uploads, or other sensitive files.",
        next_step="Confirm manually, note any sensitive filenames, and recommend disabling autoindex/directory listing.",
    )
    for directory in ("/uploads/", "/files/", "/images/", "/backup/")
]


def evaluate(
    host: str, check: Check, status_code: int, body: str
) -> Optional[Finding]:
    """Decide whether a response counts as a finding. No network access."""
    if status_code != 200 or not check.matches(body):
        return None
    return Finding(
        severity=check.severity,
        host=host,
        title=check.title,
        # Deliberately no file contents here: a real .env would leak secrets.
        evidence=f"GET {check.path} returned HTTP 200 with a matching signature",
        why=check.why,
        next_step=check.next_step,
    )


def run(target: str) -> list[Finding]:
    """Request each path once and report the ones that look exposed."""
    findings = []
    for index, check in enumerate(CHECKS):
        if index:
            time.sleep(DELAY)  # between requests only, never after the last
        try:
            with get_for_host(
                target,
                check.path,
                timeout=TIMEOUT,
                allow_redirects=False,
                stream=True,
            ) as response:
                chunk = next(response.iter_content(chunk_size=MAX_BYTES), b"")
                body = chunk.decode("utf-8", errors="replace")
                status = response.status_code
        except requests.RequestException:
            # Connection problems are reported by the headers module.
            continue

        finding = evaluate(target, check, status, body)
        if finding:
            findings.append(finding)
    return findings
