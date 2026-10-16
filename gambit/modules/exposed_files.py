"""Inspect: look for commonly exposed files with a single GET request each."""

import re
import time
from dataclasses import dataclass
from typing import Callable, Optional

import requests

from gambit.models import Finding, Severity

USER_AGENT = (
    "GAMBIT/0.1 (+https://github.com/Phantom9869/Gambit; authorized testing only)"
)
TIMEOUT = 10  # seconds
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
    for check in CHECKS:
        url = f"https://{target}{check.path}"
        try:
            with requests.get(
                url,
                headers={"User-Agent": USER_AGENT},
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
        time.sleep(DELAY)
    return findings
