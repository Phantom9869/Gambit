# GAMBIT

**A small, readable recon-and-triage tool for the first hour of a web pentest.**

Every web pentest starts with the same repetitive opening moves: look up the DNS, check the headers, see what's exposed, work out what stack you're facing. GAMBIT automates that first hour and, instead of dumping raw output, **ranks what it finds** so you know where to dig first.

> **Status:** All pipeline stages are implemented: Gather (DNS, certificate-transparency subdomains, and dangling-CNAME takeover checks), Analyze, Map, Baseline (headers, TLS, CORS, and HTTP methods), Inspect, and Triage (text, Markdown, and JSON reports). GAMBIT is still pre-release — there is no tagged release yet — and the checklist under [Roadmap](#roadmap) shows what remains.

---

## What the name means

Each letter is a stage in the pipeline and a module in the codebase:

| Letter | Stage | What it does |
|---|---|---|
| **G** | **Gather** | Subdomain discovery (DNS, certificate transparency) and dangling-CNAME takeover checks |
| **A** | **Analyze** | Technology fingerprinting from headers, cookies, and responses |
| **M** | **Map** | Light check of common ports on discovered hosts |
| **B** | **Baseline** | Security hygiene: HTTP headers, TLS, CORS, enabled HTTP methods |
| **I** | **Inspect** | Exposed-file checks (`/.git/HEAD`, `/.git/config`, `/.env`, `/.DS_Store`, `robots.txt`, directory listing) |
| **T** | **Triage** | Rank everything into a short report with a suggested next step for each finding |

## What it is, and what it isn't

GAMBIT is a **first-look tool**. It answers "what am I looking at, and where should I dig first?"

It is **not** an exploitation framework. It does not brute-force, fuzz, or exploit anything, and it never will. For that, use Burp Suite, ffuf, or nuclei. GAMBIT only makes DNS queries and ordinary HTTP requests, and it reports what it finds without touching it.

## Installation

GAMBIT requires Python 3.11 or later. From a clone of this repository:

```bash
python -m pip install .
```

For development (editable install plus `pytest`):

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

## Usage

```bash
gambit example.com
# equivalent:
python -m gambit example.com
```

GAMBIT first runs Gather for the target, then runs the per-host checks (Analyze, Baseline, Inspect, and Map) on the apex host and the subdomains it discovers, and finally ranks everything with Triage. Discovered hosts are de-duplicated and capped (25 by default; see `--max-hosts`) so a scan stays small, and hosts are checked one at a time with a short pause between them.

| Flag | Description |
|---|---|
| `--format text\|md\|json` | Report format: human-readable text (default), Markdown (`md`), or JSON (`json`). |
| `--json` | Print the report as JSON. Shortcut for `--format json`. |
| `-o FILE`, `--output FILE` | Write the report to `FILE` instead of standard output. |
| `--max-hosts N` | Maximum number of hosts to check, including the target itself (default: 25). |
| `--yes` | Skip the interactive authorization confirmation (see [Responsible use](#responsible-use)). Use only where you already have permission. |

For example, to save a Markdown report for at most 10 hosts without the confirmation prompt:

```bash
gambit example.com --yes --format md --max-hosts 10 -o report.md
```

## Example output

```
$ gambit example.com

[HIGH]  dev.example.com: /.git/HEAD is publicly accessible
        Why:  Source code and history may be recoverable.
        Next: Confirm manually; check for credentials in commit history.

[HIGH]  old.example.com: CNAME points to an unclaimed GitHub Pages site
        Why:  Subdomain takeover is likely possible.
        Next: Verify the fingerprint, then report it. Do not claim the resource.

[MED]   api.example.com: CORS reflects arbitrary Origin headers
        Why:  Cross-origin pages may be able to read authenticated responses.
        Next: Test whether credentials are allowed alongside the wildcard origin.

[INFO]  www.example.com: nginx 1.x with PHP (via X-Powered-By)
        Next: Look at PHP-specific issues and the version for known CVEs.
```

Reports can be exported as Markdown (for humans) or JSON (for pipelines).

## Responsible use

**Only run GAMBIT against systems you own or have explicit written permission to test.** Unauthorized scanning may be illegal in your jurisdiction.

Safeguards built into the design:

- Asks you to confirm you have authorization before it runs (skip with `--yes` only when you already have permission)
- Caps how many hosts a single scan checks (25 by default, `--max-hosts`)
- Rate-limited by default
- Honest `User-Agent` string that identifies the tool
- Read-only: it never writes to, modifies, or claims anything on a target

The authors accept no responsibility for misuse.

## Design

Each stage is a module with one job. A module exposes a single `run(target)` function that returns a list of findings:

```python
def run(target: str) -> list[Finding]:
    ...
```

Shared plumbing lives outside the stage modules: `gambit/http.py` provides the one honest `User-Agent`, timeout, and `get()` helper every HTTP module uses, and `gambit/pipeline.py` turns a target into a normalized, de-duplicated, capped host list and runs the per-host modules with failure isolation — one module crashing on one host becomes an INFO finding and never aborts the scan.

A finding is a small, consistent record:

```json
{
  "severity": "HIGH",
  "host": "dev.example.com",
  "title": "/.git/HEAD is publicly accessible",
  "evidence": "HTTP 200, body starts with 'ref: refs/heads/'",
  "why": "Source code and history may be recoverable.",
  "next_step": "Confirm manually; check for credentials in commit history."
}
```

Adding a check means adding one file. The Triage stage sorts every finding from every module by severity.

## Roadmap

- [x] Finding data model and module interface
- [x] **Gather:** DNS records and certificate-transparency subdomains
- [x] **Gather:** dangling-CNAME takeover check (fingerprints in a JSON file)
- [x] **Analyze:** technology fingerprinting
- [x] **Baseline:** security headers and TLS checks
- [x] **Baseline:** CORS and HTTP methods
- [x] **Inspect:** exposed-file checks
- [x] **Map:** common-port check
- [x] **Triage:** severity ranking and Markdown/JSON export
- [ ] Tests for every module
- [x] CI (pytest on Ubuntu and Windows, Python 3.11 and 3.12)
- [ ] First tagged release

## Prior art

GAMBIT is not trying to replace these. They are more complete and worth using:

- [reconFTW](https://github.com/six2dez/reconftw) and [Osmedeus](https://github.com/j3ssie/osmedeus): full recon automation frameworks
- [nuclei](https://github.com/projectdiscovery/nuclei): template-based vulnerability scanning
- [subjack](https://github.com/haccer/subjack) and [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz): subdomain takeover tooling and the community reference for fingerprints

The takeover fingerprints in `gambit/data/takeover_fingerprints.json` are seeded from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) — credit to EdOverflow and its contributors for maintaining that reference.

GAMBIT's niche is being **small and readable**: a few modules you can understand in an afternoon, with a ranked report aimed at people learning how a pentest starts.

## License

MIT (see `LICENSE`).

---

*Built by [Kamal Choubey](https://github.com/Phantom9869), a CS student learning security by building tools. It grows out of my earlier [netrecon](https://github.com/Phantom9869/netrecon) project.*
