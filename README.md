# GAMBIT

**A small, readable recon-and-triage tool for the first hour of a web pentest.**

Every web pentest starts with the same repetitive opening moves: look up the DNS, check the headers, see what's exposed, work out what stack you're facing. GAMBIT automates that first hour and, instead of dumping raw output, **ranks what it finds** so you know where to dig first.

> **Status:** GAMBIT is in early development. The checklist under [Roadmap](#roadmap) shows what works today. Anything unchecked is planned, not shipped.

---

## What the name means

Each letter is a stage in the pipeline and a module in the codebase:

| Letter | Stage | What it does |
|---|---|---|
| **G** | **Gather** | Subdomain discovery (DNS, certificate transparency) and dangling-CNAME takeover checks |
| **A** | **Analyze** | Technology fingerprinting from headers, cookies, and responses |
| **M** | **Map** | Light check of common ports on discovered hosts |
| **B** | **Baseline** | Security hygiene: HTTP headers, TLS, CORS, enabled HTTP methods |
| **I** | **Inspect** | Exposed-file checks (`/.git/HEAD`, `/.env`, `robots.txt`, directory listing) |
| **T** | **Triage** | Rank everything into a short report with a suggested next step for each finding |

## What it is, and what it isn't

GAMBIT is a **first-look tool**. It answers "what am I looking at, and where should I dig first?"

It is **not** an exploitation framework. It does not brute-force, fuzz, or exploit anything, and it never will. For that, use Burp Suite, ffuf, or nuclei. GAMBIT only makes DNS queries and ordinary HTTP requests, and it reports what it finds without touching it.

## Example output (target design)

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

- Asks you to confirm you have authorization before it runs
- Rate-limited by default
- Honest `User-Agent` string that identifies the tool
- Read-only: it never writes to, modifies, or claims anything on a target

The authors accept no responsibility for misuse.

## Design

Each stage is a module with one job. A module exposes a single `run(target)` function that returns a list of findings:

```python
# Planned interface; may change as the project develops
def run(target: str) -> list[Finding]:
    ...
```

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

- [ ] Finding data model and module interface
- [ ] **Gather:** DNS records and certificate-transparency subdomains
- [ ] **Gather:** dangling-CNAME takeover check (fingerprints in a JSON file)
- [ ] **Analyze:** technology fingerprinting
- [ ] **Baseline:** security headers and TLS checks
- [ ] **Baseline:** CORS and HTTP methods
- [ ] **Inspect:** exposed-file checks
- [ ] **Map:** common-port check
- [ ] **Triage:** severity ranking and Markdown/JSON export
- [ ] Tests and CI
- [ ] First tagged release

## Prior art

GAMBIT is not trying to replace these. They are more complete and worth using:

- [reconFTW](https://github.com/six2dez/reconftw) and [Osmedeus](https://github.com/j3ssie/osmedeus): full recon automation frameworks
- [nuclei](https://github.com/projectdiscovery/nuclei): template-based vulnerability scanning
- [subjack](https://github.com/haccer/subjack) and [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz): subdomain takeover tooling and the community reference for fingerprints

GAMBIT's niche is being **small and readable**: a few modules you can understand in an afternoon, with a ranked report aimed at people learning how a pentest starts.

## License

MIT (see `LICENSE`).

---

*Built by [Kamal Choubey](https://github.com/Phantom9869), a CS student learning security by building tools. It grows out of my earlier [netrecon](https://github.com/Phantom9869/netrecon) project.*
