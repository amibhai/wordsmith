# wordsmith

**OSINT-seeded intelligent wordlist generator for authorized password auditing engagements.**

![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/github/license/amibhai/wordsmith?style=flat-square)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)
![CI](https://img.shields.io/github/actions/workflow/status/amibhai/wordsmith/ci.yml?style=flat-square&label=CI)

Made by अमी — same DNA as [wifi_down](https://github.com/amibhai/wifi_down).

---

## What it does

wordsmith passively collects public intelligence about a target organization (WHOIS, DNS, certificates, GitHub, website), then applies 13 configurable mutation strategies to generate a likelihood-scored, policy-aware wordlist tailored to that specific target — or, via hashcat rule export, turns that same target intelligence into a transformation you can run against a base wordlist you already have (rockyou, SecLists, ...) at native hashcat speed.

**Dual-use:** with `--defend` it flips red to blue — the same intelligence becomes a custom **banned-password list** (Microsoft Entra ID / Azure AD, Keycloak, `pam_pwquality`) plus an **exposure report** that shows the client exactly how guessable their org-specific passwords are, and what to harden. *wordsmith shows you how an attacker would build a wordlist for your org — then hands you the ban-list to stop them.*

**Every action is HMAC-chained and audited (tamper-evident against edits and trailing truncation). Every outbound request — including redirects and derived document URLs — is scope-checked, and explicit exclusions always win. No active scanning. No auth bypasses. Memory use stays bounded even against very large targets.**

---

## Legal

**Use only on systems you own or have written permission to test.**
Unauthorized access is a criminal offence under CFAA, IT Act 2000, and similar laws worldwide.
Create `scope.yaml` before targeting anything.

`scope.yaml` supports both `targets` (what's authorized) and `exclude` (what's carved out even if it would otherwise match — e.g. a shared mail server or a critical-infra host the client asked you to leave alone). Exclusions always win over a broader include. `--scope-wizard` prompts for both.

---

## Quick Start

```bash
# Install dependencies (Linux/macOS)
bash install.sh

# Check all dependencies
python3 wordsmith.py --preflight

# Create scope file (required)
python3 wordsmith.py --scope-wizard

# Interactive mode
python3 wordsmith.py

# Fully automated pipeline
python3 wordsmith.py --auto --domain example.com --scope scope.yaml

# Also export a hashcat rule file + seed words alongside the wordlist
python3 wordsmith.py --auto --domain example.com --scope scope.yaml --export-rules

# Rules + seeds only — skip full wordlist generation (fast path for big targets)
python3 wordsmith.py --auto --domain example.com --scope scope.yaml --rules-only

# Defensive mode: banned-password list + exposure report for the client (blue-team)
python3 wordsmith.py --auto --domain example.com --scope scope.yaml --defend

# Resume a previous session
python3 wordsmith.py --resume SESSION_ID

# Generate report for a session
python3 wordsmith.py --report SESSION_ID --format all
```

```powershell
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File install.ps1
python wordsmith.py --preflight
python wordsmith.py --scope-wizard
python wordsmith.py --auto --domain example.com --scope scope.yaml
```

---

## Features

| Feature | Description |
|---------|-------------|
| OSINT Collection | WHOIS, DNS, crt.sh, GitHub, Reddit, HackerNews |
| Website Scraper | Crawls target site, extracts meaningful words |
| 13 Mutation Strategies | Case, leet, years, symbols, numbers, combinator, walks, names, domain, patterns, CMS defaults, temporal, location |
| Likelihood Scoring | Sorts candidates by probability for that specific target |
| Bounded Streaming Pipeline | Memory stays flat regardless of seed-list size — a fixed-capacity top-K accumulator, not an unbounded in-RAM set |
| Hashcat Rule Export | Turns mutation logic into a valid `.rule` file usable against *any* base wordlist via `hashcat -r` |
| **Defensive Mode** | `--defend`: custom banned-password list (Entra ID / Azure AD, Keycloak, pwquality) + an exposure report for the client to harden with |
| Policy Filtering | Filters output to comply with detected password policy, inline during generation *and* over the final merge |
| HMAC Audit Chain | Every action cryptographically logged; chain continues across resume/report and detects edits **and trailing truncation** |
| Scope Enforcement | Blocks unauthorized targets on every request (redirects/derived URLs included); explicit `exclude` rules always win; `--auto` fails closed |
| Three Output Files | Full list, Top-1000, Name-based variants |
| Report Generation | JSON + Markdown engagement reports |
| Session Resume | Save and resume long-running sessions |
| Hindi / English UI | `--lang hi` for Hindi interface |

---

## Mutation Strategies

1. **Case variants** — lower, UPPER, Title, aLtErNaTiNg
2. **Leet speak** — p@55w0rd style substitutions
3. **Year suffix** — word2024, word@2024, word24
4. **Symbol append** — word!, word@, word#1
5. **Number append** — word1, word123, word007
6. **Word combinator** — acmecorp, AcmeCorp, acme_corp
7. **Keyboard walks** — qwerty, asdfgh mixed with seeds
8. **Name variants** — rahul, rsharma, rahul.sharma
9. **Domain variants** — acme, acmeadmin, acme2024
10. **Common patterns** — Word@Year, Word@123, Admin{word}
11. **CMS defaults** — wp-admin, cpanel, joomlaadmin
12. **Temporal patterns** — FY2024, Q12024, Jan2024
13. **Location variants** — delhi123, Delhi@123, mumbaiHQ

> **Wordlist vs. rules:** a few transforms exist only in the generated wordlist, not in the exported `.rule` file, because they have no faithful position-independent hashcat equivalent — specifically **alternating-case** (`aLtErNaTiNg`) and **single-position** leet (`p4ssword` with just one letter changed). The rule file emits the faithful subset (case ops, lower/title-cased affixes, and substitute-*all* leet). This is by design, not a gap.

Every candidate streams through a bounded top-K accumulator (`modules/streaming.py`) scored by `modules/scoring.py` — at most `--max-words` candidates are ever kept, and at most `--max-candidates-scanned` unique candidates are ever considered (a documented safety valve for very large targets), so peak memory stays predictable regardless of how many scraped words or employee names feed into the run.

---

## Hashcat Rule Export

Flat wordlists have a ceiling: they can only ever contain what you generated. Hashcat rules don't — a `.rule` file *transforms* every line of whatever base wordlist you point it at, so wordsmith's target intelligence (case patterns, leet substitutions, OSINT-derived years, org-specific suffixes) can be applied to rockyou, SecLists, or any dictionary you already have, at hashcat-native speed, without ever materializing millions of lines in Python.

```bash
# Export rules + seeds alongside a normal run
python3 wordsmith.py --auto --domain example.com --export-rules --rules-tier standard

# Or skip wordlist generation entirely and just get the rules (fast path)
python3 wordsmith.py --auto --domain example.com --rules-only --rules-tier exhaustive
```

This writes two files to `outputs/`:

- `wordsmith_<target>_<timestamp>.rule` — the hashcat rule file
- `wordsmith_<target>_<timestamp>_seeds.txt` — target-specific seed words (org name, domain, employee name parts, products, location)

Rules only transform existing lines — they can't invent target-specific words from nothing, which is why the seeds file exists. Pair them:

```bash
cat wordsmith_example_com_seeds.txt rockyou.txt > combined.txt
hashcat -a 0 -r wordsmith_example_com.rule combined.txt hash.txt
```

`--rules-tier` controls coverage: `basic` (case + top suffixes), `standard` (+ leet substitutions + OSINT year suffixes, default), or `exhaustive` (+ full suffix/pattern coverage, still capped to a reviewable line count).

Emitted rules are **valid hashcat syntax** — arguments are literal (`$!`, `$$`, `sa@`), not John-style backslash escapes. A test shells out to `hashcat --stdout` to confirm it when a hashcat binary is available.

---

## Defensive Mode (blue-team)

The same OSINT that builds an attacker's wordlist also tells a defender exactly where they're exposed. `--defend` turns one engagement's intelligence into two client deliverables:

```bash
# Produce a banned-password list + exposure report (all formats)
python3 wordsmith.py --auto --domain example.com --scope scope.yaml --defend

# Pick specific formats
python3 wordsmith.py --auto --domain example.com --defend --defend-format entra,keycloak
```

**1. A custom banned-password list**, rendered for the places a defender actually loads one:

- `..._banned_entra.txt` — base *terms* for a Microsoft **Entra ID / Azure AD Password Protection** custom banned list (Entra fuzzy-matches substrings, l33t and keyboard variants itself, so it wants stems, not full passwords).
- `..._banned_keycloak.txt` — full candidate passwords for an **exact-match blocklist** (Keycloak password blacklist, or similar).
- `..._banned_pwquality.dict` — a word list for **`pam_pwquality` / cracklib**.

**2. An exposure report** (`..._exposure.md` + `.json`): which public sources leak which base terms (provenance), how much of the org-specific candidate space is trivially weak, a weak-pattern breakdown, and prioritized, evidence-backed hardening recommendations. Figures are derived from wordsmith's own candidate generation and are clearly labeled as estimates over the org-specific candidate space — **never invented breach statistics**.

Everything in defensive mode is scope-checked and HMAC-audit-logged like the offensive path.

---

## Output Files

```
outputs/
├── wordsmith_<target>_<timestamp>_full.txt      ← Complete sorted wordlist
├── wordsmith_<target>_<timestamp>_top1000.txt   ← Top 1000 by score
├── wordsmith_<target>_<timestamp>_names.txt     ← Name-based only
├── wordsmith_<target>_<timestamp>.rule          ← Hashcat rule file (--export-rules / --rules-only)
├── wordsmith_<target>_<timestamp>_seeds.txt     ← Companion seed words for the rule file
├── wordsmith_<target>_<timestamp>_banned_entra.txt      ← Entra ID / Azure AD banned terms (--defend)
├── wordsmith_<target>_<timestamp>_banned_keycloak.txt   ← Exact-match blocklist (--defend)
├── wordsmith_<target>_<timestamp>_banned_pwquality.dict ← cracklib / pam_pwquality dict (--defend)
└── wordsmith_<target>_<timestamp>_exposure.md / .json   ← Exposure report (--defend)
```

---

## CLI Reference

```
wordsmith [options]

  --domain DOMAIN                Target domain
  --company NAME                 Company name (if no domain)
  --scope FILE                   scope.yaml path (default: scope.yaml)
  --no-scope-i-understand        Run --auto with no valid scope (DANGEROUS;
                                  disables scope/exclude enforcement)
  --strategies 1,2,3             Enable only these strategies
  --max-size MB                  Max wordlist size in MB (default 100)
  --max-words N                  Max word count (default 5M)
  --max-candidates-scanned N     Safety valve: stop after N unique candidates
                                  considered, even under --max-words (default
                                  20M, 0 = unlimited)
  --policy-min N                 Min password length
  --policy-max N                 Max password length
  --no-scrape                    Skip website scraping
  --no-osint                     Skip OSINT collection
  --seeds FILE                   Additional seed words file
  --output DIR                   Output directory
  --export-rules                 Also export hashcat .rule + seeds files
  --rules-only                   Skip wordlist generation, rules/seeds only
  --rules-tier TIER              basic|standard|exhaustive (default standard)
  --defend                       Defensive mode: banned-password list + report
  --defend-format FMT            entra,ad,keycloak,pwquality,all (default all)
  --format json|md|all           Report format
  --auto                         Fully automatic mode
  --resume SESSION_ID            Resume previous session
  --preflight                    Run dependency check
  --scope-wizard                 Create scope.yaml interactively
  --verify-log SID               Verify HMAC audit log
  --lang en|hi                   Interface language
  -v, --verbose                  Verbose output
  -q, --quiet                    Minimal output
```

---

## Directory Structure

```
wordsmith/
├── wordsmith.py              ← Entry point
├── install.sh                ← Linux/macOS installer
├── install.ps1                ← Windows PowerShell installer
├── requirements.txt
├── requirements-dev.txt      ← + pytest, for running the test suite
├── pytest.ini
├── scope.yaml.example
├── modules/
│   ├── audit.py              ← HMAC-chained audit log (locally-generated key)
│   ├── banner.py              ← Amber/gold TUI banner
│   ├── preflight.py          ← Dependency checker
│   ├── scope.py              ← Scope enforcement (includes + excludes)
│   ├── netutil.py            ← Scope-aware HTTP client (TLS, redirect re-check, SSRF guard)
│   ├── state.py              ← Session state
│   ├── osint.py              ← OSINT collector
│   ├── scraper.py            ← Website crawler
│   ├── mutator.py            ← Mutation engine (13 strategies, streaming)
│   ├── scoring.py            ← Shared likelihood-scoring heuristic
│   ├── policy.py             ← Shared password-policy predicate (mutator + generator)
│   ├── streaming.py          ← Bounded top-K accumulator
│   ├── rules.py              ← Hashcat rule-file exporter
│   ├── defense.py            ← Defensive mode: banned list + exposure report
│   ├── analyzer.py           ← Password policy detector
│   ├── generator.py          ← Wordlist assembler + writer
│   ├── report.py             ← JSON/Markdown report generator
│   └── i18n.py                ← Localization
├── data/
│   ├── common_passwords.txt
│   ├── leet_map.json
│   ├── suffixes.json
│   ├── patterns.json
│   └── keyboard_walks.txt
├── locale/
│   ├── en.json
│   └── hi.json
├── tests/                    ← pytest suite (mutator, scope, netutil, audit, generator, rules, defense, streaming, osint)
├── .github/workflows/ci.yml  ← GitHub Actions: pytest on Linux/Windows/macOS across Python 3.10–3.12
└── outputs/                  ← Generated wordlists, reports, rule files
```

---

## Testing

```bash
pip install -r requirements-dev.txt
pytest -q
```

The suite covers mutation strategies and the bounded/streaming accumulator, scope include/exclude enforcement (including expiry for IP/email and fail-closed on a malformed scope), the scope-aware HTTP client (off-scope redirect/host refusal, SSRF guard, size-capped download), HMAC audit-chain continuity + edit **and trailing-truncation** detection, scoring/policy filtering, hashcat rule validity + the faithful subset, and defensive-mode output. The network layer is exercised via httpx's `MockTransport` (no live calls); a `hashcat --stdout` check runs when a hashcat binary is present, and is skipped otherwise.

---

## Audit Log Verification

Every action wordsmith takes is HMAC-SHA256 chained:

```bash
python3 wordsmith.py --verify-log SESSION_ID
```

The chain is signed with a key generated on first use and stored locally at `~/.wordsmith/audit/.hmac_key` (created with owner-only permissions where the OS supports it) — never hardcoded in source. Each entry carries a monotonic sequence number and the previous entry's HMAC, and a small `~/.wordsmith/audit/<session_id>.head` anchor records the latest `(seq, hmac)`. Together these make the log tamper-evident against edits, reordering, mid-file deletion **and trailing truncation**. Reopening a session (resume, or generating a report for a past session) **continues** the chain rather than resetting it, so `--verify-log` stays green across the normal workflow.

Logs are stored in `~/.wordsmith/audit/<session_id>.log`.

---

## Security model & limitations

- **Audit chain is tamper-*evident*, not tamper-*proof*.** The signing key sits next to the logs (`~/.wordsmith/audit/`), so anyone who can read it can forge the chain — this defends against post-hoc edits by someone without the key, not against the operator. Verifying on another machine needs the key (and, for the truncation check, the `.head`) copied over; a missing key is reported as *"cannot verify"*, never as tampering.
- **Scope is enforced on every request to the target** — including redirect hops and derived document URLs — with TLS verification on and an SSRF guard that refuses private/loopback/link-local IPs. Fixed third-party APIs that wordsmith queries *about* the target (crt.sh, GitHub, HackerNews, Reddit) are host-allowlisted rather than scope-gated to the target's own domain.
- **`--auto` fails closed:** a missing or malformed scope file aborts the run unless you pass `--no-scope-i-understand`. Interactive mode warns but lets you proceed. `scope.yaml`'s `exclude` always wins over any broader include, and `restrictions` (`allowed_modules`, `max_wordlist_size_mb`) are enforced.
- **Defensive-mode figures are estimates** over the org-specific candidate space wordsmith itself generates — not measured breach statistics — and are labeled as such in the report.

---

*wordsmith is for authorized security engagements only. The author accepts no liability for misuse.*

*Always obtain written authorization before running wordsmith against any target. Unauthorized use is illegal.*
