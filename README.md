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

**Every action is HMAC-chained and audited. Every outbound request is scope-checked, including explicit exclusions. No active scanning. No auth bypasses. Memory use stays bounded even against very large targets.**

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
| Hashcat Rule Export | Turns mutation logic into a `.rule` file usable against *any* base wordlist via `hashcat -r` |
| Policy Filtering | Filters output to comply with detected password policy, inline during generation |
| HMAC Audit Chain | Every action cryptographically logged with a locally-generated, non-public signing key |
| Scope Enforcement | Blocks actions on unauthorized targets; explicit `exclude` rules always win |
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

---

## Output Files

```
outputs/
├── wordsmith_<target>_<timestamp>_full.txt      ← Complete sorted wordlist
├── wordsmith_<target>_<timestamp>_top1000.txt   ← Top 1000 by score
├── wordsmith_<target>_<timestamp>_names.txt     ← Name-based only
├── wordsmith_<target>_<timestamp>.rule          ← Hashcat rule file (--export-rules / --rules-only)
└── wordsmith_<target>_<timestamp>_seeds.txt     ← Companion seed words for the rule file
```

---

## CLI Reference

```
wordsmith [options]

  --domain DOMAIN                Target domain
  --company NAME                 Company name (if no domain)
  --scope FILE                   scope.yaml path (default: scope.yaml)
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
│   ├── state.py              ← Session state
│   ├── osint.py              ← OSINT collector
│   ├── scraper.py            ← Website crawler
│   ├── mutator.py            ← Mutation engine (13 strategies, streaming)
│   ├── scoring.py            ← Shared likelihood-scoring heuristic
│   ├── streaming.py          ← Bounded top-K accumulator
│   ├── rules.py              ← Hashcat rule-file exporter
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
├── tests/                    ← pytest suite (mutator, scope, audit, generator, rules, streaming)
├── .github/workflows/ci.yml  ← GitHub Actions: pytest across Python 3.10–3.12
└── outputs/                  ← Generated wordlists, reports, rule files
```

---

## Testing

```bash
pip install -r requirements-dev.txt
pytest -q
```

The suite covers mutation strategies and the bounded/streaming accumulator, scope include/exclude enforcement, HMAC audit-chain signing and tamper detection, wordlist scoring/size-limiting, and hashcat rule syntax + faithfulness (that emitted rules actually reproduce what the corresponding mutator strategy produces). Network-dependent OSINT/scraper code is intentionally out of scope for this suite — it isn't mocked yet.

---

## Audit Log Verification

Every action wordsmith takes is HMAC-SHA256 chained:

```bash
python3 wordsmith.py --verify-log SESSION_ID
```

The chain is signed with a key generated on first use and stored locally at `~/.wordsmith/audit/.hmac_key` (created with owner-only permissions where the OS supports it) — never hardcoded in source. This makes the log tamper-evident against post-hoc edits to the file on disk; it isn't a substitute for OS-level access control, and verifying a log on a different machine requires securely transferring that key file too, the same caveat that applies to any locally-anchored audit trail.

Logs themselves are stored in `~/.wordsmith/audit/<session_id>.log`.

---

*wordsmith is for authorized security engagements only. The author accepts no liability for misuse.*

*Always obtain written authorization before running wordsmith against any target. Unauthorized use is illegal.*
