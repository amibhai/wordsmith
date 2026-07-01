# wordsmith

**OSINT-seeded intelligent wordlist generator for authorized password auditing engagements.**

![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/github/license/amibhai/wordsmith?style=flat-square)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)

Made by अमी — same DNA as [wifi_down](https://github.com/amibhai/wifi_down).

---

## What it does

wordsmith passively collects public intelligence about a target organization (WHOIS, DNS, certificates, GitHub, website), then applies 13 configurable mutation strategies to generate a likelihood-scored, policy-aware wordlist tailored to that specific target.

**Every action is HMAC-chained and audited. Every outbound request is scope-checked. No active scanning. No auth bypasses.**

---

## Legal

**Use only on systems you own or have written permission to test.**  
Unauthorized access is a criminal offence under CFAA, IT Act 2000, and similar laws worldwide.  
Create `scope.yaml` before targeting anything.

---

## Quick Start

```bash
# Install dependencies
bash install.sh

# Check all dependencies
python3 wordsmith.py --preflight

# Create scope file (required)
python3 wordsmith.py --scope-wizard

# Interactive mode
python3 wordsmith.py

# Fully automated pipeline
python3 wordsmith.py --auto --domain example.com --scope scope.yaml

# Resume a previous session
python3 wordsmith.py --resume SESSION_ID

# Generate report for a session
python3 wordsmith.py --report SESSION_ID --format all
```

---

## Features

| Feature | Description |
|---------|-------------|
| OSINT Collection | WHOIS, DNS, crt.sh, GitHub, Reddit, HackerNews |
| Website Scraper | Crawls target site, extracts meaningful words |
| 13 Mutation Strategies | Case, leet, years, symbols, numbers, combinator, walks, names, domain, patterns, CMS defaults, temporal, location |
| Likelihood Scoring | Sorts candidates by probability for that specific target |
| Policy Filtering | Filters output to comply with detected password policy |
| HMAC Audit Chain | Every action cryptographically logged |
| Scope Enforcement | Blocks all actions on unauthorized targets |
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

---

## Output Files

```
outputs/
├── wordsmith_<target>_<timestamp>_full.txt      ← Complete sorted wordlist
├── wordsmith_<target>_<timestamp>_top1000.txt   ← Top 1000 by score
└── wordsmith_<target>_<timestamp>_names.txt     ← Name-based only
```

---

## CLI Reference

```
wordsmith [options]

  --domain DOMAIN         Target domain
  --company NAME          Company name (if no domain)
  --scope FILE            scope.yaml path (default: scope.yaml)
  --strategies 1,2,3      Enable only these strategies
  --max-size MB           Max wordlist size in MB (default 100)
  --max-words N           Max word count (default 5M)
  --policy-min N          Min password length
  --policy-max N          Max password length
  --no-scrape             Skip website scraping
  --no-osint              Skip OSINT collection
  --seeds FILE            Additional seed words file
  --output DIR            Output directory
  --format json|md|all    Report format
  --auto                  Fully automatic mode
  --resume SESSION_ID     Resume previous session
  --preflight             Run dependency check
  --scope-wizard          Create scope.yaml interactively
  --verify-log SID        Verify HMAC audit log
  --lang en|hi            Interface language
  -v, --verbose           Verbose output
  -q, --quiet             Minimal output
```

---

## Directory Structure

```
wordsmith/
├── wordsmith.py              ← Entry point
├── install.sh
├── requirements.txt
├── scope.yaml.example
├── modules/
│   ├── audit.py              ← HMAC-chained audit log
│   ├── banner.py             ← Amber/gold TUI banner
│   ├── preflight.py          ← Dependency checker
│   ├── scope.py              ← Scope enforcement
│   ├── state.py              ← Session state
│   ├── osint.py              ← OSINT collector
│   ├── scraper.py            ← Website crawler
│   ├── mutator.py            ← Mutation engine (13 strategies)
│   ├── analyzer.py           ← Password policy detector
│   ├── generator.py          ← Wordlist assembler + scorer
│   ├── report.py             ← JSON/Markdown report generator
│   └── i18n.py               ← Localization
├── data/
│   ├── common_passwords.txt
│   ├── leet_map.json
│   ├── suffixes.json
│   ├── patterns.json
│   └── keyboard_walks.txt
├── locale/
│   ├── en.json
│   └── hi.json
└── outputs/                  ← Generated wordlists
```

---

## Audit Log Verification

Every action wordsmith takes is HMAC-SHA256 chained:

```bash
python3 wordsmith.py --verify-log SESSION_ID
```

Logs are stored in `~/.wordsmith/audit/<session_id>.log`.

---

*wordsmith is for authorized security engagements only. The author accepts no liability for misuse.*

*Always obtain written authorization before running wordsmith against any target. Unauthorized use is illegal.*
