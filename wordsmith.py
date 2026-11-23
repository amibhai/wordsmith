#!/usr/bin/env python3
"""
wordsmith — OSINT-seeded intelligent wordlist generator for authorized engagements.

Usage (interactive):
  python3 wordsmith.py

Usage (headless/automated):
  python3 wordsmith.py --auto --domain example.com --scope scope.yaml

Special commands:
  wordsmith --preflight              Run pre-flight dependency checker
  wordsmith --scope-wizard           Create scope.yaml interactively
  wordsmith --report SESSION_ID      Generate report (JSON + Markdown)
  wordsmith --verify-log SESSION_ID  Verify HMAC audit log integrity
  wordsmith --auto                   Fully automatic mode (OSINT→scrape→generate→report)
  wordsmith --lang en|hi             Override UI language
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from modules import i18n
from modules.banner import (
    C, print_banner, print_compact_header, print_menu,
    print_section, info, success, warn, error,
)
from modules.scope import ScopeManager, scope_wizard, DEFAULT_SCOPE_FILE, ScopeError
from modules.state import SessionManager, WordsmithSession
from modules.audit import get_logger, AuditLogger
from modules.preflight import run_preflight, run_preflight_with_autofix, SENTINEL_FILE

logger = logging.getLogger(__name__)


# ─── CLI argument parser ──────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wordsmith",
        description="OSINT-seeded intelligent wordlist generator — authorized engagements only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("--domain",      metavar="DOMAIN",  help="Target domain (e.g. example.com)")
    p.add_argument("--company",     metavar="NAME",    help="Company/organization name")
    p.add_argument("--scope",       metavar="FILE",    help="Path to scope.yaml", default="scope.yaml")
    p.add_argument("--no-scope-i-understand", action="store_true",
                   help="Run --auto even with no valid scope.yaml (DANGEROUS: "
                        "disables scope/exclude enforcement — authorized use only)")
    p.add_argument("--strategies",  metavar="1,2,3",   help="Enable only these strategy numbers")
    p.add_argument("--max-size",    metavar="MB",      type=float, default=100.0,
                   help="Max wordlist size in MB (default 100)")
    p.add_argument("--max-words",   metavar="N",       type=int, default=5_000_000,
                   help="Max word count (default 5M)")
    p.add_argument("--max-candidates-scanned", metavar="N", type=int, default=20_000_000,
                   help="Safety valve: stop mutating after this many unique "
                        "candidates have been considered, even if --max-words "
                        "hasn't been reached (default 20M, 0 = unlimited)")
    p.add_argument("--policy-min",  metavar="N",       type=int, help="Min password length")
    p.add_argument("--policy-max",  metavar="N",       type=int, help="Max password length")
    p.add_argument("--no-scrape",   action="store_true", help="Skip website scraping")
    p.add_argument("--no-osint",    action="store_true", help="Skip OSINT collection")
    p.add_argument("--seeds",       metavar="FILE",    help="Additional seed words file")
    p.add_argument("--output",      metavar="DIR",     help="Output directory")
    p.add_argument("--export-rules", action="store_true",
                    help="Also export a hashcat .rule file + seed-words file "
                         "usable against any external base wordlist")
    p.add_argument("--rules-only",  action="store_true",
                    help="Skip mutation/wordlist generation entirely — only "
                         "collect OSINT and export the hashcat rule + seeds "
                         "files (fast path for very large targets)")
    p.add_argument("--rules-tier",  metavar="TIER",    default="standard",
                    choices=["basic", "standard", "exhaustive"],
                    help="Hashcat rule coverage: basic|standard|exhaustive (default standard)")
    p.add_argument("--format",      metavar="FORMAT",  default="all",
                   choices=["json", "md", "all"], help="Report format")
    p.add_argument("--auto",        action="store_true", help="Fully automatic mode")
    p.add_argument("--resume",      metavar="SESSION_ID", help="Resume a previous session")
    p.add_argument("--preflight",   action="store_true", help="Run dependency check")
    p.add_argument("--scope-wizard",action="store_true", help="Create scope.yaml interactively")
    p.add_argument("--verify-log",  metavar="SESSION_ID", help="Verify HMAC audit log")
    p.add_argument("--report",      metavar="SESSION_ID", help="Generate report for session")
    p.add_argument("--lang",        metavar="LANG",    default="en",
                   choices=["en", "hi"], help="Interface language")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("-q", "--quiet",   action="store_true", help="Minimal output")
    return p


# ─── Setup ────────────────────────────────────────────────────────────────────

def _setup(args: argparse.Namespace) -> None:
    level = logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(name)s  %(levelname)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    i18n.init(args.lang)

    if args.output:
        from modules import generator
        generator.OUTPUTS_DIR = Path(args.output)
        generator.OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)


# ─── Hashcat rule export ──────────────────────────────────────────────────────

def _export_rules(s: WordsmithSession, tier: str, audit) -> dict[str, str]:
    """Export a hashcat .rule file + companion seed-words file for the
    current session's OSINT context. Shared by --auto/--rules-only and the
    interactive menu so both paths stay in sync."""
    from modules.generator import OUTPUTS_DIR
    from modules.rules import RuleExporter

    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = re.sub(r"[^\w.-]", "_", s.target_domain or s.target_name or "wordsmith")

    exporter = RuleExporter(s)
    paths = exporter.export(OUTPUTS_DIR, target, ts, tier=tier)

    success(f"Hashcat rules: {paths['rules']}  ({tier} tier)")
    success(f"Seed words:    {paths['seeds']}")
    info("Pair with an existing base wordlist, e.g.:")
    info(f"  cat {paths['seeds']} rockyou.txt > combined.txt")
    info(f"  hashcat -a 0 -r {paths['rules']} combined.txt hash.txt")

    audit.log(
        "rules.exported",
        rules_path=str(paths["rules"]),
        seeds_path=str(paths["seeds"]),
        tier=tier,
    )
    return {k: str(v) for k, v in paths.items()}


# ─── Auto mode ────────────────────────────────────────────────────────────────

def run_auto(args: argparse.Namespace) -> int:
    """Automated pipeline: OSINT → scrape → policy → mutate → generate → report."""
    mgr = SessionManager()
    s   = mgr.session

    if args.domain:
        s.target_domain = args.domain
    if args.company:
        s.target_name = args.company

    if not s.target_domain and not s.target_name:
        error("--auto requires --domain or --company")
        return 1

    scope_path = Path(args.scope)
    scope_mgr  = ScopeManager(scope_path)
    target     = s.target_domain or s.target_name
    audit      = get_logger(s.session_id)

    # Fail-closed: --auto refuses to run without a valid scope file unless the
    # operator explicitly accepts the risk. A missing OR malformed scope file
    # leaves scope_mgr unloaded; the old warn-and-continue path silently
    # disabled all enforcement on a typo'd --scope.
    if not scope_mgr.loaded:
        if args.no_scope_i_understand:
            warn(f"Running WITHOUT scope enforcement ({scope_mgr.load_error}).")
            audit.log("scope.disabled", reason=scope_mgr.load_error or "unloaded")
        else:
            error(
                f"No valid scope loaded ({scope_mgr.load_error}). Refusing to run "
                "--auto. Create one with --scope-wizard, or pass "
                "--no-scope-i-understand to override (authorized use only)."
            )
            return 1

    try:
        scope_mgr.require_scope(target, "wordsmith auto mode")
    except ScopeError as exc:
        error(str(exc))
        return 1

    audit.log("session.start", mode="auto", target=target)
    s.scope_file = str(scope_path)

    # Apply manual policy overrides from CLI
    if args.policy_min or args.policy_max:
        s.policy.update({
            "min_length": args.policy_min or 8,
            "max_length": args.policy_max or 0,
        })

    # Load extra seeds
    if args.seeds:
        seed_path = Path(args.seeds)
        if seed_path.exists():
            extra = [l.strip() for l in seed_path.read_text(encoding="utf-8").splitlines() if l.strip()]
            s.base_words.extend(extra)
            info(f"Loaded {len(extra)} extra seeds from {seed_path}")

    # Step 2: OSINT
    if not args.no_osint and s.target_domain and scope_mgr.module_allowed("osint"):
        print_section("OSINT Collection")
        try:
            from modules.osint import OSINTCollector
            collector = OSINTCollector(s, scope_path)
            collector.collect_all(s.target_domain)
        except Exception as exc:
            warn(f"OSINT collection failed: {exc}")

    # Step 3: Scrape (only if not already done via OSINT)
    if (not args.no_scrape and s.target_domain and not s.scraped_words
            and scope_mgr.module_allowed("scraper")):
        print_section("Website Scraping")
        try:
            from modules.scraper import WebScraper
            scraper = WebScraper(s, scope_mgr=scope_mgr)
            scraper.scrape(s.target_domain)
        except Exception as exc:
            warn(f"Scraping failed: {exc}")

    # Step 4: Policy detection
    print_section("Password Policy")
    if not s.policy and s.target_domain:
        try:
            from modules.analyzer import PolicyAnalyzer
            analyzer = PolicyAnalyzer(s, scope_mgr=scope_mgr)
            analyzer.analyze(s.target_domain, interactive=False)
        except Exception as exc:
            warn(f"Policy detection failed: {exc}")

    # Step 5+6: Mutation + wordlist generation — skipped entirely under
    # --rules-only, since the hashcat rule export below needs neither.
    if not args.rules_only:
        print_section("Word Mutation")
        try:
            from modules.mutator import MutationEngine
            engine = MutationEngine(s)
            if args.strategies:
                nums = [int(x.strip()) for x in args.strategies.split(",") if x.strip().isdigit()]
                engine.enable_strategies(nums)

            seed_words = (
                s.target_keywords
                + s.target_employees
                + s.target_products
                + s.scraped_words
                + s.base_words
                + ([s.target_domain.split(".")[0]] if s.target_domain else [])
                + ([s.target_name] if s.target_name else [])
            )
            seed_words = list(dict.fromkeys(w for w in seed_words if w))
            info(f"Mutating {len(seed_words)} seed words...")
            s.mutated_words = engine.mutate_all(
                seed_words,
                max_words=args.max_words,
                max_scan=args.max_candidates_scanned or None,
            )
            engine.print_stats()
            success(f"Generated {len(s.mutated_words):,} mutations")
        except Exception as exc:
            error(f"Mutation failed: {exc}")
            logger.exception("Mutation error")
            return 1

        print_section("Wordlist Generation")
        try:
            from modules.generator import WordlistGenerator
            gen = WordlistGenerator(s)
            gen.build(
                max_size_mb=scope_mgr.max_wordlist_mb(args.max_size),
                max_words=args.max_words,
                max_scan=args.max_candidates_scanned or None,
            )
        except Exception as exc:
            error(f"Generation failed: {exc}")
            return 1

    # Step 6b: Hashcat rule export
    if args.export_rules or args.rules_only:
        print_section("Hashcat Rule Export")
        try:
            _export_rules(s, args.rules_tier, audit)
        except Exception as exc:
            error(f"Rule export failed: {exc}")
            logger.exception("Rule export error")

    # Step 7: Report
    print_section("Report Generation")
    try:
        from modules.report import ReportGenerator
        rgen = ReportGenerator(s)
        fmt = [args.format] if args.format != "all" else ["json", "md"]
        rgen.generate(formats=fmt)
    except Exception as exc:
        warn(f"Report generation failed: {exc}")

    mgr.save()
    audit.close(success=True)
    success(f"Session saved: {s.session_id}")

    if not args.quiet and s.final_wordlist_path:
        success(f"Wordlist: {s.final_wordlist_path}")

    return 0


# ─── Interactive menu ─────────────────────────────────────────────────────────

def run_interactive(args: argparse.Namespace) -> int:
    """Full interactive TUI menu."""
    print_banner()

    mgr = SessionManager()
    if args.resume:
        try:
            mgr = SessionManager.load(args.resume)
            success(f"Resumed session: {args.resume}")
        except Exception as exc:
            warn(f"Could not resume: {exc}. Starting fresh session.")

    s   = mgr.session
    audit = get_logger(s.session_id)

    # Apply CLI target hints
    if args.domain:
        s.target_domain = args.domain
    if args.company:
        s.target_name = args.company

    scope_path = Path(args.scope)
    scope_mgr  = ScopeManager(scope_path)

    # CLI overrides also take effect in interactive mode (previously
    # --strategies and --policy-min/max were silently auto-only).
    if args.strategies:
        s.strategies_used = [x.strip() for x in args.strategies.split(",") if x.strip().isdigit()]
    if args.policy_min or args.policy_max:
        s.policy.update({
            "min_length": args.policy_min or 8,
            "max_length": args.policy_max or 0,
        })

    audit.log("session.start", mode="interactive")

    while True:
        print_compact_header(s.target_domain or "no target")
        print_menu({
            "target_domain":     s.target_domain,
            "target_name":       s.target_name,
            "final_wordlist_path": s.final_wordlist_path,
        })

        try:
            choice = input(f"\n  {C.YELLOW}wordsmith{C.RESET} > ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            mgr.save()
            audit.close()
            break

        if choice == "q":
            mgr.save()
            audit.close()
            info("Session saved. Goodbye.")
            break

        elif choice == "1":
            _menu_set_target(s, scope_mgr, audit)

        elif choice == "2":
            _menu_run_osint(s, scope_path, audit)

        elif choice == "3":
            _menu_scrape(s, scope_mgr, audit)

        elif choice == "4":
            _menu_detect_policy(s, scope_mgr, audit)

        elif choice == "5":
            _menu_configure_mutations(s)

        elif choice == "6":
            _menu_generate(s, args, audit)

        elif choice == "7":
            _menu_view_top(s)

        elif choice == "8":
            _menu_export_report(s, args)

        elif choice == "9":
            _menu_test_hashes(s)

        elif choice == "x":
            _menu_export_rules(s, args, audit)

        elif choice == "s":
            path = mgr.save()
            success(f"Session saved: {path}")

        elif choice == "r":
            sid = input("  Session ID: ").strip()
            try:
                mgr = SessionManager.load(sid)
                s   = mgr.session
                success(f"Resumed: {sid}")
            except Exception as exc:
                error(str(exc))

        elif choice == "l":
            _menu_list_sessions()

        elif choice == "w":
            scope_wizard(scope_path)
            scope_mgr = ScopeManager(scope_path)

        elif choice == "v":
            _menu_verify_log(s)

        elif choice == "?":
            _print_help()

        else:
            warn(f"Unknown option: {choice!r}. Press [?] for help.")

    return 0


# ─── Menu handlers ────────────────────────────────────────────────────────────

def _menu_set_target(s: WordsmithSession, scope_mgr: ScopeManager, audit) -> None:
    print_section("Set Target")
    domain = input("  Target domain (e.g. example.com, blank to skip): ").strip()
    if domain:
        try:
            scope_mgr.require_scope(domain, "target")
            s.target_domain = domain.lower()
            audit.log("target.set", domain=s.target_domain)
            success(f"Domain set: {s.target_domain}")
        except ScopeError as exc:
            error(str(exc))

    name = input("  Company/organization name (blank to skip): ").strip()
    if name:
        s.target_name = name
        audit.log("target.set", name=name)
        success(f"Org name set: {name}")

    extra_emails = input("  Known employee emails (comma-separated, blank to skip): ").strip()
    if extra_emails:
        s.target_emails.extend(e.strip() for e in extra_emails.split(",") if e.strip())

    extra_kw = input("  Manual seed words (comma-separated, blank to skip): ").strip()
    if extra_kw:
        s.target_keywords.extend(k.strip() for k in extra_kw.split(",") if k.strip())
        success(f"Added {len(s.target_keywords)} manual seeds")


def _menu_run_osint(s: WordsmithSession, scope_path: Path, audit) -> None:
    if not s.target_domain:
        error("Set a target domain first (option 1).")
        return
    print_section("OSINT Collection")
    try:
        from modules.osint import OSINTCollector
        collector = OSINTCollector(s, scope_path)
        collector.collect_all(s.target_domain)
        audit.log("osint.menu.done", domain=s.target_domain)
    except ScopeError as exc:
        error(str(exc))
    except Exception as exc:
        error(f"OSINT failed: {exc}")
        logger.exception("OSINT error")


def _menu_scrape(s: WordsmithSession, scope_mgr: ScopeManager, audit) -> None:
    if not s.target_domain:
        error("Set a target domain first (option 1).")
        return
    print_section("Website Scraping")
    try:
        scope_mgr.require_scope(s.target_domain, "website scraping")
        from modules.scraper import WebScraper
        scraper = WebScraper(s, scope_mgr=scope_mgr)
        words = scraper.scrape(s.target_domain)
        success(f"Scraped {len(words)} unique words from {s.target_domain}")
        audit.log("scrape.done", domain=s.target_domain, words=len(words))
    except ScopeError as exc:
        error(str(exc))
    except Exception as exc:
        error(f"Scrape failed: {exc}")


def _menu_detect_policy(s: WordsmithSession, scope_mgr: ScopeManager, audit) -> None:
    print_section("Password Policy Detection")
    domain = s.target_domain or ""
    try:
        from modules.analyzer import PolicyAnalyzer
        analyzer = PolicyAnalyzer(s, scope_mgr=scope_mgr)
        if domain:
            policy = analyzer.analyze(domain)
        else:
            policy = analyzer.manual_input()
        s.policy = policy
        audit.log("policy.detected", policy=policy)
    except Exception as exc:
        error(f"Policy detection failed: {exc}")


def _menu_configure_mutations(s: WordsmithSession) -> None:
    print_section("Configure Mutations")
    print(f"""
  Strategy list:
   [1] Case variants        [2] Leet speak          [3] Year suffix
   [4] Symbol append        [5] Number append        [6] Word combinator
   [7] Keyboard walks       [8] Name variants        [9] Domain variants
  [10] Common patterns     [11] CMS defaults        [12] Temporal patterns
  [13] Location variants

  Currently all strategies are enabled by default.
  Enter strategy numbers to enable (comma-separated), or blank for all:
    """)
    raw = input("  Enable strategies [1-13, all]: ").strip()
    if raw and raw.lower() != "all":
        nums = [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]
        s.strategies_used = [str(n) for n in nums]
        success(f"Enabled strategies: {nums}")
    else:
        s.strategies_used = []
        success("All strategies enabled")


def _menu_generate(s: WordsmithSession, args: argparse.Namespace, audit) -> None:
    print_section("Generate Wordlist")

    if not s.target_domain and not s.target_name:
        error("Set a target first (option 1).")
        return

    try:
        from modules.mutator import MutationEngine
        engine = MutationEngine(s)

        if s.strategies_used and all(x.isdigit() for x in s.strategies_used):
            engine.enable_strategies([int(x) for x in s.strategies_used])

        seed_words = (
            s.target_keywords
            + s.target_employees
            + s.target_products
            + s.scraped_words
            + s.base_words
            + ([s.target_domain.split(".")[0]] if s.target_domain else [])
            + ([s.target_name] if s.target_name else [])
        )
        seed_words = list(dict.fromkeys(w for w in seed_words if w))

        if not seed_words:
            word_input = input("  No seeds yet. Enter words manually (comma-separated): ").strip()
            seed_words = [w.strip() for w in word_input.split(",") if w.strip()]

        if not seed_words:
            error("No seed words available. Run OSINT or set seeds manually.")
            return

        info(f"Mutating {len(seed_words)} seed words with all enabled strategies...")
        s.mutated_words = engine.mutate_all(
            seed_words,
            max_words=args.max_words,
            max_scan=args.max_candidates_scanned or None,
        )
        engine.print_stats()
        success(f"Generated {len(s.mutated_words):,} candidates")

        max_mb_raw = input(f"  Max wordlist size in MB [{args.max_size}]: ").strip()
        max_mb = float(max_mb_raw) if max_mb_raw else args.max_size

        from modules.generator import WordlistGenerator
        gen = WordlistGenerator(s)
        gen.build(
            max_size_mb=max_mb,
            max_words=args.max_words,
            max_scan=args.max_candidates_scanned or None,
        )
        audit.log("generate.done", words=s.final_wordlist_size, path=s.final_wordlist_path)

    except Exception as exc:
        error(f"Generation failed: {exc}")
        logger.exception("Generate error")


def _menu_view_top(s: WordsmithSession) -> None:
    print_section("Top Password Candidates")
    if not s.mutated_words and not s.final_wordlist_path:
        error("Generate a wordlist first (option 6).")
        return

    words = s.mutated_words[:50] if s.mutated_words else []
    if not words and s.final_wordlist_path:
        try:
            import itertools
            with open(s.final_wordlist_path, encoding="utf-8") as f:
                words = [line.strip() for line in itertools.islice(f, 50)]
        except Exception:
            pass

    for i, w in enumerate(words[:50], 1):
        print(f"  {i:3d}. {C.YELLOW}{w}{C.RESET}")


def _menu_export_report(s: WordsmithSession, args: argparse.Namespace) -> None:
    print_section("Export Report")
    try:
        from modules.report import ReportGenerator
        rgen = ReportGenerator(s)
        fmt = [args.format] if args.format != "all" else ["json", "md"]
        paths = rgen.generate(formats=fmt)
        for fmt_name, path in paths.items():
            success(f"{fmt_name.upper()} report: {path}")
    except Exception as exc:
        error(f"Report failed: {exc}")


def _menu_export_rules(s: WordsmithSession, args: argparse.Namespace, audit) -> None:
    print_section("Export Hashcat Rules")

    if not s.target_domain and not s.target_name:
        error("Set a target first (option 1).")
        return

    tier = args.rules_tier
    raw = input(f"  Rules tier [basic/standard/exhaustive, default {tier}]: ").strip().lower()
    if raw in ("basic", "standard", "exhaustive"):
        tier = raw

    try:
        _export_rules(s, tier, audit)
    except Exception as exc:
        error(f"Rule export failed: {exc}")
        logger.exception("Rule export error")


def _menu_test_hashes(s: WordsmithSession) -> None:
    print_section("Test Against Hashes")
    if not s.final_wordlist_path:
        error("Generate a wordlist first (option 6).")
        return

    import shutil
    if not shutil.which("hashcat"):
        warn("hashcat not found. Install it to use this feature.")
        info("Suggested command:")
        wl = s.final_wordlist_path
        print(f"\n  hashcat -a 0 -m <HASH_TYPE> <HASH_FILE> {wl}\n")
        return

    hash_file = input("  Path to hash file: ").strip()
    hash_mode = input("  Hash type (e.g. 0=MD5, 1000=NTLM, 22000=WPA): ").strip()

    if not hash_file or not hash_mode:
        return

    from modules.banner import info as binfo
    binfo(f"Running hashcat (stats only — cracked values NOT logged)...")
    try:
        import subprocess
        result = subprocess.run(
            ["hashcat", "-a", "0", "-m", hash_mode, hash_file, s.final_wordlist_path,
             "--status", "--quiet", "--runtime=60"],
            capture_output=True, text=True, timeout=120,
        )
        for line in result.stdout.splitlines():
            if any(k in line.lower() for k in ["progress", "recovered", "speed", "time"]):
                print(f"  {line}")
    except Exception as exc:
        error(f"hashcat error: {exc}")


def _menu_list_sessions() -> None:
    print_section("Sessions")
    from modules.state import SessionManager
    sessions = SessionManager.list_sessions()
    if not sessions:
        info("No saved sessions found.")
        return
    for sess in sessions:
        ts = sess.get("timestamp", "")[:19]
        domain = sess.get("target_domain", "–")
        sid    = sess.get("session_id", "–")
        wl     = "✓" if sess.get("final_wordlist_path") else "–"
        print(f"  [{ts}] {C.YELLOW}{sid[:8]}...{C.RESET}  domain={domain}  wordlist={wl}")


def _menu_verify_log(s: WordsmithSession) -> None:
    print_section("Verify Audit Log")
    ok, count, msg = AuditLogger.verify(s.session_id)
    if ok:
        success(msg)
    else:
        error(f"Verification FAILED: {msg}")


def _print_help() -> None:
    print(f"""
  {C.BOLD}wordsmith — OSINT-seeded intelligent wordlist generator{C.RESET}

  {C.YELLOW}Workflow:{C.RESET}
    1 → Set your target domain/company
    2 → Run OSINT to gather public intelligence
    3 → Scrape the website for additional keywords
    4 → Detect or input the password policy
    5 → Configure which mutation strategies to use
    6 → Generate the wordlist (scores by likelihood)
    7 → Preview top 50 candidates
    8 → Export a pentest report (JSON + Markdown)
    x → Export hashcat rules (.rule + seed words, for use with any base wordlist)

  {C.YELLOW}Session:{C.RESET}
    [s] Save current session to disk
    [r] Resume a previous session
    [l] List all saved sessions

  {C.YELLOW}Scope:{C.RESET}
    [w] Create scope.yaml (REQUIRED before targeting any system)
    [v] Verify the HMAC-chained audit log

  {C.YELLOW}CLI flags:{C.RESET}
    --auto --domain example.com   Fully automated pipeline
    --export-rules                Also export hashcat .rule + seeds files
    --rules-only                  Skip wordlist generation, rules/seeds only
    --preflight                   Check dependencies
    --scope-wizard                Create scope.yaml
    --verify-log SESSION_ID       Verify audit chain
    --lang en|hi                  Change language
    """)


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> int:
    parser = _build_parser()
    args   = parser.parse_args()
    _setup(args)

    # ── Special single-shot modes ──────────────────────────────────────────
    if args.preflight:
        ok, _ = run_preflight()
        return 0 if ok else 1

    if getattr(args, "scope_wizard"):
        scope_wizard(Path(args.scope))
        return 0

    if args.verify_log:
        ok, count, msg = AuditLogger.verify(args.verify_log)
        if ok:
            print(f"  {C.GREEN}[+]{C.RESET} {msg}")
        else:
            print(f"  {C.RED}[-]{C.RESET} {msg}")
        return 0 if ok else 1

    if args.report:
        try:
            mgr = SessionManager.load(args.report)
        except FileNotFoundError:
            error(f"Session not found: {args.report}")
            return 1
        from modules.report import ReportGenerator
        rgen = ReportGenerator(mgr.session)
        fmt = [args.format] if args.format != "all" else ["json", "md"]
        paths = rgen.generate(formats=fmt)
        for fmt_name, path in paths.items():
            print(f"  {fmt_name}: {path}")
        return 0

    # ── First-run check ────────────────────────────────────────────────────
    if not SENTINEL_FILE.exists() and not args.quiet:
        run_preflight_with_autofix()

    # ── Dispatch ──────────────────────────────────────────────────────────
    if args.auto:
        return run_auto(args)
    else:
        return run_interactive(args)


if __name__ == "__main__":
    sys.exit(main())
