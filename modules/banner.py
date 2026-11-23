#!/usr/bin/env python3
"""wordsmith — Terminal Identity Module (amber/gold theme)."""
from __future__ import annotations

import os
import random
import shutil
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.style import Style
from rich.text import Text


# ─── ANSI compatibility shim ──────────────────────────────────────────────────

class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


C = Colors


def _make_console() -> Console:
    import io
    if hasattr(sys.stdout, "buffer"):
        utf8_out = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace",
            newline="", line_buffering=True,
        )
        return Console(file=utf8_out, force_terminal=True, legacy_windows=False)
    return Console(force_terminal=True, legacy_windows=False)


console = _make_console()

# ─── ASCII art ────────────────────────────────────────────────────────────────

WORDSMITH_ART = """\
██╗    ██╗ ██████╗ ██████╗ ██████╗ ███████╗███╗   ███╗██╗████████╗██╗  ██╗
██║    ██║██╔═══██╗██╔══██╗██╔══██╗██╔════╝████╗ ████║██║╚══██╔══╝██║  ██║
██║ █╗ ██║██║   ██║██████╔╝██║  ██║███████╗██╔████╔██║██║   ██║   ███████║
██║███╗██║██║   ██║██╔══██╗██║  ██║╚════██║██║╚██╔╝██║██║   ██║   ██╔══██║
╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝███████║██║ ╚═╝ ██║██║   ██║   ██║  ██║
 ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝"""

# ─── Quotes ───────────────────────────────────────────────────────────────────

QUOTES = [
    ("Kevin Mitnick",
     "The human side of computer security is easily exploited "
     "and we still don't take it seriously enough."),
    ("Bruce Schneier",
     "Security is not a product, but a process."),
    ("Bruce Schneier",
     "Amateurs hack systems, professionals hack people."),
    ("Dan Kaminsky",
     "We keep saying the internet isn't a safe place. "
     "But we built it as if it was."),
    ("Mikko Hyppönen",
     "If it's smart, it's vulnerable."),
    ("Edward Snowden",
     "Arguing that you don't care about privacy because you have "
     "nothing to hide is no different from saying you don't care "
     "about free speech because you have nothing to say."),
    ("Anonymous",
     "We are legion. We do not forgive. "
     "We do not forget. Expect us."),
    ("Richard Stallman",
     "Free software is a matter of liberty, not price."),
    ("Gene Spafford",
     "The only truly secure system is one that is powered off, "
     "cast in a block of concrete and sealed in a lead-lined room "
     "with armed guards."),
    ("Kevin Poulsen",
     "Hackers are breaking the systems for profit. "
     "Before, it was about intellectual curiosity and "
     "there was an understanding that you don't do damage."),
    ("Parisa Tabriz",
     "I think of hacking as an intellectual challenge — "
     "a puzzle waiting to be solved."),
    ("Tsutomu Shimomura",
     "The key to security is knowing what you are protecting "
     "and who you are protecting it from."),
]

_CORNER_CHARS = frozenset("╗╔╝╚╣╠╦╩╬")

# ─── Amber/gold styles ────────────────────────────────────────────────────────

_S_LEFT   = Style(color="color(214)")         # amber
_S_MID    = Style(color="color(220)", bold=True)  # gold
_S_RIGHT  = Style(color="color(178)")         # warm yellow
_S_CORNER = Style(color="color(208)", bold=True)  # deep amber corners

_RESET = "\033[0m"


# ─── Core primitives ──────────────────────────────────────────────────────────

def _ansi(style_str: str) -> str:
    """Convert space-separated Rich-style tokens to ANSI escape sequence."""
    codes: list[str] = []
    for token in style_str.split():
        if token == "bold":
            codes.append("1")
        elif token == "dim":
            codes.append("2")
        elif token == "italic":
            codes.append("3")
        elif token.startswith("color(") and token.endswith(")"):
            n = token[6:-1]
            codes.append(f"38;5;{n}")
    return f"\033[{';'.join(codes)}m" if codes else ""


def typewrite(
    text: str,
    style: str = "",
    delay: float = 0.018,
    newline: bool = True,
) -> None:
    """Print text character-by-character with optional ANSI style and delay."""
    esc = _ansi(style) if style else ""
    for char in text:
        sys.stdout.write(f"{esc}{char}{_RESET}" if esc else char)
        sys.stdout.flush()
        time.sleep(delay)
    if newline:
        sys.stdout.write("\n")
        sys.stdout.flush()


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_scope() -> str:
    for candidate in ("scope.yaml", "scope.yml", "config/scope.yaml"):
        if os.path.exists(candidate):
            return "loaded"
    return "none"


def _get_target() -> str:
    """Return current session target if any from saved sessions."""
    sessions_dir = Path.home() / ".wordsmith" / "sessions"
    if sessions_dir.exists():
        files = sorted(sessions_dir.glob("*.json"), reverse=True)
        if files:
            try:
                import json
                data = json.loads(files[0].read_text(encoding="utf-8"))
                domain = data.get("target_domain", "")
                if domain:
                    return domain
            except Exception:
                pass
    return "not set"


# ─── Banner sections ──────────────────────────────────────────────────────────

def _color_row(row: str) -> Text:
    """Apply amber/gold tri-zone gradient to a single art row."""
    n  = len(row)
    t1 = row[:n // 3]
    t2 = row[n // 3 : 2 * n // 3]
    t3 = row[2 * n // 3:]

    def _section(s: str, base: Style) -> list:
        return [(ch, _S_CORNER if ch in _CORNER_CHARS else base) for ch in s]

    return Text.assemble(
        *_section(t1, _S_LEFT),
        *_section(t2, _S_MID),
        *_section(t3, _S_RIGHT),
    )


def _print_art() -> None:
    """Scan-line reveal — each row with 0.04s delay."""
    for row in WORDSMITH_ART.splitlines():
        if not row.strip():
            continue
        console.print(_color_row(row))
        time.sleep(0.04)


def _print_made_by() -> None:
    """Right-aligned 'made by  अ  म  ी' printed char-by-char."""
    term_width = shutil.get_terminal_size((80, 24)).columns
    label = "made by"
    name_spaced = "  अ  म  ी  "
    suffix = " ──"
    prefix = "── "

    full_text = prefix + label + name_spaced + suffix
    pad = max(0, term_width - len(full_text) - 2)

    parts = [
        (" " * pad + prefix, "color(240) italic"),
        (label + " ",        "color(240) italic"),
        (name_spaced,        "color(213) bold"),
        (suffix,             "color(240) italic"),
    ]

    for text, style_str in parts:
        esc = _ansi(style_str)
        for char in text:
            sys.stdout.write(f"{esc}{char}{_RESET}")
            sys.stdout.flush()
            time.sleep(0.04)

    sys.stdout.write("\n")
    sys.stdout.flush()


def _print_quote(author: str, quote: str) -> None:
    """Single quote with separator and ❝❞ formatting."""
    sep = "  ─────────────────────────────────────────────────"
    typewrite(sep, style="color(238) dim", delay=0.005)
    console.print()

    wrapped_lines = textwrap.fill(quote, width=65).splitlines()
    for i, ln in enumerate(wrapped_lines):
        prefix = "   ❝  " if i == 0 else "      "
        suffix = "  ❞" if i == len(wrapped_lines) - 1 else ""
        typewrite(prefix + ln + suffix, style="color(252) italic", delay=0.022)

    console.print()
    typewrite(f"        — {author}", style="color(220) bold", delay=0.035)
    console.print()
    typewrite(sep, style="color(238) dim", delay=0.005)


def _print_disclaimer() -> None:
    """Plain typewriter legal notice."""
    sep = "  ─────────────────────────────────────────────────"
    console.print()
    typewrite(sep, style="color(238) dim", delay=0.005)
    console.print()
    typewrite("  ⚠  LEGAL NOTICE", style="color(196) bold", delay=0.03)
    console.print()
    typewrite("  Use only on systems you own or have written",      style="color(252)", delay=0.015)
    typewrite("  permission to test. Unauthorized access is a",     style="color(252)", delay=0.015)
    typewrite("  criminal offence under CFAA, IT Act 2000 and",     style="color(252)", delay=0.015)
    typewrite("  similar laws worldwide. No liability accepted.",    style="color(252)", delay=0.015)
    console.print()
    typewrite(sep, style="color(238) dim", delay=0.005)


def _print_status(target: str, scope: str, ts: str) -> None:
    """Segment-by-segment ANSI typewriter status line."""
    console.print()
    segments = [
        ("  ◈ ",         "color(214)"),
        ("target: ",     "color(240) dim"),
        (target,         "color(220) bold"),
        ("   ◈ ",        "color(214)"),
        ("scope: ",      "color(240) dim"),
        (scope,          "color(220) bold"),
        ("   ◈ ",        "color(214)"),
        (ts,             "color(220) bold"),
    ]
    for text, style_str in segments:
        esc = _ansi(style_str)
        for char in text:
            sys.stdout.write(f"{esc}{char}{_RESET}")
            sys.stdout.flush()
            time.sleep(0.012)
    sys.stdout.write("\n")
    sys.stdout.flush()


def _print_enter_prompt() -> None:
    """Typewriter prompt → amber pulse → wait → clear."""
    prompt = "         [ Press ENTER to launch wordsmith ]"
    console.print()
    typewrite(prompt, style="color(214) bold", delay=0.045)

    pulse_colors = ["color(214)", "color(220)", "color(226)", "color(220)", "color(214)"]
    for _ in range(3):
        for c in pulse_colors:
            esc = _ansi(c + " bold")
            sys.stdout.write(f"\r{esc}{prompt}{_RESET}   ")
            sys.stdout.flush()
            time.sleep(0.15)

    sys.stdout.write("\r" + " " * (len(prompt) + 3) + "\r")
    sys.stdout.flush()

    try:
        input("")
    except (EOFError, KeyboardInterrupt):
        pass

    console.clear()


# ─── Public API ───────────────────────────────────────────────────────────────

def print_banner() -> None:
    """Full launch banner — called once at startup.

    Flow:
        1. clear screen
        2. scan-line art reveal (_print_art)
        3. right-aligned 'made by  अ  म  ी  ' (_print_made_by)
        4. one random hacker quote (_print_quote)
        5. plain typewriter disclaimer (_print_disclaimer)
        6. segment typewriter status bar (_print_status)
        7. typewriter + amber pulse Enter prompt (_print_enter_prompt)
           → console.clear() after Enter
    """
    os.system("clear" if os.name == "posix" else "cls")

    target = _get_target()
    scope  = _get_scope()
    ts     = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

    _print_art()
    _print_made_by()

    author, quote = random.choice(QUOTES)
    console.print()
    _print_quote(author, quote)
    _print_disclaimer()
    _print_status(target, scope, ts)
    _print_enter_prompt()


def print_compact_header(target: Optional[str] = None) -> None:
    """One-line amber header — shown at top of every menu iteration."""
    ts  = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    tgt = target or _get_target()
    t = Text.assemble(
        ("  wordsmith",  Style(color="color(214)", bold=True)),
        ("  ◈  ",        Style(color="color(240)")),
        (ts,             Style(color="color(240)", dim=True)),
        ("  ◈  ",        Style(color="color(240)")),
        (tgt,            Style(color="color(220)")),
    )
    console.print(t)
    console.print()


# ─── Menu and section helpers ─────────────────────────────────────────────────

MENU_TEMPLATE = f"""
{C.YELLOW}{'─'*62}{C.RESET}
  {C.BOLD}{C.WHITE}MAIN MENU{C.RESET}
{C.YELLOW}{'─'*62}{C.RESET}
  {C.BOLD}{C.DIM}── Target & Intelligence ─────────────────────────────────{C.RESET}
  {C.YELLOW}[1]{C.RESET} Set Target          {C.DIM}(domain / company name / both){C.RESET}
  {C.YELLOW}[2]{C.RESET} Run OSINT Collector  {C.DIM}(passive intelligence gathering){C.RESET}
  {C.YELLOW}[3]{C.RESET} Scrape Website       {C.DIM}(crawl target site for keywords){C.RESET}
  {C.YELLOW}[4]{C.RESET} Detect Policy        {C.DIM}(auto-detect password policy){C.RESET}
  {C.BOLD}{C.DIM}── Generation ─────────────────────────────────────────────{C.RESET}
  {C.YELLOW}[5]{C.RESET} Configure Mutations  {C.DIM}(toggle strategies on/off){C.RESET}
  {C.YELLOW}[6]{C.RESET} {C.BOLD}Generate Wordlist{C.RESET}    {C.DIM}(build and score final wordlist){C.RESET}
  {C.YELLOW}[7]{C.RESET} View Top Candidates  {C.DIM}(preview top 50 passwords){C.RESET}
  {C.YELLOW}[8]{C.RESET} Export Report        {C.DIM}(JSON / Markdown){C.RESET}
  {C.YELLOW}[9]{C.RESET} Test Against Hashes  {C.DIM}(optional hashcat integration){C.RESET}
  {C.YELLOW}[x]{C.RESET} Export Hashcat Rules {C.DIM}(.rule + seeds, works with any base wordlist){C.RESET}
  {C.YELLOW}[d]{C.RESET} Defensive Mode       {C.DIM}(banned-password list + exposure report){C.RESET}
  {C.BOLD}{C.DIM}── Session ────────────────────────────────────────────────{C.RESET}
  {C.DIM}[s]{C.RESET} Save Session
  {C.DIM}[r]{C.RESET} Resume Session       {C.DIM}(load previous session){C.RESET}
  {C.DIM}[l]{C.RESET} List Sessions
  {C.BOLD}{C.DIM}── Scope ──────────────────────────────────────────────────{C.RESET}
  {C.DIM}[w]{C.RESET} Scope Wizard         {C.DIM}(create scope.yaml){C.RESET}
  {C.DIM}[v]{C.RESET} Verify Audit Log
  {C.DIM}[?]{C.RESET} Help
  {C.RED}[q]{C.RESET} Quit
{C.YELLOW}{'─'*62}{C.RESET}"""


def print_menu(session_info: dict) -> None:
    """Print the main menu with current session state."""
    print(MENU_TEMPLATE)
    domain  = session_info.get("target_domain") or f"{C.DIM}not set{C.RESET}"
    name    = session_info.get("target_name") or f"{C.DIM}not set{C.RESET}"
    wl      = session_info.get("final_wordlist_path") or f"{C.DIM}none{C.RESET}"
    wl_name = os.path.basename(str(wl)) if wl != f"{C.DIM}none{C.RESET}" else wl
    print(
        f"  {C.DIM}domain={C.RESET}{C.YELLOW}{domain}{C.RESET}  "
        f"{C.DIM}org={C.RESET}{C.YELLOW}{name}{C.RESET}  "
        f"{C.DIM}wordlist={C.RESET}{C.YELLOW}{wl_name}{C.RESET}"
    )


def print_section(title: str) -> None:
    """Print a bold amber section header."""
    w = shutil.get_terminal_size((80, 24)).columns
    sep = "=" * w
    console.print()
    console.print(f"[bold color(214)]{sep}[/]")
    console.print(f"  [bold]{title}[/]")
    console.print(f"[bold color(214)]{sep}[/]")


def info(msg: str)    -> None: print(f"  {C.YELLOW}[*]{C.RESET} {msg}")
def success(msg: str) -> None: print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def warn(msg: str)    -> None: print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def error(msg: str)   -> None: print(f"  {C.RED}[-]{C.RESET} {msg}")
def found(msg: str)   -> None: print(f"\n  {C.BOLD}{C.GREEN}[★]{C.RESET} {C.BOLD}{msg}{C.RESET}\n")
