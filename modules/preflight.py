"""
Pre-flight system checker — verify all dependencies before wordsmith runs.
First-run experience with interactive dependency installer.
Re-runnable via: wordsmith --preflight
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from importlib import import_module
from pathlib import Path
from typing import Optional

import io
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table


def _make_console() -> Console:
    if hasattr(sys.stdout, "buffer"):
        utf8_out = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace",
            newline="", line_buffering=True,
        )
        return Console(file=utf8_out, force_terminal=True, legacy_windows=False)
    return Console(force_terminal=True, legacy_windows=False)


console = _make_console()

MIN_PYTHON   = (3, 10)
SENTINEL_FILE = Path.home() / ".wordsmith" / ".preflight_done"

# ─── Tool definitions ─────────────────────────────────────────────────────────

# (name, version_cmd, version_regex, category, install_hint)
REQUIRED_TOOLS: list[tuple[str, str, str, str, str]] = [
    ("python3", "python3 --version 2>&1 || python --version 2>&1",
     r"Python (\d+\.\d+[\.\d]*)", "runtime", "python3"),
]

OPTIONAL_TOOLS: list[tuple[str, str, str, str, str]] = [
    ("curl",    "curl --version 2>&1 | head -1",
     r"curl (\d+\.\d+[\.\d]*)",    "osint",    "curl"),
    ("whois",   "whois --version 2>&1 | head -1",
     r"(\d+\.\d+[\.\d]*)",          "osint",    "whois"),
    ("dig",     "dig -v 2>&1 | head -1",
     r"(\d+\.\d+[\.\d]*)",          "osint",    "dnsutils"),
    ("hashcat", "hashcat --version 2>&1 | head -1",
     r"v?(\d+\.\d+[\.\d]*)",        "cracking", "hashcat"),
    ("john",    "john --version 2>&1 | head -1",
     r"John the Ripper (\d+\.\d+[\.\d]*)", "cracking", "john"),
    ("crunch",  "crunch 2>&1 | head -1",
     r"(\d+\.\d+[\.\d]*)",          "generation","crunch"),
    ("exiftool","exiftool -ver 2>&1",
     r"(\d+\.\d+[\.\d]*)",          "osint",    "libimage-exiftool-perl"),
]

PIP_PACKAGES: list[tuple[str, str, str]] = [
    ("requests",     "requests",       "required"),
    ("bs4",          "beautifulsoup4", "required"),
    ("rich",         "rich",           "required"),
    ("dns",          "dnspython",      "required"),
    ("whois",        "python-whois",   "required"),
    ("yaml",         "pyyaml",         "required"),
    ("cryptography", "cryptography",   "required"),
    ("httpx",        "httpx",          "required"),
    ("pypdf",        "pypdf",          "optional"),
]

TOOL_PACKAGES: dict[str, dict[str, Optional[str]]] = {
    "curl":     {"apt": "curl",    "pacman": "curl",    "dnf": "curl"},
    "whois":    {"apt": "whois",   "pacman": "whois",   "dnf": "whois"},
    "dig":      {"apt": "dnsutils","pacman": "bind",    "dnf": "bind-utils"},
    "hashcat":  {"apt": "hashcat", "pacman": "hashcat", "dnf": "hashcat"},
    "john":     {"apt": "john",    "pacman": "john",    "dnf": "john"},
    "crunch":   {"apt": "crunch",  "pacman": "crunch",  "dnf": "crunch"},
    "exiftool": {"apt": "libimage-exiftool-perl", "pacman": "perl-image-exiftool", "dnf": "perl-Image-ExifTool"},
}

FEATURE_MAP: dict[str, list[str]] = {
    "curl":     ["OSINT HTTP requests"],
    "whois":    ["Domain WHOIS lookup"],
    "dig":      ["DNS enumeration"],
    "hashcat":  ["GPU-accelerated hash testing"],
    "john":     ["Alternative hash testing"],
    "crunch":   ["Supplemental wordlist generation"],
    "exiftool": ["Document metadata extraction"],
}


@dataclass
class ToolStatus:
    name: str
    path: Optional[str]
    version: Optional[str]
    ok: bool
    required: bool
    category: str
    install_hint: str
    note: str = ""


@dataclass
class PipStatus:
    import_name: str
    pip_name: str
    category: str
    ok: bool
    version: Optional[str] = None


# ─── Detection helpers ────────────────────────────────────────────────────────

def _get_version(cmd_str: str, pattern: str) -> Optional[str]:
    try:
        result = subprocess.run(
            cmd_str, shell=True, capture_output=True, text=True, timeout=5
        )
        output = result.stdout + result.stderr
        m = re.search(pattern, output, re.IGNORECASE)
        return m.group(1) if m else "found"
    except Exception:
        return None


def _check_tool(
    name: str, cmd: str, pattern: str,
    required: bool, category: str, hint: str,
) -> ToolStatus:
    path = shutil.which(name) or shutil.which(name.replace("3", ""))
    if not path:
        return ToolStatus(
            name=name, path=None, version=None, ok=False,
            required=required, category=category, install_hint=hint,
            note="Not found",
        )
    version = _get_version(cmd, pattern)
    return ToolStatus(
        name=name, path=path, version=version, ok=version is not None,
        required=required, category=category, install_hint=hint,
    )


def _check_pip(import_name: str, pip_name: str, category: str) -> PipStatus:
    try:
        mod = import_module(import_name)
        ver = getattr(mod, "__version__", None) or getattr(mod, "VERSION", "found")
        return PipStatus(import_name=import_name, pip_name=pip_name,
                         category=category, ok=True, version=str(ver))
    except ImportError:
        return PipStatus(import_name=import_name, pip_name=pip_name,
                         category=category, ok=False)


# ─── Package manager detection ────────────────────────────────────────────────

def detect_package_manager() -> str:
    for pm in ("apt-get", "pacman", "dnf", "yum"):
        if shutil.which(pm):
            return pm
    return ""


def _pm_key(pm: str) -> str:
    if pm in ("apt-get", "apt"):
        return "apt"
    if pm == "pacman":
        return "pacman"
    if pm in ("dnf", "yum"):
        return "dnf"
    return ""


# ─── Interactive install ──────────────────────────────────────────────────────

def _install_system_packages(pkg_names: list[str], pm: str) -> dict[str, bool]:
    results: dict[str, bool] = {}
    pm_key = _pm_key(pm)
    if not pm_key:
        return {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("Installing...", total=len(pkg_names))
        for pkg in pkg_names:
            prog.update(task, description=f"Installing [color(214)]{pkg}[/color(214)]...")
            if pm == "apt-get":
                cmd = ["apt-get", "install", "-y", "--no-install-recommends", pkg]
            elif pm == "pacman":
                cmd = ["pacman", "-S", "--noconfirm", "--needed", pkg]
            else:
                cmd = [pm, "install", "-y", pkg]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                results[pkg] = r.returncode == 0
            except Exception as exc:
                results[pkg] = False
                console.print(f"  [red]ERROR[/] {pkg}: {exc}")
            prog.advance(task)
    return results


def _install_pip_packages(pip_names: list[str]) -> dict[str, bool]:
    results: dict[str, bool] = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task("pip install...", total=len(pip_names))
        for pkg in pip_names:
            prog.update(task, description=f"pip install [color(214)]{pkg}[/color(214)]...")
            try:
                r = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-q", pkg],
                    capture_output=True, text=True, timeout=120,
                )
                results[pkg] = r.returncode == 0
            except Exception as exc:
                results[pkg] = False
                console.print(f"  [red]ERROR[/] pip {pkg}: {exc}")
            prog.advance(task)
    return results


def _prompt_install(group_label: str, tool_names: list[str]) -> bool:
    console.print(
        f"\n  [bold yellow]{group_label}:[/bold yellow] "
        + ", ".join(f"[color(214)]{n}[/color(214)]" for n in tool_names)
    )
    try:
        ans = input("  Install them now? [Y/n]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    return ans in ("", "y", "yes")


# ─── Display table ────────────────────────────────────────────────────────────

def _build_tool_table(statuses: list[ToolStatus], pip_statuses: list[PipStatus]) -> Table:
    t = Table(
        title="System Dependencies — wordsmith",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold color(214)",
        border_style="dim color(178)",
    )
    t.add_column("Tool",        style="bold", width=18)
    t.add_column("Status",      justify="center", width=8)
    t.add_column("Version",     width=12)
    t.add_column("Category",    width=12)
    t.add_column("Install cmd", width=30)

    py_ok  = sys.version_info >= MIN_PYTHON
    py_ver = ".".join(str(x) for x in sys.version_info[:3])
    t.add_row(
        "python",
        "[green]✓[/]" if py_ok else "[red]✗[/]",
        py_ver,
        "runtime",
        f"requires >= {'.'.join(str(x) for x in MIN_PYTHON)}",
    )

    for s in statuses:
        if s.name == "python3":
            continue
        if s.ok:
            status_icon = "[green]✓[/]"
            inst_hint   = "[dim]installed[/dim]"
        elif s.required:
            status_icon = "[red]✗[/]"
            inst_hint   = f"[red]apt install {s.install_hint}[/red]"
        else:
            status_icon = "[yellow]–[/]"
            inst_hint   = f"[dim]apt install {s.install_hint}[/dim]"

        t.add_row(
            s.name,
            status_icon,
            s.version or "[dim]–[/]",
            f"[dim]{s.category}[/dim]",
            inst_hint,
        )

    t.add_section()
    for p in pip_statuses:
        if p.ok:
            icon = "[green]✓[/]"
            hint = "[dim]installed[/dim]"
            ver  = p.version or "found"
        else:
            if p.category == "required":
                icon = "[red]✗[/]"
                hint = f"[red]pip install {p.pip_name}[/red]"
            else:
                icon = "[yellow]–[/]"
                hint = f"[dim]pip install {p.pip_name}[/dim]"
            ver = "[dim]–[/]"
        t.add_row(
            p.import_name, icon, ver,
            f"[dim]{p.category}[/dim]", hint,
        )

    return t


# ─── Core preflight runner ────────────────────────────────────────────────────

def run_preflight(exit_on_failure: bool = True) -> tuple[bool, list[ToolStatus]]:
    """
    Run all pre-flight checks and display Rich tables.
    Returns (all_required_pass, statuses).
    """
    console.print()
    console.print(Panel.fit(
        "[bold color(214)]wordsmith — Pre-Flight System Check[/bold color(214)]",
        border_style="color(214)",
        padding=(0, 4),
    ))
    console.print()

    py_ok = sys.version_info >= MIN_PYTHON
    all_pass = py_ok

    statuses: list[ToolStatus] = []
    for name, cmd, pattern, cat, hint in REQUIRED_TOOLS:
        s = _check_tool(name, cmd, pattern, required=True, category=cat, hint=hint)
        statuses.append(s)
        if not s.ok:
            all_pass = False

    for name, cmd, pattern, cat, hint in OPTIONAL_TOOLS:
        statuses.append(
            _check_tool(name, cmd, pattern, required=False, category=cat, hint=hint)
        )

    pip_statuses = [_check_pip(imp, pip, cat) for imp, pip, cat in PIP_PACKAGES]

    required_pip_missing = any(
        not p.ok for p in pip_statuses if p.category == "required"
    )
    if required_pip_missing:
        all_pass = False

    console.print(_build_tool_table(statuses, pip_statuses))
    console.print()

    blocked: list[tuple[str, str]] = []
    for s in statuses:
        if not s.ok and s.name in FEATURE_MAP:
            for feat in FEATURE_MAP[s.name]:
                blocked.append((feat, s.name))

    if blocked:
        console.print("[dim]Features limited due to missing optional tools:[/dim]")
        for feat, tool in blocked:
            console.print(f"  [yellow]•[/yellow] [dim]{feat}[/dim]  [dim](needs {tool})[/dim]")
        console.print()

    if all_pass:
        console.print("[bold green]✓ All required checks passed. Ready to generate wordlists.[/bold green]")
    else:
        console.print("[bold red]✗ Pre-flight FAILED — fix the issues above.[/bold red]")
        if exit_on_failure:
            sys.exit(2)

    return all_pass, statuses


# ─── Interactive first-run installer ─────────────────────────────────────────

def run_preflight_with_autofix() -> bool:
    """Interactive first-run: scan, show, prompt install, re-verify, write sentinel."""
    console.print()
    console.print(Panel.fit(
        "[bold color(214)]wordsmith — First-Run Setup[/bold color(214)]\n"
        "[dim]Scanning system and installing missing dependencies...[/dim]",
        border_style="color(214)",
        padding=(0, 4),
    ))
    console.print()

    all_pass, statuses = run_preflight(exit_on_failure=False)
    pip_statuses = [_check_pip(imp, pip, cat) for imp, pip, cat in PIP_PACKAGES]

    pm = detect_package_manager()
    pm_key = _pm_key(pm)

    missing_optional = [s for s in statuses if not s.ok and not s.required]
    if missing_optional:
        pkg_map: dict[str, list[str]] = {}
        for s in missing_optional:
            pkg = TOOL_PACKAGES.get(s.name, {}).get(pm_key) if pm_key else None
            if pkg:
                pkg_map.setdefault(pkg, []).append(s.name)

        if pkg_map and _prompt_install(
            "OPTIONAL tools missing (some features limited)",
            [s.name for s in missing_optional],
        ):
            _install_system_packages(list(pkg_map.keys()), pm)

    missing_pip = [p for p in pip_statuses if not p.ok]
    if missing_pip:
        if _prompt_install(
            "Python packages missing (required for core functionality)",
            [p.pip_name for p in missing_pip],
        ):
            _install_pip_packages([p.pip_name for p in missing_pip])

    if missing_optional or missing_pip:
        console.print("\n[color(214)]Re-running verification...[/color(214)]\n")
        all_pass, _ = run_preflight(exit_on_failure=False)
    else:
        console.print("[green]  All dependencies present — nothing to install.[/green]")

    SENTINEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    SENTINEL_FILE.touch()
    console.print(
        f"\n[dim]  Sentinel: {SENTINEL_FILE}[/dim]"
        "\n[dim]  Future starts skip this check. "
        "Run [bold]wordsmith --preflight[/bold] to re-check.[/dim]\n"
    )
    return all_pass
