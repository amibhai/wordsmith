#!/bin/bash
# wordsmith installer
# Usage: bash install.sh
# Requires: Python >= 3.10

set -e

echo ""
echo "┌──────────────────────────────────────────────────────┐"
echo "│          wordsmith — dependency installer            │"
echo "│     OSINT-seeded intelligent wordlist generator      │"
echo "└──────────────────────────────────────────────────────┘"
echo ""

# ── Detect OS and package manager ─────────────────────────────────────────────
PKG_INSTALL=""
PKG_MGR=""
if command -v apt-get &>/dev/null; then
    PKG_INSTALL="apt-get install -y";              PKG_MGR="apt"
elif command -v pacman &>/dev/null; then
    PKG_INSTALL="pacman -S --noconfirm --needed";  PKG_MGR="pacman"
elif command -v dnf &>/dev/null; then
    PKG_INSTALL="dnf install -y";                  PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
    PKG_INSTALL="yum install -y";                  PKG_MGR="yum"
elif command -v apk &>/dev/null; then
    PKG_INSTALL="apk add";                         PKG_MGR="apk"
elif command -v brew &>/dev/null; then
    PKG_INSTALL="brew install";                    PKG_MGR="brew"
fi

# ── Check Python version ──────────────────────────────────────────────────────
PYTHON="python3"
if ! command -v python3 &>/dev/null; then
    PYTHON="python"
fi

PY_VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    echo "ERROR: Python >= 3.10 required (found $PY_VERSION)"
    exit 1
fi
echo "[+] Python $PY_VERSION — OK"

# ── Install system packages ───────────────────────────────────────────────────
SYSTEM_PACKAGES="curl whois"
case "$PKG_MGR" in
    apt)          SYSTEM_PACKAGES="$SYSTEM_PACKAGES dnsutils" ;;
    pacman|brew)  SYSTEM_PACKAGES="$SYSTEM_PACKAGES bind" ;;
    apk)          SYSTEM_PACKAGES="$SYSTEM_PACKAGES bind-tools" ;;
    *)            SYSTEM_PACKAGES="$SYSTEM_PACKAGES bind-utils" ;;
esac

if [ -n "$PKG_INSTALL" ]; then
    echo "[*] Installing system packages: $SYSTEM_PACKAGES"
    if [ "$PKG_MGR" = "brew" ]; then
        # Homebrew must NOT run as root.
        $PKG_INSTALL $SYSTEM_PACKAGES || echo "[!] Some packages may have failed — continuing"
    elif [ "${EUID:-$(id -u)}" -eq 0 ]; then
        $PKG_INSTALL $SYSTEM_PACKAGES || echo "[!] Some packages may have failed — continuing"
    else
        echo "[!] Not root — skipping system package install."
        echo "    Run manually: sudo $PKG_INSTALL $SYSTEM_PACKAGES"
    fi
else
    echo "[!] No supported package manager found (apt/dnf/yum/pacman/apk/brew)."
    echo "    Install manually: curl, whois, and dig (dnsutils/bind-tools)."
fi

# ── Install Python packages ───────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQ="$SCRIPT_DIR/requirements.txt"

# Prefer a plain install; only retry with --break-system-packages on a
# PEP 668 "externally-managed-environment" failure. Errors are NOT swallowed
# (no 2>/dev/null) so real problems surface. A venv is still the cleanest
# option — see the README.
PKGS="beautifulsoup4 rich dnspython python-whois pyyaml httpx"
echo "[*] Installing Python packages..."
if [ -f "$REQ" ]; then
    $PYTHON -m pip install -q -r "$REQ" || \
    $PYTHON -m pip install --break-system-packages -q -r "$REQ" || \
    echo "[!] pip install failed — see errors above (try a virtualenv)"
else
    $PYTHON -m pip install -q $PKGS || \
    $PYTHON -m pip install --break-system-packages -q $PKGS || \
    echo "[!] pip install failed — see errors above (try a virtualenv)"
fi
echo "[+] Python package install step complete"

# ── Create directories ────────────────────────────────────────────────────────
mkdir -p ~/.wordsmith/{sessions,audit}
echo "[+] Created ~/.wordsmith/sessions and ~/.wordsmith/audit"

# ── Create entry point ────────────────────────────────────────────────────────
ENTRY="/usr/local/bin/wordsmith"
if [ "$EUID" -eq 0 ] && [ -d /usr/local/bin ]; then
    cat > "$ENTRY" <<ENTRY_SCRIPT
#!/bin/bash
$PYTHON "$SCRIPT_DIR/wordsmith.py" "\$@"
ENTRY_SCRIPT
    chmod +x "$ENTRY"
    echo "[+] Created entry point: $ENTRY"
else
    echo "[!] Not root — skipping /usr/local/bin/wordsmith creation."
    echo "    Run manually: python3 $SCRIPT_DIR/wordsmith.py"
fi

echo ""
echo "┌──────────────────────────────────────────────────────┐"
echo "│  wordsmith installed successfully!                   │"
echo "│                                                      │"
echo "│  Quick start:                                        │"
echo "│    python3 wordsmith.py                              │"
echo "│    python3 wordsmith.py --preflight                  │"
echo "│    python3 wordsmith.py --scope-wizard               │"
echo "│    python3 wordsmith.py --auto --domain example.com  │"
echo "│                                                      │"
echo "│  LEGAL: Use only on systems you own or are           │"
echo "│  authorized to test. Create scope.yaml first.        │"
echo "└──────────────────────────────────────────────────────┘"
echo ""
