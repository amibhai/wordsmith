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
if command -v apt-get &>/dev/null; then
    PKG_INSTALL="apt-get install -y"
elif command -v pacman &>/dev/null; then
    PKG_INSTALL="pacman -S --noconfirm --needed"
elif command -v dnf &>/dev/null; then
    PKG_INSTALL="dnf install -y"
elif command -v yum &>/dev/null; then
    PKG_INSTALL="yum install -y"
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
if command -v apt-get &>/dev/null; then
    SYSTEM_PACKAGES="$SYSTEM_PACKAGES dnsutils"
elif command -v pacman &>/dev/null; then
    SYSTEM_PACKAGES="$SYSTEM_PACKAGES bind"
else
    SYSTEM_PACKAGES="$SYSTEM_PACKAGES bind-utils"
fi

if [ -n "$PKG_INSTALL" ]; then
    echo "[*] Installing system packages: $SYSTEM_PACKAGES"
    if [ "$EUID" -eq 0 ]; then
        $PKG_INSTALL $SYSTEM_PACKAGES || echo "[!] Some packages may have failed — continuing"
    else
        echo "[!] Not root — skipping system package install."
        echo "    Run manually: sudo $PKG_INSTALL $SYSTEM_PACKAGES"
    fi
fi

# ── Install Python packages ───────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQ="$SCRIPT_DIR/requirements.txt"

echo "[*] Installing Python packages..."
if [ -f "$REQ" ]; then
    $PYTHON -m pip install --break-system-packages -q -r "$REQ" 2>/dev/null || \
    $PYTHON -m pip install -q -r "$REQ" || \
    echo "[!] pip install may have had issues — check output above"
else
    $PYTHON -m pip install --break-system-packages -q \
        requests beautifulsoup4 rich dnspython python-whois \
        tldextract nltk pyyaml cryptography httpx 2>/dev/null || \
    $PYTHON -m pip install -q \
        requests beautifulsoup4 rich dnspython python-whois \
        tldextract nltk pyyaml cryptography httpx
fi
echo "[+] Python packages installed"

# ── NLTK data ─────────────────────────────────────────────────────────────────
echo "[*] Downloading NLTK data..."
$PYTHON -c "import nltk; nltk.download('words', quiet=True); nltk.download('names', quiet=True)" || true

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
