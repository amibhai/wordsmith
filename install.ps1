#!/usr/bin/env pwsh
# wordsmith installer (Windows / PowerShell)
# Usage: powershell -ExecutionPolicy Bypass -File install.ps1
# Requires: Python >= 3.10

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "+--------------------------------------------------------+"
Write-Host "|          wordsmith - dependency installer               |"
Write-Host "|     OSINT-seeded intelligent wordlist generator         |"
Write-Host "+--------------------------------------------------------+"
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# -- Locate Python ----------------------------------------------------------------
# Prefer the "py" launcher (pinned to -3) since it's the standard Windows
# install method; fall back to python3, then plain python.
$PythonExe = $null
$PythonPreArgs = @()

if (Get-Command py -ErrorAction SilentlyContinue) {
    $PythonExe = "py"
    $PythonPreArgs = @("-3")
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $PythonExe = "python3"
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $PythonExe = "python"
}

if (-not $PythonExe) {
    Write-Host "[-] ERROR: Python not found. Install Python >= 3.10 from python.org first." -ForegroundColor Red
    exit 1
}

function Invoke-Py {
    & $PythonExe @PythonPreArgs @args
}

# -- Check Python version -----------------------------------------------------------
$versionOutput = (Invoke-Py -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')").Trim()
$versionParts = $versionOutput.Split(".")
$pyMajor = [int]$versionParts[0]
$pyMinor = [int]$versionParts[1]

if ($pyMajor -lt 3 -or ($pyMajor -eq 3 -and $pyMinor -lt 10)) {
    Write-Host "[-] ERROR: Python >= 3.10 required (found $versionOutput)" -ForegroundColor Red
    exit 1
}
Write-Host "[+] Python $versionOutput - OK" -ForegroundColor Green

# -- Install Python packages ---------------------------------------------------------
$Req = Join-Path $ScriptDir "requirements.txt"
Write-Host "[*] Installing Python packages..." -ForegroundColor Yellow

Invoke-Py -m pip install --upgrade pip -q
if (Test-Path $Req) {
    Invoke-Py -m pip install -q -r $Req
} else {
    Invoke-Py -m pip install -q requests beautifulsoup4 rich dnspython python-whois pyyaml cryptography httpx
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] pip install may have had issues - check output above" -ForegroundColor Yellow
} else {
    Write-Host "[+] Python packages installed" -ForegroundColor Green
}

# -- Create ~/.wordsmith directories ---------------------------------------------------
$WordsmithHome = Join-Path $HOME ".wordsmith"
New-Item -ItemType Directory -Force -Path (Join-Path $WordsmithHome "sessions") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $WordsmithHome "audit") | Out-Null
Write-Host "[+] Created $WordsmithHome\sessions and $WordsmithHome\audit" -ForegroundColor Green

# -- Convenience launcher shim ---------------------------------------------------------
# Doesn't touch system PATH — just drops a wordsmith.cmd next to wordsmith.py so
# `.\wordsmith.cmd ...` works without remembering the python invocation.
$ShimPath = Join-Path $ScriptDir "wordsmith.cmd"
$PreArgsStr = if ($PythonPreArgs.Count -gt 0) { ($PythonPreArgs -join " ") + " " } else { "" }
$ShimContent = "@echo off`r`n$PythonExe $PreArgsStr`"$ScriptDir\wordsmith.py`" %*`r`n"
Set-Content -Path $ShimPath -Value $ShimContent -Encoding ascii -NoNewline
Write-Host "[+] Created launcher: $ShimPath" -ForegroundColor Green

Write-Host ""
Write-Host "[i] Note: the optional curl/whois/dig checks in --preflight are Linux" -ForegroundColor DarkGray
Write-Host "    conveniences only. Core OSINT (WHOIS/DNS/HTTP) runs through pure-" -ForegroundColor DarkGray
Write-Host "    Python httpx/dnspython/python-whois, so Windows works fully without" -ForegroundColor DarkGray
Write-Host "    them." -ForegroundColor DarkGray

Write-Host ""
Write-Host "+--------------------------------------------------------+"
Write-Host "|  wordsmith installed successfully!                      |"
Write-Host "|                                                          |"
Write-Host "|  Quick start:                                           |"
Write-Host "|    python wordsmith.py                                  |"
Write-Host "|    python wordsmith.py --preflight                      |"
Write-Host "|    python wordsmith.py --scope-wizard                   |"
Write-Host "|    python wordsmith.py --auto --domain example.com      |"
Write-Host "|                                                          |"
Write-Host "|  LEGAL: Use only on systems you own or are               |"
Write-Host "|  authorized to test. Create scope.yaml first.            |"
Write-Host "+--------------------------------------------------------+"
Write-Host ""
