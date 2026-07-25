# voli installer — https://github.com/Topurrra/voli
#
# WHAT THIS SCRIPT DOES (and it does NOTHING else — this is on purpose):
#   1. Downloads the latest voli release zip and its .sha256 from GitHub.
#   2. Verifies the SHA-256 hash. Mismatch => abort, delete download.
#   3. Extracts to %LOCALAPPDATA%\voli\bootstrap-tmp.
#   4. Runs `voli.exe setup` from there. THAT command (not this script) copies
#      the binaries to <root>\bin, creates dirs, adds shims\ to your user PATH
#      via HKCU, and broadcasts the change. All of it is user-level, no admin.
#   5. Deletes the temp extraction dir.
#
#   No telemetry. No analytics. No hidden prompts. No writes anywhere except
#   the temp dir and whatever `voli.exe setup` does (all under your user
#   profile, all reversible with `voli uninstall`). Read it top to bottom —
#   that is the whole thing.
#
# Usage:
#   iwr -useb https://volibear.dev/install | iex
#   iwr -useb https://github.com/Topurrra/voli/releases/latest/download/install.ps1 | iex
#
# Dev/testing:
#   .\install.ps1 -ZipPath C:\path\to\voli-x64.zip
#     Skips the download and installs from a local zip. If a sibling
#     <zip>.sha256 exists it is verified; otherwise the hash step is skipped.

[CmdletBinding()]
param(
    [string] $ZipPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Old PowerShell (5.1) defaults to TLS 1.0; GitHub requires 1.2+.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$BaseUrl = 'https://github.com/Topurrra/voli/releases/latest/download'
$ZipName = 'voli-x64.zip'

function Write-Info  { param($m) Write-Host $m -ForegroundColor Cyan }
function Write-Ok    { param($m) Write-Host $m -ForegroundColor Green }
function Write-Warn2 { param($m) Write-Host $m -ForegroundColor Yellow }

function Get-Download {
    param([string] $Url, [string] $OutFile)
    # Invoke-WebRequest surfaces HTTP 404 as a terminating error we catch below.
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
}

function Assert-Hash {
    param([string] $ZipFile, [string] $ShaFile)
    # The .sha256 file's first whitespace-delimited token is the hex digest
    # (tolerates both a bare hash and sha256sum's "<hash>  <name>" format).
    $expected = ((Get-Content $ShaFile -Raw).Trim() -split '\s+')[0].ToLower()
    $actual   = (Get-FileHash $ZipFile -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) {
        throw "SHA-256 mismatch: expected $expected, got $actual"
    }
}

# No admin required. Some users insist on running elevated — allow it, but warn:
# the PATH change lands in the elevated user's HKCU, which may not be you.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warn2 'Warning: running elevated. voli needs no admin; PATH changes apply to the elevated account.'
}

$root   = Join-Path $env:LOCALAPPDATA 'voli'
$tmpDir = Join-Path $root 'bootstrap-tmp'

# Fresh temp dir every run.
if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir }
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null

$cleanupZip = $null  # a download we own and should delete on failure

try {
    if ($ZipPath) {
        # ---- Local zip (dev/testing) ----
        if (-not (Test-Path $ZipPath)) {
            throw "zip not found: $ZipPath"
        }
        $zip = (Resolve-Path $ZipPath).Path
        $shaFile = "$zip.sha256"
        if (Test-Path $shaFile) {
            Write-Info "Verifying $zip against $shaFile ..."
            Assert-Hash -ZipFile $zip -ShaFile $shaFile
            Write-Ok 'Hash OK.'
        } else {
            Write-Warn2 'No sibling .sha256 found; skipping hash verification (local zip).'
        }
    } else {
        # ---- Download from GitHub releases/latest ----
        $zip     = Join-Path $tmpDir $ZipName
        $shaFile = "$zip.sha256"
        $cleanupZip = $zip

        Write-Info "Downloading voli from $BaseUrl/$ZipName ..."
        Get-Download -Url "$BaseUrl/$ZipName"         -OutFile $zip
        Get-Download -Url "$BaseUrl/$ZipName.sha256"  -OutFile $shaFile

        Write-Info 'Verifying SHA-256 ...'
        Assert-Hash -ZipFile $zip -ShaFile $shaFile
        Write-Ok 'Hash OK.'
    }

    # ---- Extract ----
    $extractDir = Join-Path $tmpDir 'extract'
    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
    Write-Info 'Extracting ...'
    Expand-Archive -Path $zip -DestinationPath $extractDir -Force

    $voliExe = Join-Path $extractDir 'voli.exe'
    if (-not (Test-Path $voliExe)) {
        throw "voli.exe not found in the archive at $extractDir"
    }

    # ---- Hand off to voli.exe setup (the real installer) ----
    Write-Info 'Running voli setup ...'
    & $voliExe setup
    if ($LASTEXITCODE -ne 0) {
        throw "voli setup failed (exit $LASTEXITCODE)"
    }

    $version = (& $voliExe --version) -join ' '

    Write-Host ''
    Write-Ok  "Installed $version"
    Write-Host 'Open a new terminal and run:  voli install ripgrep'
}
catch {
    Write-Host ''
    if ($_.Exception.Message -match '404' -or $_.Exception.Message -match 'Not Found') {
        Write-Warn2 'No published voli release was found (404). Check https://github.com/Topurrra/voli/releases.'
    } else {
        Write-Host "Install failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    if ($cleanupZip -and (Test-Path $cleanupZip)) { Remove-Item -Force $cleanupZip -ErrorAction SilentlyContinue }
    exit 1
}
finally {
    # Always clean up the temp extraction dir.
    if (Test-Path $tmpDir) { Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue }
}
