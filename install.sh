#!/bin/sh
# voli installer for Linux and macOS — https://github.com/Topurrra/voli
#
# WHAT THIS SCRIPT DOES (and it does NOTHING else — this is on purpose):
#   1. Detects your OS (linux/darwin) and architecture (x86_64/aarch64) and
#      picks the matching release tarball.
#   2. Downloads the tarball and its .sha256 from GitHub releases.
#   3. Verifies the SHA-256 hash. Mismatch => abort, delete download.
#   4. Extracts to <root>/bootstrap-tmp (<root> is $VOLI_ROOT, or
#      $XDG_DATA_HOME/voli (~/.local/share/voli) on Linux,
#      ~/Library/Application\ Support/voli on macOS).
#   5. Runs `./voli setup` from there. THAT command (not this script) copies
#      the binaries to <root>/bin and creates dirs, shims, cache, and db.
#      All of it is user-level, no sudo, no root.
#   6. Appends the shims dir to your shell PATH (once, idempotent) via your
#      login profile (~/.profile, or fish config for fish). The voli BINARY
#      itself never touches shell rc files — only this installer does, once.
#   7. Deletes the temp extraction dir.
#
#   No telemetry. No analytics. No hidden prompts. No writes anywhere except
#   the temp dir, the voli root, and one PATH line in your shell profile — all
#   reversible with `voli self-delete`. Read it top to bottom.
#
# Usage:
#   curl -fsSL https://volibear.dev/install.sh | sh
#   curl -fsSL https://github.com/Topurrra/voli/releases/latest/download/install.sh | sh
#
# Dev/testing:
#   ./install.sh /path/to/voli-x86_64-linux.tar.gz
#     Skips the download and installs from a local tarball. If a sibling
#     <tarball>.sha256 exists it is verified; otherwise the hash step is skipped.

set -eu

BASE_URL='https://github.com/Topurrra/voli/releases/latest/download'

info() { printf '\033[36m%s\033[0m\n' "$*"; }
ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*"; }
fail() { printf '\033[31mInstall failed: %s\033[0m\n' "$*" >&2; exit 1; }

# ---- platform ---------------------------------------------------------------

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Linux)  OS='linux' ;;
  Darwin) OS='macos' ;;
  *) fail "unsupported OS: $(uname -s) (voli supports Linux and macOS; Windows uses install.ps1)" ;;
esac
case "$ARCH" in
  x86_64|amd64)   ARCH='x86_64' ;;
  arm64|aarch64)  ARCH='aarch64' ;;
  *) fail "unsupported architecture: $(uname -m) (voli ships x86_64 and aarch64)" ;;
esac
ASSET="voli-${ARCH}-${OS}.tar.gz"

# ---- root -------------------------------------------------------------------

if [ -n "${VOLI_ROOT:-}" ]; then
  ROOT="$VOLI_ROOT"
elif [ "$OS" = 'macos' ]; then
  ROOT="$HOME/Library/Application Support/voli"
else
  ROOT="${XDG_DATA_HOME:-$HOME/.local/share}/voli"
fi
TMPDIR="$ROOT/bootstrap-tmp"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

# ---- acquire tarball --------------------------------------------------------

LOCAL_TARBALL="${1:-}"
if [ -n "$LOCAL_TARBALL" ]; then
  [ -f "$LOCAL_TARBALL" ] || fail "tarball not found: $LOCAL_TARBALL"
  TARBALL="$LOCAL_TARBALL"
  # Resolve to an absolute path without depending on realpath(1).
  case "$TARBALL" in
    /*) ;;
    *) TARBALL="$(pwd)/$TARBALL" ;;
  esac
  if [ -f "$TARBALL.sha256" ]; then
    info "Verifying $TARBALL against $TARBALL.sha256 ..."
    EXPECTED="$(awk '{print $1}' "$TARBALL.sha256" | tr 'A-Z' 'a-z')"
    ACTUAL="$(sha256sum "$TARBALL" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$TARBALL" | awk '{print $1}')"
    [ "$EXPECTED" = "$ACTUAL" ] || fail "SHA-256 mismatch: expected $EXPECTED, got $ACTUAL"
    ok 'Hash OK.'
  else
    warn 'No sibling .sha256 found; skipping hash verification (local tarball).'
  fi
else
  command -v curl >/dev/null 2>&1 || fail 'curl is required to download voli'
  TARBALL="$TMPDIR/$ASSET"
  info "Downloading voli from $BASE_URL/$ASSET ..."
  curl -fsSL --retry 3 -o "$TARBALL" "$BASE_URL/$ASSET" \
    || fail "download failed (404 means no published release for $ASSET yet — see https://github.com/Topurrra/voli/releases)"
  curl -fsSL --retry 3 -o "$TARBALL.sha256" "$BASE_URL/$ASSET.sha256" \
    || fail 'checksum download failed'
  info 'Verifying SHA-256 ...'
  EXPECTED="$(awk '{print $1}' "$TARBALL.sha256" | tr 'A-Z' 'a-z')"
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL="$(sha256sum "$TARBALL" | awk '{print $1}')"
  else
    ACTUAL="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
  fi
  [ "$EXPECTED" = "$ACTUAL" ] || fail "SHA-256 mismatch: expected $EXPECTED, got $ACTUAL"
  rm -f "$TARBALL.sha256"
  ok 'Hash OK.'
fi

# ---- extract ----------------------------------------------------------------

EXTRACT="$TMPDIR/extract"
mkdir -p "$EXTRACT"
info 'Extracting ...'
tar -xzf "$TARBALL" -C "$EXTRACT"
[ -x "$EXTRACT/voli" ] || [ -f "$EXTRACT/voli" ] \
  || fail "voli not found in the archive at $EXTRACT"

# ---- hand off to voli setup (the real installer) ----------------------------

info 'Running voli setup ...'
VOLI_ROOT="$ROOT" "$EXTRACT/voli" setup || fail "voli setup failed (exit $?)"

# ---- PATH -------------------------------------------------------------------

SHIMS="$ROOT/shims"
case ":${PATH:-}:" in
  *":$SHIMS:"*) IN_PATH_NOW=1 ;;
  *) IN_PATH_NOW='' ;;
esac

add_to_profile() {
  # $1 = file, $2 = line. Appends once; creates the file if missing.
  [ -f "$1" ] || : > "$1"
  grep -qxF "$2" "$1" 2>/dev/null && return 1
  printf '%s\n' "$2" >> "$1"
  printf '%s\n' "$1"
  return 0
}

PROFILE_LINE="export PATH=\"$SHIMS:\$PATH\""
if [ -n "${FISH_VERSION:-}" ] || [ "$(basename "${SHELL:-sh}")" = 'fish' ]; then
  FISH_CONF="$HOME/.config/fish/config.fish"
  FISH_LINE="fish_add_path \"$SHIMS\""
  mkdir -p "$(dirname "$FISH_CONF")"
  if ADDED="$(add_to_profile "$FISH_CONF" "$FISH_LINE")"; then
    ok "Added shims to PATH in $ADDED"
  else
    info "Shims dir already on PATH in your fish config."
  fi
else
  # Login shells read ~/.profile; add there so every shell gets it, and to the
  # rc of the current interactive shell for immediacy.
  ADDED=''
  if ADDED_FILE="$(add_to_profile "$HOME/.profile" "$PROFILE_LINE")"; then
    ADDED="$ADDED_FILE"
  fi
  case "$(basename "${SHELL:-}")" in
    zsh) RC="$HOME/.zshrc" ;;
    bash) RC="$HOME/.bashrc" ;;
    *) RC='' ;;
  esac
  if [ -n "${RC:-}" ] && [ "$RC" != "$HOME/.profile" ]; then
    if ADDED_FILE="$(add_to_profile "$RC" "$PROFILE_LINE")"; then
      ADDED="$ADDED $ADDED_FILE"
    fi
  fi
  if [ -n "$ADDED" ]; then
    ok "Added shims to PATH in:$ADDED"
  else
    info 'Shims dir already on PATH in your shell profile.'
  fi
fi

if [ -z "$IN_PATH_NOW" ]; then
  export PATH="$SHIMS:$PATH"
fi

VERSION="$("$EXTRACT/voli" --version 2>/dev/null || echo voli)"
printf '\n'
ok "Installed $VERSION"
echo 'Ready in this terminal. Try:  voli install skill/voli-memory --for claude-code'
echo '(New terminals pick up PATH from your profile automatically.)'
