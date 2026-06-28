#!/usr/bin/env bash
# MCPAudit CLI installer
# Usage: curl -sSfL https://raw.githubusercontent.com/abhijitdalal26/MCP-Audit/master/packages/cli/install.sh | bash
#
# Detects your OS/arch, downloads the right binary from GitHub Releases,
# verifies the SHA-256 checksum, and installs to /usr/local/bin.
#
# Supports: macOS (arm64/amd64), Linux (amd64), Windows (via Git Bash/WSL)
# Requires: curl, sha256sum (or shasum on macOS)

set -euo pipefail

REPO="abhijitdalal26/MCP-Audit"
BINARY_NAME="mcpaudit"
INSTALL_DIR="/usr/local/bin"

# ── Color helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'
info()  { printf "${BOLD}[mcpaudit]${RESET} %s\n" "$*"; }
ok()    { printf "${GREEN}[mcpaudit]${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}[mcpaudit]${RESET} %s\n" "$*" >&2; }
error() { printf "${RED}[mcpaudit]${RESET} %s\n" "$*" >&2; exit 1; }

# ── Detect OS / arch ──────────────────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  linux)   OS_KEY="linux" ;;
  darwin)  OS_KEY="darwin" ;;
  mingw*|msys*|cygwin*) OS_KEY="windows" ;;
  *)       error "Unsupported OS: $OS. Download manually from https://github.com/${REPO}/releases" ;;
esac

case "$ARCH" in
  x86_64)        ARCH_KEY="amd64" ;;
  arm64|aarch64) ARCH_KEY="arm64" ;;
  *)             error "Unsupported architecture: $ARCH" ;;
esac

# Windows binary has .exe extension
EXT=""
if [ "$OS_KEY" = "windows" ]; then EXT=".exe"; fi
ASSET_NAME="${BINARY_NAME}-${OS_KEY}-${ARCH_KEY}${EXT}"

# ── Resolve version ───────────────────────────────────────────────────────────
VERSION="${MCPAUDIT_VERSION:-}"
if [ -z "$VERSION" ]; then
  info "Resolving latest release..."
  VERSION=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
  if [ -z "$VERSION" ]; then
    error "Could not resolve latest version. Set MCPAUDIT_VERSION=v0.x.x to pin."
  fi
fi

info "Installing mcpaudit ${VERSION} for ${OS_KEY}/${ARCH_KEY}..."

# ── Download ──────────────────────────────────────────────────────────────────
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading ${ASSET_NAME}..."
curl -sSfL "${BASE_URL}/${ASSET_NAME}" -o "${TMP_DIR}/${BINARY_NAME}${EXT}"

# ── Verify checksum ───────────────────────────────────────────────────────────
info "Verifying SHA-256 checksum..."
curl -sSfL "${BASE_URL}/checksums.txt" -o "${TMP_DIR}/checksums.txt"

EXPECTED=$(grep "${ASSET_NAME}" "${TMP_DIR}/checksums.txt" | awk '{print $1}')
if [ -z "$EXPECTED" ]; then
  warn "No checksum entry found for ${ASSET_NAME} — skipping verification"
else
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "${TMP_DIR}/${BINARY_NAME}${EXT}" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "${TMP_DIR}/${BINARY_NAME}${EXT}" | awk '{print $1}')
  else
    warn "sha256sum / shasum not found — skipping checksum verification"
    ACTUAL="$EXPECTED"
  fi

  if [ "$ACTUAL" != "$EXPECTED" ]; then
    error "Checksum mismatch for ${ASSET_NAME}!\n  Expected: ${EXPECTED}\n  Actual:   ${ACTUAL}\nAborting install."
  fi
  ok "Checksum verified: ${ACTUAL}"
fi

# ── Install ───────────────────────────────────────────────────────────────────
chmod +x "${TMP_DIR}/${BINARY_NAME}${EXT}"

if [ -w "$INSTALL_DIR" ]; then
  mv "${TMP_DIR}/${BINARY_NAME}${EXT}" "${INSTALL_DIR}/${BINARY_NAME}${EXT}"
else
  info "Needs sudo to write to ${INSTALL_DIR}..."
  sudo mv "${TMP_DIR}/${BINARY_NAME}${EXT}" "${INSTALL_DIR}/${BINARY_NAME}${EXT}"
fi

# ── Verify ────────────────────────────────────────────────────────────────────
ok "Installed to ${INSTALL_DIR}/${BINARY_NAME}${EXT}"
"${INSTALL_DIR}/${BINARY_NAME}${EXT}" version

printf "\n${BOLD}Quick start:${RESET}\n"
printf "  mcpaudit scan                          # auto-detect config\n"
printf "  mcpaudit scan mcp.json --fail-on high  # CI gate\n"
printf "  mcpaudit scan mcp.json --format sarif  # GitHub Security tab\n\n"
printf "Docs: https://github.com/${REPO}#readme\n"
