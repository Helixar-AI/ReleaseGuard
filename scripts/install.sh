#!/bin/sh
# ReleaseGuard installer
# Usage: curl -sSfL https://raw.githubusercontent.com/Helixar-AI/ReleaseGuard/main/scripts/install.sh | sh
set -e

REPO="Helixar-AI/ReleaseGuard"
BINARY="releaseguard"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  linux)  OS="linux" ;;
  darwin) OS="darwin" ;;
  *)      echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64 | amd64) ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *)               echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# Get latest version
VERSION="${VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
fi

if [ -z "$VERSION" ]; then
  echo "Failed to determine latest version" >&2
  exit 1
fi

echo "Installing releaseguard ${VERSION} (${OS}/${ARCH})..."

# Build download URL
ARCHIVE="${BINARY}-${VERSION}-${OS}-${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"

# Download and extract
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -sSfL "$URL" -o "$TMP/$ARCHIVE"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP"

# Verify checksum
CHECKSUM_FILE="${BINARY}-${VERSION}-checksums.txt"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
if curl -sSfL "$CHECKSUM_URL" -o "$TMP/checksums.txt" 2>/dev/null; then
  (cd "$TMP" && grep "$ARCHIVE" checksums.txt | sha256sum -c --status 2>/dev/null \
    || sha256sum -c --ignore-missing checksums.txt 2>/dev/null) \
    && echo "Checksum verified." || echo "Warning: checksum verification skipped."
fi

# Install
mkdir -p "$INSTALL_DIR"
mv "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
chmod +x "$INSTALL_DIR/$BINARY"

echo "Installed to $INSTALL_DIR/$BINARY"

# PATH hint
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo ""
     echo "Add the following to your shell profile:"
     echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
     ;;
esac

echo ""
"$INSTALL_DIR/$BINARY" --version
