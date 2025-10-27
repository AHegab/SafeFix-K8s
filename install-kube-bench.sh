#!/bin/bash
# install-kube-bench.sh
# Installation script for kube-bench v0.13.0 on Linux/macOS
# This script downloads, verifies, and installs kube-bench

set -e

# Configuration
KUBE_BENCH_VERSION="0.13.0"
GITHUB_REPO="aquasecurity/kube-bench"
INSTALL_DIR="/usr/local/bin"
CFG_DIR="/etc/kube-bench"

# Detect OS and Architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case $ARCH in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# URLs
RELEASE_URL="https://github.com/$GITHUB_REPO/releases/download/v$KUBE_BENCH_VERSION"
BINARY_NAME="kube-bench_${KUBE_BENCH_VERSION}_${OS}_${ARCH}.tar.gz"
CHECKSUM_NAME="kube-bench_${KUBE_BENCH_VERSION}_checksums.txt"

echo "========================================"
echo "  kube-bench v$KUBE_BENCH_VERSION Installer"
echo "========================================"
echo ""
echo "Target System: $OS/$ARCH"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "WARNING: Not running as root."
    echo "You may need to use 'sudo' for installation."
    echo ""
fi

# Create temporary directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "Temporary directory: $TEMP_DIR"

# Step 1: Download binary
echo ""
echo "[1/6] Downloading kube-bench v$KUBE_BENCH_VERSION..."
BINARY_PATH="$TEMP_DIR/$BINARY_NAME"
BINARY_URL="$RELEASE_URL/$BINARY_NAME"
echo "  URL: $BINARY_URL"

if command -v curl &> /dev/null; then
    curl -sSL "$BINARY_URL" -o "$BINARY_PATH"
elif command -v wget &> /dev/null; then
    wget -q "$BINARY_URL" -O "$BINARY_PATH"
else
    echo "ERROR: Neither curl nor wget found. Please install one of them."
    exit 1
fi

echo "  Downloaded: $BINARY_PATH"
echo "  Size: $(du -h "$BINARY_PATH" | cut -f1)"

# Step 2: Download checksums
echo ""
echo "[2/6] Downloading checksums..."
CHECKSUM_PATH="$TEMP_DIR/$CHECKSUM_NAME"
CHECKSUM_URL="$RELEASE_URL/$CHECKSUM_NAME"
echo "  URL: $CHECKSUM_URL"

if command -v curl &> /dev/null; then
    curl -sSL "$CHECKSUM_URL" -o "$CHECKSUM_PATH"
else
    wget -q "$CHECKSUM_URL" -O "$CHECKSUM_PATH"
fi

echo "  Downloaded: $CHECKSUM_PATH"

# Step 3: Verify checksum
echo ""
echo "[3/6] Verifying checksum..."

EXPECTED_CHECKSUM=$(grep "$BINARY_NAME" "$CHECKSUM_PATH" | awk '{print $1}')

if [ -z "$EXPECTED_CHECKSUM" ]; then
    echo "ERROR: Could not find checksum for $BINARY_NAME"
    echo "Available checksums:"
    cat "$CHECKSUM_PATH"
    exit 1
fi

echo "  Expected SHA256: $EXPECTED_CHECKSUM"

if command -v sha256sum &> /dev/null; then
    ACTUAL_CHECKSUM=$(sha256sum "$BINARY_PATH" | awk '{print $1}')
elif command -v shasum &> /dev/null; then
    ACTUAL_CHECKSUM=$(shasum -a 256 "$BINARY_PATH" | awk '{print $1}')
else
    echo "ERROR: Neither sha256sum nor shasum found."
    exit 1
fi

echo "  Actual SHA256:   $ACTUAL_CHECKSUM"

if [ "$EXPECTED_CHECKSUM" = "$ACTUAL_CHECKSUM" ]; then
    echo "  Checksum verified successfully!"
else
    echo "ERROR: Checksum mismatch!"
    echo "  Expected: $EXPECTED_CHECKSUM"
    echo "  Actual:   $ACTUAL_CHECKSUM"
    exit 1
fi

# Step 4: Extract archive
echo ""
echo "[4/6] Extracting archive..."
EXTRACT_DIR="$TEMP_DIR/extracted"
mkdir -p "$EXTRACT_DIR"

tar -xzf "$BINARY_PATH" -C "$EXTRACT_DIR"
echo "  Extracted successfully"

# Find the executable
KUBE_BENCH_EXE=$(find "$EXTRACT_DIR" -name "kube-bench" -type f)

if [ -z "$KUBE_BENCH_EXE" ]; then
    echo "ERROR: Could not find kube-bench executable in extracted files"
    echo "Contents of extracted directory:"
    ls -la "$EXTRACT_DIR"
    exit 1
fi

echo "  Found executable: $KUBE_BENCH_EXE"

# Step 5: Install to target directory
echo ""
echo "[5/6] Installing to $INSTALL_DIR..."

if [ ! -w "$INSTALL_DIR" ]; then
    echo "  ERROR: No write permission for $INSTALL_DIR"
    echo "  Please run with sudo or as root"
    exit 1
fi

# Copy executable
TARGET_EXE="$INSTALL_DIR/kube-bench"
cp "$KUBE_BENCH_EXE" "$TARGET_EXE"
chmod +x "$TARGET_EXE"
echo "  Installed executable: $TARGET_EXE"

# Copy configuration files if they exist
CFG_SOURCE="$EXTRACT_DIR/cfg"
if [ -d "$CFG_SOURCE" ]; then
    echo "  Copying configuration files..."
    mkdir -p "$CFG_DIR"
    cp -r "$CFG_SOURCE"/* "$CFG_DIR/"
    echo "  Configuration files copied to: $CFG_DIR"
else
    echo "  No configuration files found in archive"
    echo "  Configuration files may need to be downloaded separately"
fi

# Step 6: Verify installation
echo ""
echo "[6/6] Verifying installation..."

if command -v kube-bench &> /dev/null; then
    VERSION_OUTPUT=$(kube-bench version 2>&1 || echo "Version check failed")
    echo "  Version check: OK"
    echo "  $VERSION_OUTPUT"
else
    echo "  WARNING: kube-bench not found in PATH"
    echo "  You may need to add $INSTALL_DIR to your PATH"
fi

echo ""
echo "========================================"
echo "  Installation Complete!"
echo "========================================"
echo ""
echo "Installation Summary:"
echo "  Executable:     $TARGET_EXE"
echo "  Configuration:  $CFG_DIR"
echo "  Version:        v$KUBE_BENCH_VERSION"
echo "  OS/Arch:        $OS/$ARCH"
echo ""
echo "Next Steps:"
echo "  1. Check version: kube-bench version"
echo "  2. Run basic scan: kube-bench run --targets node"
echo "  3. Run on master node: kube-bench run --targets master"
echo "  4. Full cluster scan: kube-bench run --targets master,node,etcd,policies"
echo ""
echo "For Kubernetes nodes:"
echo "  - Master node: sudo kube-bench run --targets master"
echo "  - Worker node: sudo kube-bench run --targets node"
echo "  - Etcd node:   sudo kube-bench run --targets etcd"
echo ""
echo "Documentation:"
echo "  https://github.com/aquasecurity/kube-bench"
echo ""
echo "Installation script completed."
