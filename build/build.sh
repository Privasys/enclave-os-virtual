#!/bin/bash
# Build the Enclave OS (Virtual) disk image.
#
# This script:
#   1. Cross-compiles the enclave-os Go binary for linux/amd64
#   2. Places it in the mkosi.extra overlay
#   3. Runs mkosi to build the disk image
#
# Requirements:
#   - Go 1.25+ (Privasys fork with RA-TLS)
#   - mkosi==26 (pip install mkosi==26)
#   - Must be run as root (for mkosi)
#   - Must be run on Linux (Ubuntu 24.04 recommended)
#
# Usage:
#   sudo ./build/build.sh [--manifest /path/to/manifest.yaml]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_DIR="$SCRIPT_DIR/image"
EXTRA_DIR="$IMAGE_DIR/mkosi.extra"

echo "=== Enclave OS (Virtual) Image Builder ==="
echo "Repo root: $REPO_ROOT"
echo "Image dir: $IMAGE_DIR"

# Parse arguments.
MANIFEST_PATH=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --manifest)
            MANIFEST_PATH="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

# Step 1: Build the Go binary.
echo ""
echo "=== Step 1: Building manager binary ==="
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
    -ldflags="-s -w" \
    -o "$EXTRA_DIR/usr/bin/manager" \
    "$REPO_ROOT/cmd/manager/"
echo "Binary built: $EXTRA_DIR/usr/bin/manager"

# Step 2: Optionally bake in a manifest.
if [ -n "$MANIFEST_PATH" ]; then
    echo ""
    echo "=== Step 2: Baking manifest into image ==="
    mkdir -p "$EXTRA_DIR/data"
    cp "$MANIFEST_PATH" "$EXTRA_DIR/data/manifest.yaml"
    echo "Manifest copied: $MANIFEST_PATH"
else
    echo ""
    echo "=== Step 2: No manifest specified (will need to provide at runtime) ==="
fi

# Step 3: Fix symlinks (Git may check them out as plain text).
echo ""
echo "=== Step 3: Fixing symlinks ==="
cd "$EXTRA_DIR/etc/systemd/system"
for f in local-fs.target.wants/data.mount \
         local-fs.target.wants/var-log.mount \
         local-fs.target.wants/var-tmp.mount \
         multi-user.target.wants/systemd-networkd.service \
         multi-user.target.wants/containerd.service \
         multi-user.target.wants/manager.service \
         sockets.target.wants/systemd-networkd.socket \
         sysinit.target.wants/systemd-networkd-wait-online.service; do
    if [ -f "$f" ] && [ ! -L "$f" ]; then
        target=$(cat "$f" | tr -d '\r\n')
        rm "$f"
        ln -s "$target" "$f"
        echo "  Fixed symlink: $f -> $target"
    fi
done
cd "$IMAGE_DIR"

# Fix resolv.conf symlink.
if [ -f "$EXTRA_DIR/etc/resolv.conf" ] && [ ! -L "$EXTRA_DIR/etc/resolv.conf" ]; then
    target=$(cat "$EXTRA_DIR/etc/resolv.conf" | tr -d '\r\n')
    rm "$EXTRA_DIR/etc/resolv.conf"
    ln -s "$target" "$EXTRA_DIR/etc/resolv.conf"
    echo "  Fixed symlink: resolv.conf -> $target"
fi

# Step 4: Build the disk image with mkosi.
echo ""
echo "=== Step 4: Building disk image with mkosi ==="
cd "$IMAGE_DIR"
mkosi build

echo ""
echo "=== Build complete ==="
ls -lh enclave-os-virtual_*.raw 2>/dev/null || echo "(No .raw file found — check mkosi output above)"
