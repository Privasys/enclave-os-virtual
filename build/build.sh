#!/bin/bash
# Build the Enclave OS (Virtual) disk image.
#
# This script:
#   0. Builds a patched kernel with CVM guard (BadAML mitigation) if needed
#   1. Cross-compiles the manager Go binary for linux/amd64
#   2. Builds Caddy with the ra-tls-caddy module via xcaddy
#   3. Optionally bakes a manifest into the image
#   4. Fixes symlinks (Git may check them out as plain text)
#   5. Runs mkosi to build the disk image
#
# Requirements:
#   - Go 1.25+ (Privasys fork with RA-TLS)
#   - xcaddy (go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest)
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

# Step 0: Build patched kernel if .debs are not present.
KERNEL_DEBS_DIR="$SCRIPT_DIR/kernel/debs"
if ! ls "$KERNEL_DEBS_DIR"/linux-image-*.deb 1>/dev/null 2>&1; then
    echo ""
    echo "=== Step 0: Building patched kernel (CVM guard) ==="
    "$SCRIPT_DIR/kernel/build-kernel.sh"
else
    echo ""
    echo "=== Step 0: Patched kernel .debs already present, skipping ==="
    ls "$KERNEL_DEBS_DIR"/*.deb
fi

# Step 1: Build the Go binary.
echo ""
echo "=== Step 1: Building manager binary ==="
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
    -ldflags="-s -w" \
    -o "$EXTRA_DIR/usr/bin/manager" \
    "$REPO_ROOT/cmd/manager/"
echo "Binary built: $EXTRA_DIR/usr/bin/manager"

# Step 2: Build the Caddy binary with ra-tls-caddy module.
echo ""
echo "=== Step 2: Building Caddy with ra-tls-caddy ==="
RA_TLS_CADDY_DIR="$REPO_ROOT/../../libraries/ra-tls-caddy/src"
if [ ! -d "$RA_TLS_CADDY_DIR" ]; then
    echo "ERROR: ra-tls-caddy source not found at $RA_TLS_CADDY_DIR"
    exit 1
fi
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 xcaddy build \
    --with "github.com/Privasys/ra-tls-caddy=$RA_TLS_CADDY_DIR" \
    --output "$EXTRA_DIR/usr/bin/caddy"
echo "Caddy built: $EXTRA_DIR/usr/bin/caddy"

# Step 3: Optionally bake in a manifest.
if [ -n "$MANIFEST_PATH" ]; then
    echo ""
    echo "=== Step 3: Baking manifest into image ==="
    mkdir -p "$EXTRA_DIR/data"
    cp "$MANIFEST_PATH" "$EXTRA_DIR/data/manifest.yaml"
    echo "Manifest copied: $MANIFEST_PATH"
else
    echo ""
    echo "=== Step 3: No manifest specified (will need to provide at runtime) ==="
fi

# Step 4: Fix symlinks (Git may check them out as plain text).
echo ""
echo "=== Step 4: Fixing symlinks ==="
cd "$EXTRA_DIR/etc/systemd/system"
for f in local-fs.target.wants/data.mount \
         local-fs.target.wants/var-log.mount \
         local-fs.target.wants/var-tmp.mount \
         multi-user.target.wants/systemd-networkd.service \
         multi-user.target.wants/containerd.service \
         multi-user.target.wants/manager.service \
         multi-user.target.wants/caddy.service \
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

# Step 5: Build the disk image with mkosi.
echo ""
echo "=== Step 5: Building disk image with mkosi ==="
cd "$IMAGE_DIR"
mkosi build

echo ""
echo "=== Build complete ==="
ls -lh enclave-os-virtual_*.raw 2>/dev/null || echo "(No .raw file found — check mkosi output above)"
