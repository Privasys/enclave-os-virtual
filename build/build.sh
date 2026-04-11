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
#   sudo ./build/build.sh --gpu [--manifest /path/to/manifest.yaml]
#   sudo ./build/build.sh --cloud gcp [--gpu] [--manifest /path/to/manifest.yaml]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
EXTRA_DIR="$SCRIPT_DIR/image/mkosi.extra"

# Parse arguments.
MANIFEST_PATH=""
GPU_VARIANT=false
CLOUD_PROFILE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --manifest)
            MANIFEST_PATH="$2"
            shift 2
            ;;
        --gpu)
            GPU_VARIANT=true
            shift
            ;;
        --cloud)
            CLOUD_PROFILE="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

if [ "$GPU_VARIANT" = true ]; then
    IMAGE_DIR="$SCRIPT_DIR/image-gpu"
    echo "=== Enclave OS (Virtual) GPU Image Builder ==="
else
    IMAGE_DIR="$SCRIPT_DIR/image"
    echo "=== Enclave OS (Virtual) Image Builder ==="
fi
echo "Repo root: $REPO_ROOT"
echo "Image dir: $IMAGE_DIR"
if [ -n "$CLOUD_PROFILE" ]; then
    echo "Cloud profile: $CLOUD_PROFILE"
fi

# Step 0: Download patched kernel if .debs are not present.
# Both base and GPU variants use the BadAML-patched kernel.
# The patch does NOT change the kernel ABI, so Ubuntu-signed NVIDIA
# modules load correctly with module.sig_enforce=1.
KERNEL_DEBS_DIR="$SCRIPT_DIR/kernel/debs"
if ! ls "$KERNEL_DEBS_DIR"/linux-image-*.deb 1>/dev/null 2>&1; then
    echo ""
    echo "=== Step 0: Downloading patched kernel .debs from cvm-images ==="
    mkdir -p "$KERNEL_DEBS_DIR"
    if ! command -v gh >/dev/null 2>&1; then
        echo "ERROR: GitHub CLI (gh) is required to download kernel .debs."
        echo "Install it with: sudo apt install gh"
        echo "Or build the kernel manually in cvm-images and copy the .debs to $KERNEL_DEBS_DIR"
        exit 1
    fi
    gh release download --repo Privasys/cvm-images --tag kernel-v0.1.0 \
        --pattern '*.deb' --dir "$KERNEL_DEBS_DIR"
    echo "Downloaded kernel .debs:"
    ls "$KERNEL_DEBS_DIR"/*.deb
else
    echo ""
    echo "=== Step 0: Patched kernel .debs already present, skipping ==="
    ls "$KERNEL_DEBS_DIR"/*.deb
fi

# Step 0.5: Fetch cvm-images.
# Both base and GPU images import from cvm-images:
#   - Base: boot chain (boot.conf), common overlay (SSH, network, GCE keys,
#     volatile mounts, sysctl), and post-installation scripts (vmlinuz, GRUB).
#   - GPU: all of the above, plus NVIDIA APT pinning, prepare script,
#     nvidia-persistenced overlay, and GPU kernel command line.
#
# Pin to a specific cvm-images release tag so builds are reproducible.
CVM_IMAGES_TAG="tdx-gpu-v0.2.0"
CVM_IMAGES_DIR="$SCRIPT_DIR/cvm-images"
if [ ! -d "$CVM_IMAGES_DIR/common" ]; then
    echo ""
    echo "=== Step 0.5: Fetching cvm-images ==="
    # Try workspace layout first (monorepo / local development).
    LOCAL_CVM="$(cd "$REPO_ROOT/../.." 2>/dev/null && pwd)/infra/cvm-images"
    if [ -d "$LOCAL_CVM/common" ]; then
        ln -sfn "$LOCAL_CVM" "$CVM_IMAGES_DIR"
        echo "Linked local cvm-images: $LOCAL_CVM"
    else
        if ! command -v gh >/dev/null 2>&1; then
            echo "ERROR: GitHub CLI (gh) is required to clone cvm-images."
            exit 1
        fi
        gh repo clone Privasys/cvm-images "$CVM_IMAGES_DIR" -- --depth 1 --branch "$CVM_IMAGES_TAG"
        echo "Cloned cvm-images"
    fi
else
    echo ""
    echo "=== Step 0.5: cvm-images already present, skipping ==="
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

# Fix symlinks in cvm-images common overlay.
COMMON_EXTRA="$CVM_IMAGES_DIR/common/mkosi.extra"
cd "$COMMON_EXTRA/etc/systemd/system"
for f in local-fs.target.wants/tmp.mount \
         local-fs.target.wants/var-log.mount \
         local-fs.target.wants/var-tmp.mount \
         multi-user.target.wants/systemd-networkd.service \
         sockets.target.wants/systemd-networkd.socket \
         sysinit.target.wants/systemd-networkd-wait-online.service; do
    if [ -f "$f" ] && [ ! -L "$f" ]; then
        target=$(cat "$f" | tr -d '\r\n')
        rm "$f"
        ln -s "$target" "$f"
        echo "  Fixed symlink (common): $f -> $target"
    fi
done

# Fix resolv.conf symlink in common.
if [ -f "$COMMON_EXTRA/etc/resolv.conf" ] && [ ! -L "$COMMON_EXTRA/etc/resolv.conf" ]; then
    target=$(cat "$COMMON_EXTRA/etc/resolv.conf" | tr -d '\r\n')
    rm "$COMMON_EXTRA/etc/resolv.conf"
    ln -s "$target" "$COMMON_EXTRA/etc/resolv.conf"
    echo "  Fixed symlink (common): resolv.conf -> $target"
fi

# Fix symlinks in Enclave OS overlay.
cd "$EXTRA_DIR/etc/systemd/system"
for f in local-fs.target.wants/data.mount \
         local-fs.target.wants/home.mount \
         local-fs.target.wants/luks-data.service \
         multi-user.target.wants/containerd.service \
         multi-user.target.wants/manager.service \
         multi-user.target.wants/caddy.service \
         multi-user.target.wants/container-volumes.service; do
    if [ -f "$f" ] && [ ! -L "$f" ]; then
        target=$(cat "$f" | tr -d '\r\n')
        rm "$f"
        ln -s "$target" "$f"
        echo "  Fixed symlink: $f -> $target"
    fi
done

# Fix GPU-specific symlinks (in cvm-images overlay).
if [ "$GPU_VARIANT" = true ] && [ -d "$CVM_IMAGES_DIR/images/tdx-gpu/mkosi.extra" ]; then
    GPU_WANTS="$CVM_IMAGES_DIR/images/tdx-gpu/mkosi.extra/etc/systemd/system/multi-user.target.wants"
    if [ -d "$GPU_WANTS" ]; then
        cd "$GPU_WANTS"
        for f in nvidia-persistenced.service; do
            if [ -f "$f" ] && [ ! -L "$f" ]; then
                target=$(cat "$f" | tr -d '\r\n')
                rm "$f"
                ln -s "$target" "$f"
                echo "  Fixed symlink: $f -> $target"
            fi
        done
    fi
fi
cd "$IMAGE_DIR"

# Step 5: Build the disk image with mkosi.
echo ""
echo "=== Step 5: Building disk image with mkosi ==="
cd "$IMAGE_DIR"
MKOSI_ARGS=""
if [ -n "$CLOUD_PROFILE" ]; then
    MKOSI_ARGS="--profile $CLOUD_PROFILE"
fi
mkosi $MKOSI_ARGS build

echo ""
echo "=== Build complete ==="
ls -lh "$IMAGE_DIR"/enclave-os-virtual*.raw 2>/dev/null || echo "(No .raw file found - check mkosi output above)"
