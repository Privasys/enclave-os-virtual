#!/bin/bash
# Build a patched Ubuntu kernel with the CVM guard (BadAML mitigation).
#
# Produces .deb files in build/kernel/debs/ that mkosi installs via
# PackageDirectories.  The image's mkosi.conf references the custom
# package name (linux-image-*-generic+privasys) instead of the stock
# linux-image-gcp / linux-image-generic-hwe-24.04.
#
# This script is called automatically by build.sh when the .debs do
# not already exist, or can be run standalone.
#
# Requirements: Ubuntu 24.04 build host, ~20 GB disk, root privileges.
#
# Usage:
#   sudo ./build/kernel/build-kernel.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PATCH_DIR="$SCRIPT_DIR/patches"
OUTPUT_DIR="$SCRIPT_DIR/debs"
BUILD_DIR="/tmp/privasys-kernel-build-$$"
JOBS="$(nproc)"

echo "=== Privasys Kernel Builder (CVM guard) ==="
echo "Patches:    $PATCH_DIR"
echo "Output:     $OUTPUT_DIR"
echo "Scratch:    $BUILD_DIR"
echo "Parallel:   $JOBS"

cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

# ── Step 0: Build dependencies ──
echo ""
echo "=== Installing build dependencies ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
    build-essential fakeroot dpkg-dev \
    libncurses-dev flex bison libssl-dev libelf-dev \
    bc dwarves debhelper rsync cpio kmod \
    python3 python3-dev 2>/dev/null || true

# ── Step 1: Identify the HWE kernel version ──
echo ""
echo "=== Resolving kernel version ==="
KERNEL_META="linux-image-generic-hwe-24.04"
KERNEL_PKG=$(apt-cache depends "$KERNEL_META" 2>/dev/null \
    | grep -oP 'linux-image-unsigned-\d[\d.]+\d-\d+-generic' | head -1 || true)
if [ -z "$KERNEL_PKG" ]; then
    KERNEL_PKG=$(apt-cache depends "$KERNEL_META" 2>/dev/null \
        | grep -oP 'linux-image-\d[\d.]+\d-\d+-generic' | head -1 || true)
fi
if [ -z "$KERNEL_PKG" ]; then
    echo "ERROR: cannot resolve $KERNEL_META"
    exit 1
fi

KVER=$(echo "$KERNEL_PKG" | grep -oP '\d+\.\d+\.\d+-\d+')
KMAJMIN=$(echo "$KVER" | grep -oP '^\d+\.\d+')
echo "Target: $KERNEL_PKG  (version $KVER, series $KMAJMIN)"

# ── Step 2: Fetch source ──
echo ""
echo "=== Fetching kernel source ==="
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

SRC_PKG="linux-hwe-${KMAJMIN}"

# Ensure deb-src repos are available.
if ! apt-get source --download-only "$SRC_PKG" 2>/dev/null; then
    echo "Enabling deb-src repositories..."
    sed -i 's/^# deb-src/deb-src/' /etc/apt/sources.list.d/*.list 2>/dev/null || true
    sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/*.sources 2>/dev/null || true
    apt-get update -qq
fi

apt-get source "$SRC_PKG"
apt-get build-dep -y "$SRC_PKG"

SRC_DIR=$(find "$BUILD_DIR" -maxdepth 1 -type d -name "linux-*" ! -name "*.orig" | head -1)
if [ -z "$SRC_DIR" ]; then
    echo "ERROR: source directory not found"
    exit 1
fi
cd "$SRC_DIR"
echo "Source: $SRC_DIR"

# ── Step 3: Apply CVM guard patch ──
echo ""
echo "=== Applying CVM guard patch ==="
PATCH="$PATCH_DIR/0001-acpi-deny-aml-access-to-cvm-private-memory.patch"
[ -f "$PATCH" ] || { echo "ERROR: $PATCH not found"; exit 1; }

EXREGION="drivers/acpi/acpica/exregion.c"
GUARD_H="drivers/acpi/acpica/cvm_guard.h"

if patch -p1 --dry-run < "$PATCH" >/dev/null 2>&1; then
    patch -p1 < "$PATCH"
    echo "Applied with patch -p1"
else
    echo "Context mismatch, applying manually..."

    # Extract cvm_guard.h content from the patch file.
    awk '
        /^diff --git.*cvm_guard\.h/{found=1; next}
        found && /^diff --git/{exit}
        found && /^\+[^+]/{sub(/^\+/,""); print}
    ' "$PATCH" > "$GUARD_H"
    [ -s "$GUARD_H" ] || { echo "ERROR: failed to extract cvm_guard.h"; exit 1; }
    echo "Created $GUARD_H ($(wc -l < "$GUARD_H") lines)"

    # Insert #include after ACPI_MODULE_NAME.
    sed -i '/^ACPI_MODULE_NAME("exregion")/a\\n#include "cvm_guard.h"' "$EXREGION"

    # Insert guard call after the logical_addr_ptr calculation.
    sed -i '/((u64) address - (u64) mm->physical_address);/{
        n
        /^$/a\\tif (cvm_guard_deny_aml_access((unsigned long)logical_addr_ptr))\n\t\treturn_ACPI_STATUS(AE_AML_ILLEGAL_ADDRESS);
    }' "$EXREGION"

    echo "Patched $EXREGION"
fi

# Verify.
grep -q "cvm_guard" "$EXREGION" || { echo "ERROR: verification failed"; exit 1; }
[ -f "$GUARD_H" ] || { echo "ERROR: cvm_guard.h missing"; exit 1; }
echo "Patch verified"

# ── Step 4: Mark as Privasys build ──
echo ""
echo "=== Updating version ==="
CHANGELOG=$(find . -maxdepth 2 -name changelog -path "*/debian*/changelog" | head -1)
if [ -n "$CHANGELOG" ]; then
    sed -i "1s/)/+privasys)/" "$CHANGELOG"
    head -1 "$CHANGELOG"
fi

# ── Step 5: Build ──
echo ""
echo "=== Building kernel .deb packages ==="
KBUILD_LOG="$BUILD_DIR/build.log"
if [ -f "debian/rules" ]; then
    chmod a+x debian/rules
    echo "Running: fakeroot debian/rules clean ..."
    fakeroot debian/rules clean > "$KBUILD_LOG" 2>&1 || true
    tail -5 "$KBUILD_LOG"
    echo "Running: fakeroot debian/rules binary-headers binary-generic binary-perarch ..."
    if ! fakeroot debian/rules binary-headers binary-generic binary-perarch \
        >> "$KBUILD_LOG" 2>&1; then
        echo "binary-* targets failed, trying dpkg-buildpackage..."
        tail -20 "$KBUILD_LOG"
        dpkg-buildpackage -b -uc -us -j"$JOBS" >> "$KBUILD_LOG" 2>&1
    fi
    tail -10 "$KBUILD_LOG"
else
    make olddefconfig > "$KBUILD_LOG" 2>&1
    make -j"$JOBS" bindeb-pkg LOCALVERSION=+privasys >> "$KBUILD_LOG" 2>&1
    tail -10 "$KBUILD_LOG"
fi

# ── Step 6: Collect .debs ──
echo ""
echo "=== Collecting output ==="
mkdir -p "$OUTPUT_DIR"
N=0
for d in "$BUILD_DIR" "$(dirname "$SRC_DIR")"; do
    for deb in "$d"/linux-image-*.deb "$d"/linux-headers-*.deb "$d"/linux-modules-*.deb; do
        [ -f "$deb" ] || continue
        cp -v "$deb" "$OUTPUT_DIR/"
        N=$((N + 1))
    done
done

if [ "$N" -eq 0 ]; then
    echo "ERROR: no .deb files produced"
    find "$BUILD_DIR" -name "*.deb" -ls
    exit 1
fi

echo ""
echo "=== Done: $N .deb files in $OUTPUT_DIR ==="
ls -lh "$OUTPUT_DIR"/*.deb
