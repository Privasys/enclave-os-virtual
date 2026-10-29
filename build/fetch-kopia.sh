#!/usr/bin/env bash
# Fetch the kopia release baked into the image (content backup of container
# volumes: the manager runs it against a read-only snapshot of an opened volume
# and ships encrypted, deduplicated chunks to S3-compatible object storage).
#
# Pinned by version AND release checksum, so the measured rootfs only ever
# carries this exact binary. Bump both together, from the release's
# checksums.txt. Installs into the shared extra tree, which the GPU image
# includes as well.
#
# Usage: build/fetch-kopia.sh <mkosi.extra dir>
set -euo pipefail

KOPIA_VERSION="${KOPIA_VERSION:-0.23.1}"
KOPIA_SHA256="${KOPIA_SHA256:-416d0f84a3dbb321a8b2d8f0997b1a0a6e915babe79ee76fa6e4d2bd1e1c5178}"

EXTRA_DIR="${1:?usage: fetch-kopia.sh <mkosi.extra dir>}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fsSL -o "$TMP/kopia.tar.gz" \
    "https://github.com/kopia/kopia/releases/download/v${KOPIA_VERSION}/kopia-${KOPIA_VERSION}-linux-x64.tar.gz"
echo "${KOPIA_SHA256}  $TMP/kopia.tar.gz" | sha256sum -c -
tar -xzf "$TMP/kopia.tar.gz" -C "$TMP"
mkdir -p "$EXTRA_DIR/usr/bin"
install -m 0755 "$TMP/kopia-${KOPIA_VERSION}-linux-x64/kopia" "$EXTRA_DIR/usr/bin/kopia"
echo "kopia $KOPIA_VERSION installed: $EXTRA_DIR/usr/bin/kopia"
