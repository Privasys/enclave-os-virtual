#!/bin/bash
set -euo pipefail

cd /tmp/enclave-os-virtual/build/image/mkosi.extra/etc/systemd/system

for f in \
  local-fs.target.wants/data.mount \
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
    echo "Fixed: $f -> $target"
  fi
done

cd /tmp/enclave-os-virtual/build/image
f="mkosi.extra/etc/resolv.conf"
if [ -f "$f" ] && [ ! -L "$f" ]; then
  target=$(cat "$f" | tr -d '\r\n')
  rm "$f"
  ln -s "$target" "$f"
  echo "Fixed: $f -> $target"
fi

echo "=== Building image with mkosi ==="
cd /tmp/enclave-os-virtual/build/image
sudo mkosi build

echo "=== Build complete ==="
ls -lh /tmp/enclave-os-virtual/build/image/enclave-os-virtual_*.raw 2>/dev/null || echo "No .raw file found"
