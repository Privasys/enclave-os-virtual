#!/bin/bash
set -euo pipefail

echo "=== Pulling latest code ==="
cd /tmp/enclave-os-virtual
git pull origin main

echo "=== Building Go binary ==="
cd /tmp/enclave-os-virtual
go mod tidy
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-s -w' -o build/image/mkosi.extra/usr/bin/manager ./cmd/manager/

echo "=== Fixing symlinks ==="
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

echo "=== Ensuring signed boot packages on build host ==="
sudo apt-get install -y --no-install-recommends grub-efi-amd64-signed shim-signed

echo "=== Cleaning old build ==="
sudo rm -rf /tmp/enclave-os-virtual/build/image/mkosi.builddir
sudo rm -f /tmp/enclave-os-virtual/build/image/enclave-os-virtual_*
sudo rm -f /tmp/enclave-os-virtual/build/image/initrd.cpio.zst

echo "=== Building image with mkosi ==="
cd /tmp/enclave-os-virtual/build/image
sudo mkosi build

echo "=== Replacing unsigned GRUB with Canonical-signed binary ==="
# mkosi's ShimBootloader=signed correctly installs the Microsoft-signed shim
# (BOOTX64.EFI) but still runs grub-mkimage for grubx64.EFI, producing an
# unsigned binary.  Replace it with the distro-signed copy.
RAW=$(ls /tmp/enclave-os-virtual/build/image/enclave-os-virtual_*.raw)
LOOPDEV=$(sudo losetup --find --show --partscan "$RAW")
sudo mkdir -p /mnt/esp
sudo mount "${LOOPDEV}p1" /mnt/esp
sudo cp /usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed /mnt/esp/EFI/BOOT/grubx64.EFI
echo "Installed signed GRUB:"
sudo sbverify --list /mnt/esp/EFI/BOOT/grubx64.EFI 2>&1 | head -5
sudo umount /mnt/esp
sudo losetup -d "$LOOPDEV"

echo "=== Build complete ==="
ls -lh /tmp/enclave-os-virtual/build/image/enclave-os-virtual_*.raw 2>/dev/null || echo "No .raw file found"
