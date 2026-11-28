# Sourced by both images' mkosi.postinst.chroot, every profile: what an
# Enclave OS image is, whatever it runs. A step that cannot be made fails the
# build.

profile=$(cat /etc/privasys/image-profile 2>/dev/null || echo unknown)

# A production image ships no sshd. The gcp profile's google-compute-engine
# package pulls openssh-server in after the base image's no-sshd check, so
# it is removed here; only a proven "production" marker triggers it (the dev
# profile installs and keeps openssh).
if [ "$profile" = "production" ]; then
    rm -f /usr/sbin/sshd
    systemctl mask ssh.service ssh.socket sshd.service 2>/dev/null || true
    if [ -e /usr/sbin/sshd ]; then
        echo "FATAL: sshd still present in production image" >&2
        exit 1
    fi
    echo "production profile: sshd binary removed and units masked"
fi

# Instance metadata never runs as code: it is set by whoever controls the VM
# (on bare metal, the host itself), outside the measurement. What the image
# needs from it, it reads as data in measured units.
. /usr/lib/enclave-os/strip-metadata-exec.sh
systemctl enable instance-hostname.service enclave-checkin.service

# The data device appears only once luks-data.service has finished, which on
# a first boot includes the LUKS2 + dm-integrity format (about a minute per
# 13 GB) and the vault-backed key: the device unit waits up to 15 minutes,
# not systemd's default 90 s (a mount unit cannot carry
# x-systemd.device-timeout, so the drop-in is on the device). Bounded, so a
# failed luks-setup still lets the boot reach multi-user. Data disks beyond
# about 200 GB need more. Written here because the escaped unit name has a
# backslash, which a Windows checkout of mkosi.extra cannot hold.
mkdir -p '/usr/lib/systemd/system/dev-mapper-data\x2dcrypt.device.d'
cat > '/usr/lib/systemd/system/dev-mapper-data\x2dcrypt.device.d/50-luks-format-timeout.conf' <<'DROPIN'
[Unit]
JobRunningTimeoutSec=15min
DROPIN
echo "data-crypt device timeout drop-in installed"

# The guest clock is kept from NTS (etc/chrony/chrony.conf).
systemctl enable chrony.service
