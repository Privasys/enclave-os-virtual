# Sourced by mkosi.postinst.chroot (both images, every profile).
#
# Instance metadata is input from outside the measurement: whoever controls
# the VM (the cloud project, or the host on bare metal, which answers
# 169.254.169.254 itself) sets it. An Enclave OS image never runs it as code
# and never lets it create accounts. Nothing the image needs comes from the
# GCE guest environment (addresses come from systemd-networkd's DHCP, the
# machine name from instance-hostname.service, the check-in from
# enclave-checkin.service, the google-* disk names from the udev rules the
# gcp profile vendors), while the guest agent creates users from metadata
# ssh-keys and its plugin manager can run more. So the image ships none of
# it: no google-guest-agent, no OS Login, no google-compute-engine, no
# metadata script runner.
#
# The gcp profile no longer installs those packages; this check fails the
# build if a later package pull brings any of them back (as R14 does for
# sshd).

for pkg in google-guest-agent google-compute-engine google-compute-engine-oslogin; do
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
        echo "FATAL: package $pkg is in the image" >&2
        exit 1
    fi
done
for unit in google-guest-agent.service google-guest-agent-manager.service \
            google-startup-scripts.service google-shutdown-scripts.service \
            google-oslogin-cache.service google-oslogin-cache.timer; do
    if [ -e "/usr/lib/systemd/system/$unit" ] || [ -e "/lib/systemd/system/$unit" ]; then
        echo "FATAL: $unit is in the image" >&2
        exit 1
    fi
done
for bin in google_metadata_script_runner gce_compat_metadata_script_runner \
           google_guest_agent google_guest_agent_manager google_authorized_keys; do
    if [ -e "/usr/bin/$bin" ]; then
        echo "FATAL: /usr/bin/$bin is in the image" >&2
        exit 1
    fi
done
echo "metadata never runs as code: no guest agent, script runner or OS Login in the image (profile ${profile:-unknown})"
