# Sourced by mkosi.postinst.chroot (both images, every profile).
#
# Instance metadata is input from outside the measurement: whoever controls
# the VM (the cloud project, or the host on bare metal, which answers
# 169.254.169.254 itself) sets it. An Enclave OS image never runs it as code
# and never lets it create accounts. Nothing the image needs comes from the
# GCE guest agent (addresses come from systemd-networkd's DHCP, the machine
# name from instance-hostname.service, the check-in from
# enclave-checkin.service), while the agent creates users from metadata
# ssh-keys and its plugin manager can run more: so it is masked outright,
# with its script runner and OS Login.
#
# Masks and removals, then a FATAL check so a later package pull cannot bring
# any of it back (as R14 does for sshd).

for unit in google-guest-agent.service google-guest-agent-manager.service \
            google-startup-scripts.service google-shutdown-scripts.service \
            google-oslogin-cache.service google-oslogin-cache.timer; do
    systemctl mask "$unit" 2>/dev/null || true
done
rm -f /usr/bin/google_metadata_script_runner /usr/bin/gce_compat_metadata_script_runner \
      /usr/bin/google_guest_agent_manager

# The agent reads /etc/default/instance_configs.cfg over its packaged
# defaults: no accounts from metadata, no OS Login, no metadata scripts.
mkdir -p /etc/default
cat > /etc/default/instance_configs.cfg <<'CFG'
[Daemons]
accounts_daemon = false
clock_skew_daemon = false

[Accounts]
deprovision_remove = false

[MetadataScripts]
startup = false
shutdown = false
run_dir = /nonexistent

[OSLogin]
cert_authentication = false

[InstanceSetup]
set_host_keys = false
CFG

for unit in google-guest-agent.service google-guest-agent-manager.service \
            google-startup-scripts.service google-shutdown-scripts.service google-oslogin-cache.timer; do
    if [ -e "/usr/lib/systemd/system/$unit" ] && [ "$(readlink -f "/etc/systemd/system/$unit" 2>/dev/null)" != "/dev/null" ]; then
        echo "FATAL: $unit is not masked in the image" >&2
        exit 1
    fi
done
if [ -e /usr/bin/google_metadata_script_runner ] || [ -e /usr/bin/google_guest_agent_manager ]; then
    echo "FATAL: a metadata script runner or the agent's plugin manager is still in the image" >&2
    exit 1
fi
echo "metadata never runs as code: guest agent, script runner and OS Login masked (profile ${profile:-unknown})"
