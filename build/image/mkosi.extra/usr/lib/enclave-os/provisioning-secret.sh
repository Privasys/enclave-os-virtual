#!/bin/bash
# provisioning-secret.sh — shell library for fetching boot-time secrets
# delivered out of band by the operator (or cloud control plane).
#
# Source this file from a service script:
#
#   source /usr/lib/enclave-os/provisioning-secret.sh
#   key=$(read_provisioning_secret bootstrap-service-key) || exit 1
#
# Probe order (first hit wins):
#   1. systemd-creds  — $CREDENTIALS_DIRECTORY/<name>
#                       Used on bare-metal QEMU (OVH) where the host
#                       passes the secret via -fw_cfg or -smbios type=11
#                       and systemd's ImportCredential= dir-mounts it.
#   2. GCP metadata   — instance attribute <name>
#   3. AWS IMDSv2     — instance tag <name>
#   4. Azure metadata — compute tag <name>
#
# All steps require curl (and jq for Azure). No external state is
# written — output is plain stdout, secret stays in the caller's shell
# variable.

read_provisioning_secret() {
    local name="$1"
    if [ -z "$name" ]; then
        echo "read_provisioning_secret: name is required" >&2
        return 2
    fi

    local val=""

    # ── 1. systemd-creds (preferred for bare-metal QEMU / OVH) ─────────
    if [ -n "${CREDENTIALS_DIRECTORY:-}" ] && [ -r "${CREDENTIALS_DIRECTORY}/${name}" ]; then
        # systemd-creds writes binary blobs verbatim; trim trailing
        # newline only if the value is plain text. Operators that need
        # binary should consume $CREDENTIALS_DIRECTORY/$name directly.
        val=$(cat "${CREDENTIALS_DIRECTORY}/${name}" | tr -d '\r')
        if [ -n "$val" ]; then printf '%s' "$val"; return 0; fi
    fi

    # ── 2. GCP metadata ────────────────────────────────────────────────
    val=$(curl -sf --connect-timeout 2 --max-time 5 \
        -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/${name}" \
        2>/dev/null || true)
    if [ -n "$val" ]; then printf '%s' "$val"; return 0; fi

    # ── 3. AWS IMDSv2 ─────────────────────────────────────────────────
    local token
    token=$(curl -sf --connect-timeout 2 --max-time 5 -X PUT \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 30" \
        "http://169.254.169.254/latest/api/token" 2>/dev/null || true)
    if [ -n "$token" ]; then
        val=$(curl -sf --connect-timeout 2 --max-time 5 \
            -H "X-aws-ec2-metadata-token: $token" \
            "http://169.254.169.254/latest/meta-data/tags/instance/${name}" \
            2>/dev/null || true)
        if [ -n "$val" ]; then printf '%s' "$val"; return 0; fi
    fi

    # ── 4. Azure tagsList ─────────────────────────────────────────────
    if command -v jq >/dev/null 2>&1; then
        val=$(curl -sf --connect-timeout 2 --max-time 5 -H "Metadata: true" \
            "http://169.254.169.254/metadata/instance/compute/tagsList?api-version=2021-02-01" \
            2>/dev/null \
            | jq -r --arg n "$name" '.[] | select(.name==$n) | .value' 2>/dev/null \
            || true)
        if [ -n "$val" ] && [ "$val" != "null" ]; then printf '%s' "$val"; return 0; fi
    fi

    return 1
}

# Convenience wrapper that retries a few times. Useful at early boot
# when networkd / DHCP haven't fully settled.
read_provisioning_secret_retry() {
    local name="$1"
    local attempts="${2:-5}"
    local sleep_s="${3:-2}"
    local i val
    for i in $(seq 1 "$attempts"); do
        if val=$(read_provisioning_secret "$name"); then
            printf '%s' "$val"
            return 0
        fi
        if [ "$i" -lt "$attempts" ]; then
            echo "read_provisioning_secret($name): not yet available (attempt $i/$attempts), retrying" >&2
            sleep "$sleep_s"
        fi
    done
    return 1
}
