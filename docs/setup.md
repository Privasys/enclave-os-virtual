# Setup & Configuration

This document covers certificates, OIDC configuration, and all manager
flags needed to deploy an Enclave OS (Virtual) instance.

## Certificates

### Intermediary CA (RA-TLS)

The intermediary CA certificate and private key are baked into the image
and used by Caddy (via its RA-TLS module) to issue per-hostname RA-TLS leaf
certificates.

| File | Purpose | Location |
|------|---------|----------|
| `ca.crt` | CA certificate | `/data/ca.crt` (configurable via `CA_CERT`) |
| `ca.key` | CA private key | `/data/ca.key` (configurable via `CA_KEY`) |

- **Algorithm**: ECDSA P-256
- **Trust model**: The CA key never leaves the VM — it exists only in
  TEE-encrypted memory and on the LUKS-encrypted data partition.
- **Leaf certificates**: Generated dynamically by the RA-TLS module for each
  TLS connection (challenge-response mode) or cached up to 24h
  (deterministic mode). Each leaf embeds the TDX/SEV-SNP quote and
  Privasys OID extensions.

### RA-TLS leaf certificates

Caddy automatically generates a fresh RA-TLS leaf certificate per hostname.
No manually provisioned TLS certificates are needed:

- **Management API**: `manager.<machine-name>.<hostname>`
- **Per-container**: `<name>.<machine-name>.<hostname>`

All certificates embed hardware attestation quotes and Privasys OID
extensions. See [ra-tls.md](ra-tls.md) for details.

## OIDC configuration

The manager can verify OIDC bearer tokens from any OpenID Connect provider
that publishes a JWKS endpoint.

### Provider setup

1. Create a project `enclave-os-virtual` in your OIDC provider.
2. Add two project roles:
   - `privasys-platform:manager` — for operators who load/unload containers
   - `privasys-platform:monitoring` — for systems that read status/metrics
3. Create an API application with audience `enclave-os-virtual`.
4. Grant the appropriate role to users or service accounts.

### Role definitions

| Role | Claim value | Capabilities |
|------|-------------|-------------|
| Manager | `privasys-platform:manager` | Load/unload containers, view status, view metrics |
| Monitoring | `privasys-platform:monitoring` | View readyz, status, metrics |

Manager access implies monitoring access.

### Role claim locations

The manager checks three claim paths to support different providers:

| Provider | Claim path | Format |
|----------|-----------|--------|
| Role-claim map | `urn:zitadel:iam:org:project:roles` | `{ "role-name": { "orgId": "..." } }` |
| Standard | `roles` | `["role-name", ...]` |
| Keycloak | `realm_access.roles` | `["role-name", ...]` |

### Containers claim (optional policy)

OIDC tokens can carry an optional `containers` claim to restrict which
containers the bearer may load or unload:

```json
{
  "containers": [
    { "name": "myapp", "digest": "sha256:abc123..." },
    { "name": "postgres", "digest": "sha256:def456..." }
  ]
}
```

If the claim is omitted, all containers are permitted.

## Manager flags

All flags are passed to `manager serve`. Flags marked **required** must be
provided — the manager will refuse to start without them.

| Flag | Default | Description |
|------|---------|-------------|
| `--ca-cert` | — | **Required.** CA certificate for RA-TLS |
| `--ca-key` | — | **Required.** Intermediary CA private key for RA-TLS |
| `--oidc-issuer` | — | **Required.** OIDC issuer URL (e.g. `https://auth.example.com`) |
| `--machine-name` | — | Machine name for this instance (e.g. `prod1`); determines all RA-TLS hostnames |
| `--hostname` | — | **Required.** Hostname suffix appended to the machine name (e.g. `example.com`) |
| `--attestation-servers` | — | Comma-separated list of attestation server URLs (e.g. `https://as1.example.com,https://as2.example.com`) |
| `--containerd-socket` | `/run/containerd/containerd.sock` | containerd socket path |
| `--caddy-listen` | `:443` | External HTTPS listen address for Caddy |
| `--extensions-dir` | `/run/manager/extensions` | Per-hostname RA-TLS OID extension files |
| `--dek-origin-file` | `/run/luks/dek-origin` | DEK origin string (`"external"` or `"enclave-generated"`, written by `luks-setup`) |
| `--oidc-audience` | `enclave-os-virtual` | Expected `aud` claim |
| `--oidc-manager-role` | `privasys-platform:manager` | Role for mutating operations |
| `--oidc-monitoring-role` | `privasys-platform:monitoring` | Role for read-only access |
| `--oidc-role-claim` | `urn:zitadel:iam:org:project:roles` | JWT claim key containing roles |
| `--log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |

### Hostname derivation

All RA-TLS hostnames are derived automatically from `--machine-name` and
`--hostname`:

| Scope | Pattern | Example (`--machine-name prod1 --hostname example.com`) |
|-------|---------|----------------------------------------------------------|
| Management API | `manager.<machine-name>.<hostname>` | `manager.prod1.example.com` |
| Container | `<name>.<machine-name>.<hostname>` | `registry.prod1.example.com` |

Containers marked `"internal": true` do not receive an external hostname or
RA-TLS certificate.

The `--machine-name` value in the systemd unit defaults to `%H` (the kernel
hostname), which on GCP equals the instance name.

## systemd unit

The production configuration in `manager.service` reads instance-specific
values from `/data/manager.env` (on the LUKS-encrypted data partition):

```ini
# /data/manager.env — created by the operator on first boot
OIDC_ISSUER=https://auth.example.com
HOSTNAME_SUFFIX=example.com
# CA_CERT=/data/ca.crt        # default; override if needed
# CA_KEY=/data/ca.key          # default; override if needed
```

```ini
EnvironmentFile=-/data/manager.env
ExecStart=/usr/bin/manager serve \
    --attestation-servers ${ATTESTATION_SERVERS} \
    --ca-cert ${CA_CERT:-/data/ca.crt} \
    --ca-key ${CA_KEY:-/data/ca.key} \
    --caddy-listen :443 \
    --extensions-dir /run/manager/extensions \
    --machine-name %H \
    --hostname ${HOSTNAME_SUFFIX} \
    --dek-origin-file /run/luks/dek-origin \
    --oidc-issuer ${OIDC_ISSUER} \
    --oidc-audience ${OIDC_AUDIENCE:-enclave-os-virtual} \
    --oidc-manager-role ${OIDC_MANAGER_ROLE:-privasys-platform:manager} \
    --oidc-monitoring-role ${OIDC_MONITORING_ROLE:-privasys-platform:monitoring} \
    --log-level info
```

The `-` prefix on `EnvironmentFile` means systemd won't fail if the file
is missing — but the manager will exit with an error because `--oidc-issuer`
and `--hostname` are required.

## File layout (on image)

```
/data/                          ← OS data partition (2 GB, LUKS2+AEAD)
    ca.crt                      ← intermediary CA certificate (RA-TLS)
    ca.key                      ← intermediary CA private key (RA-TLS)
    manager.env                 ← instance-specific configuration

/run/containers/<name>/         ← per-container encrypted volume (LVM + LUKS2+AEAD)

/run/manager/extensions/        ← RuntimeDirectory, created by launcher
    <hostname>.json             ← per-hostname OID extensions for the RA-TLS module

/usr/bin/manager                ← static binary
/usr/bin/caddy                  ← Caddy with RA-TLS module
/usr/bin/luks-setup             ← LUKS data partition setup script
```

## Data-at-rest encryption (LUKS)

All data-at-rest is LUKS2-encrypted with authenticated encryption (AEAD). The `--integrity aead` flag enables dm-integrity under LUKS, providing both confidentiality and per-sector integrity protection — any tampering with ciphertext is detected.

The disk has two encrypted regions:

| Partition | Label | Size | Purpose |
|-----------|-------|------|---------|
| OS data | `data` | 2 GB fixed | Platform config: ca.crt, ca.key, manager.env |
| Container volumes | `containers` | Remaining disk | LVM PV → per-container LVs, each LUKS2+AEAD |

### OS data partition

| Mode | Source | Mechanism |
|------|--------|-----------|
| **BYOK** | Operator passphrase | Passed via instance metadata (e.g. `luks-passphrase` attribute) |

BYOK is the only supported mode today. The script fails hard if no
passphrase is found in instance metadata. Auto-generated random keys
are not supported because they would brick the partition on the next
reboot. A Vaults-backed flow (generate inside the TEE, seal to
attestation evidence, fetch on restart) will be added once Enclave
Vaults ships.

**Boot sequence:**

1. `luks-data.service` runs (Before `data.mount`)
2. Reads passphrase from instance metadata (fails hard if absent)
3. First boot: `cryptsetup luksFormat --integrity aead` + `mkfs.ext4`; subsequent boots: `cryptsetup luksOpen`
4. Writes key origin (`"byok:<fingerprint>"`) to `/run/luks/dek-origin`
5. `data.mount` mounts `/dev/mapper/data-crypt`
6. `manager.service` reads `/run/luks/dek-origin` -> publishes as OID `1.3.6.1.4.1.65230.2.6`

### Per-container encrypted volumes

Each container receives an independent LVM logical volume on the `containers` partition, encrypted with its own LUKS2+AEAD key. Keys are never shared between containers and never stored on the OS data partition — held only in TEE-encrypted memory.

| Key source | Mechanism |
|------------|-----------|
| **BYOK** | Per-container key provided in the `POST /api/v1/containers` request |
| **Enclave Vaults** | Key fetched from the vault constellation via mutual RA-TLS |

**Container load flow:**

1. `lvcreate` allocates an LV on `vg-containers`
2. `cryptsetup luksFormat --integrity aead` with per-container key
3. `cryptsetup luksOpen` → `mkfs.ext4` → mount at `/run/containers/<name>`
4. Volume bind-mounted into the container
5. On unload: unmount → `luksClose` → `lvremove` (or keep for persistent data)

### Deploying with BYOK

Pass the OS data passphrase via your cloud provider's instance metadata mechanism. Example (GCP):

```bash
gcloud compute instances create my-instance \
    --confidential-compute-type=TDX \
    --metadata=luks-passphrase=YOUR_SECRET_PASSPHRASE \
    ...
```

For Azure or AWS, set the `luks-passphrase` attribute in the equivalent metadata service.

### Choosing the disk size

The OS image (ESP + root + verity + OS data) uses ~4 GB. The container volumes partition fills remaining space, so usable container storage is roughly `disk_size - 4 GB`.

**Set the disk size at instance creation time** — for example, `--create-disk=size=50` gives ~46 GB of per-container encrypted storage. The minimum disk size is 12 GB (8 GB container volumes minimum).

> **Online resize is not supported.** LUKS with `--integrity aead` uses dm-integrity underneath, which cannot be grown in place. To increase storage, create a new instance with a larger disk and migrate the data.
