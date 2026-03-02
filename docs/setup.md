# Setup & Configuration

This document covers certificates, OIDC configuration, and all manager
flags needed to deploy an Enclave OS Virtual instance.

## Certificates

### Operations certificate (authentication)

The operations certificate is an ECDSA P-256 keypair used to sign
break-glass JWTs. The **public certificate** is baked into the image; the
**private key** stays offline.

| File | Purpose | Location |
|------|---------|----------|
| `privasys.enclave-os-virtual-operations.crt` | Public cert (in image) | `/etc/enclave-os/operations.crt` |
| `privasys.enclave-os-virtual-operations.key` | Private key (offline) | Operator workstation only |

- **Algorithm**: ECDSA P-256 (ES256)
- **CN**: `Enclave OS (Virtual) Operations`
- **Usage**: Signs short-lived JWTs for bootstrap and break-glass access
- **Trust model**: Hardcoded in the image — cannot be rotated at runtime

### Instance certificate (TLS)

The instance certificate secures the HTTPS listener. Each enclave instance
presents this certificate to clients.

| File | Purpose | Location |
|------|---------|----------|
| `privasys.enclave-os-virtual-instance.crt` | Server certificate | `/run/manager/tls/server.pem` |
| `privasys.enclave-os-virtual-instance.key` | Server private key | `/run/manager/tls/server-key.pem` |
| `privasys.intermediate-ca.crt` | Issuing CA | `/run/manager/tls/ca.pem` |

- **SAN**: `*.inst.privasys.org` — each instance is addressed as
  `<instance-id>.inst.privasys.org`
- **Issuer**: Privasys Intermediate CA
- **Min TLS version**: 1.3
- **Authentication model**: Bearer token over TLS (not mTLS). The
  certificate provides transport encryption; authorization is via the
  `Authorization` header.

### Certificate rotation

The instance certificate baked into the image bootstraps TLS on first boot.
To extend the image lifespan beyond the initial certificate's validity,
rotate via the API:

```
PUT /api/v1/tls
{
  "cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "key": "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----"
}
```

Rotation is atomic — the new cert is validated, persisted to
`/run/manager/tls/`, and hot-swapped into the TLS listener without restart.
Existing connections continue with the old certificate; new connections use
the new one.

Current certificate metadata is available at `GET /api/v1/tls` (monitoring
role). See [api.md](api.md) for full details.

### Certificate summary

```
┌─────────────────────────────────────────────────────────┐
│  Operations cert    → signs JWTs (offline private key)  │
│  Instance cert      → TLS for the HTTPS listener        │
│  Intermediate CA    → issues instance certificates      │
└─────────────────────────────────────────────────────────┘
```

## OIDC configuration

The manager can verify OIDC bearer tokens from any OpenID Connect provider
that publishes a JWKS endpoint.

### Provider setup

1. Create a project `enclave-os-virtual` in your OIDC provider.
2. Add two project roles:
   - `enclave-os-virtual:manager` — for operators who load/unload containers
   - `enclave-os-virtual:monitoring` — for systems that read status/metrics
3. Create an API application with audience `enclave-os-virtual`.
4. Grant the appropriate role to users or service accounts.

### Role definitions

| Role | Claim value | Capabilities |
|------|-------------|-------------|
| Manager | `enclave-os-virtual:manager` | Load/unload containers, view status, view metrics |
| Monitoring | `enclave-os-virtual:monitoring` | View readyz, status, metrics |

Manager access implies monitoring access. Operations certificate JWTs always
have implicit manager access.

### Role claim locations

The manager checks three claim paths to support different providers:

| Provider | Claim path | Format |
|----------|-----------|--------|
| Role-claim map | `urn:zitadel:iam:org:project:roles` | `{ "role-name": { "orgId": "..." } }` |
| Standard | `roles` | `["role-name", ...]` |
| Keycloak | `realm_access.roles` | `["role-name", ...]` |

### Containers claim (optional policy)

Both operations JWTs and OIDC tokens can carry an optional `containers`
claim to restrict which containers the bearer may load or unload:

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

All flags are passed to `manager serve`:

| Flag | Default | Description |
|------|---------|-------------|
| `--operations-cert` | `/etc/enclave-os/operations.crt` | Path to operations certificate PEM |
| `--ca-cert` | — | CA certificate for platform attestation |
| `--ca-key` | — | Intermediary CA private key for RA-TLS |
| `--attestation-backend` | `tdx` | TEE backend: `tdx` or `sev-snp` |
| `--containerd-socket` | `/run/containerd/containerd.sock` | containerd socket path |
| `--agent-addr` | `:9443` | Management API listen address |
| `--agent-tls-cert` | — | Server TLS certificate PEM |
| `--agent-tls-key` | — | Server TLS private key PEM |
| `--agent-ca-cert` | — | CA cert PEM (enables mTLS if set) |
| `--caddy-admin` | `localhost:2019` | Caddy admin API address |
| `--caddy-listen` | `:443` | External HTTPS listen address for Caddy |
| `--extensions-dir` | `/run/manager/extensions` | Per-hostname RA-TLS OID extension files |
| `--platform-hostname` | — | Management API hostname for RA-TLS route |
| `--dek-origin-file` | `/run/luks/dek-origin` | DEK origin string (`"external"` or `"enclave-generated"`, written by `luks-setup`) |
| `--oidc-issuer` | — | OIDC issuer URL (e.g. `https://auth.privasys.org`) |
| `--oidc-audience` | `enclave-os-virtual` | Expected `aud` claim |
| `--oidc-manager-role` | `enclave-os-virtual:manager` | Role for mutating operations |
| `--oidc-monitoring-role` | `enclave-os-virtual:monitoring` | Role for read-only access |
| `--oidc-role-claim` | `urn:zitadel:iam:org:project:roles` | JWT claim key containing roles |
| `--log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |

## systemd unit

The production configuration in `manager.service`:

```ini
ExecStart=/usr/bin/manager serve \
    --operations-cert /etc/enclave-os/operations.crt \
    --attestation-backend tdx \
    --agent-addr :9443 \
    --agent-tls-cert /run/manager/tls/server.pem \
    --agent-tls-key /run/manager/tls/server-key.pem \
    --agent-ca-cert /run/manager/tls/ca.pem \
    --ca-cert /etc/enclave-os/tls/ca.pem \
    --ca-key /etc/enclave-os/tls/ca-key.pem \
    --caddy-admin localhost:2019 \
    --caddy-listen :443 \
    --extensions-dir /run/manager/extensions \
    --platform-hostname mgmt.inst.privasys.org \
    --dek-origin-file /run/luks/dek-origin \
    --oidc-issuer https://auth.privasys.org \
    --oidc-audience enclave-os-virtual \
    --oidc-manager-role enclave-os-virtual:manager \
    --oidc-monitoring-role enclave-os-virtual:monitoring \
    --log-level info
```

## File layout (on image)

```
/etc/enclave-os/
    operations.crt          ← baked at build time (read-only rootfs)
    tls/
        ca.pem              ← intermediary CA certificate (RA-TLS)
        ca-key.pem          ← intermediary CA private key (RA-TLS)

/run/manager/tls/           ← RuntimeDirectory, created by systemd
    server.pem              ← instance TLS cert (management API)
    server-key.pem          ← instance TLS key
    ca.pem                  ← intermediate CA

/run/manager/extensions/    ← RuntimeDirectory, created by launcher
    <hostname>.json         ← per-hostname OID extensions for ra-tls-caddy

/usr/bin/manager            ← static binary
/usr/bin/caddy              ← Caddy with ra-tls-caddy module
/usr/bin/luks-setup         ← LUKS data partition setup script
```

## Data-at-rest encryption (LUKS)

The data partition is LUKS2-encrypted at every boot. Key provisioning:

| Mode | Source | Mechanism |
|------|--------|-----------|
| **BYOK** | Operator passphrase | Passed via instance metadata (e.g. `luks-passphrase` attribute) |
| **Auto-generated** | Random 256-bit | Generated at first boot if no external key is provided |

### Boot sequence

1. `luks-data.service` runs (Before `data.mount`)
2. Reads passphrase from instance metadata or generates one
3. First boot: `cryptsetup luksFormat` + `mkfs.ext4`; subsequent boots: `cryptsetup luksOpen`
4. Writes key origin (`"external"` or `"enclave-generated"`) to `/run/luks/dek-origin`
5. `data.mount` mounts `/dev/mapper/data-crypt`
6. `manager.service` reads `/run/luks/dek-origin` → publishes as OID `1.3.6.1.4.1.65230.2.6`

### Deploying with BYOK

Pass the LUKS passphrase via your cloud provider's instance metadata mechanism. Example (GCP):

```bash
gcloud compute instances create my-instance \
    --confidential-compute-type=TDX \
    --metadata=luks-passphrase=YOUR_SECRET_PASSPHRASE \
    ...
```

For Azure or AWS, set the `luks-passphrase` attribute in the equivalent metadata service.
