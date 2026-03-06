# Enclave OS (Virtual)

**Container workloads inside Confidential VMs, attested end-to-end.**

Enclave OS (Virtual) runs OCI containers inside [Intel TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html) (or AMD SEV-SNP) Confidential VMs. Every container image digest, environment variable, volume mount, and platform configuration is measured into a deterministic Merkle tree and embedded in X.509 certificate extensions via [RA-TLS](https://github.com/Privasys/ra-tls-caddy). Clients can verify the full workload stack in a single TLS handshake — no out-of-band attestation protocol required.

Part of the [Privasys](https://privasys.org) Confidential Computing platform, alongside [Enclave OS (Mini)](https://github.com/Privasys/enclave-os-mini) (SGX/WASM).

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Intel TDX / AMD SEV-SNP Confidential VM                │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Enclave OS (Virtual)                            │   │
│  │                                                  │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  │   │
│  │  │ ra-tls-    │  │ Workload   │  │ Management │  │   │
│  │  │ caddy      │  │ Launcher   │  │ Server     │  │   │
│  │  │ (TLS +     │  │ (containerd│  │ (HTTP on   │  │   │
│  │  │  reverse   │  │  lifecycle)│  │  localhost)│  │   │
│  │  │  proxy)    │  │            │  │            │  │   │
│  │  └─────┬──────┘  └─────┬──────┘  └────────────┘  │   │
│  │        │               │                         │   │
│  │        │    ┌──────────┴──────────┐              │   │
│  │        │    │     containerd      │              │   │
│  │        │    └──────────┬──────────┘              │   │
│  │        │    ┌──────────┴──────────┐              │   │
│  │        └────┤  OCI Containers     │              │   │
│  │             │  ┌─────┐  ┌──────┐  │              │   │
│  │             │  │App  │  │ DB   │  │              │   │
│  │             │  │     │  │      │  │              │   │
│  │             │  └─────┘  └──────┘  │              │   │
│  │             └─────────────────────┘              │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│    dm-verity root │ UKI Secure Boot │ measured /etc/    │
└─────────────────────────────────────────────────────────┘
```

## How it works

1. **Boot** — The VM starts from a dm-verity protected, UKI Secure Boot image built with [tdx-image-base](https://github.com/Privasys/tdx-image-base).

2. **Dynamic Loading** — The manager starts with zero containers. Operators call `POST /api/v1/containers` (authenticated via OIDC bearer token) to load containers at runtime. Each request specifies a digest-pinned OCI image reference, environment, volumes, and ports.

3. **Pull & Verify** — OCI images are pulled via containerd. Each image digest is verified against the pinned `@sha256:...` reference in the load request.

4. **Merkle Tree** — A platform Merkle tree and per-container Merkle trees are recomputed after every load/unload from the CA cert, image digests, and container configs.

5. **RA-TLS Certificates** — The Merkle roots and container metadata are embedded as X.509 extensions in RA-TLS certificates, alongside the TDX/SEV-SNP attestation quote.

6. **TLS Handshake** — Clients connecting via TLS receive a certificate chain that proves: which TEE is running, what OS image booted, which containers are deployed (by digest), and how they're configured.

7. **Health & Metrics** — The management API exposes `/healthz`, `/readyz`, `/api/v1/status`, and Prometheus `/metrics` over RA-TLS at `manager.<machine-name>.<hostname>`.

## OID Extensions

All Privasys OIDs live under the arc `1.3.6.1.4.1.65230`:

| OID | Name | Description |
|-----|------|-------------|
| `1.2.840.113741.1.5.5.1.6` | TDX Quote | Intel TDX attestation quote |
| `1.2.840.113741.1.13.1.0` | SGX Quote | Intel SGX attestation quote |
| `1.3.6.1.4.1.65230.1.1` | Platform Config Merkle Root | SHA-256 root of the platform config tree |
| `1.3.6.1.4.1.65230.2.4` | containerd Version Hash | SHA-256 of the containerd version string |
| `1.3.6.1.4.1.65230.2.5` | Combined Images Hash | SHA-256 covering all container image digests |
| `1.3.6.1.4.1.65230.2.6` | Data Encryption Key Origin | `"external"` (BYOK) or `"enclave-generated"` — proves data-at-rest encryption and key provenance |
| `1.3.6.1.4.1.65230.3.1` | Container Config Merkle Root | SHA-256 root of a per-container config tree |
| `1.3.6.1.4.1.65230.3.2` | Container Image Digest | Raw SHA-256 digest of the OCI image |
| `1.3.6.1.4.1.65230.3.3` | Container Image Ref | Full OCI image reference string |

## Workload Manifest

```yaml
version: "1"
platform:
  machine_name: prod1
  hostname: example.com
  ca_cert: /data/ca.crt
  ca_key: /data/ca.key
  attestation_backend: tdx
containers:
  - name: postgres
    image: "docker.io/library/postgres@sha256:..."
    port: 5432
    internal: true
    env:
      POSTGRES_DB: mydb
    health_check:
      tcp: "127.0.0.1:5432"
  - name: myapp
    image: "ghcr.io/example/myapp@sha256:..."
    port: 8080
    health_check:
      http: "http://127.0.0.1:8080/healthz"
```

Hostnames are derived automatically from the machine name and hostname:
- Management API: `manager.prod1.example.com`
- Container `myapp`: `myapp.prod1.example.com`
- Container `postgres`: internal (no external hostname)

See [dist/examples/manifest-example.yaml](dist/examples/manifest-example.yaml) for a complete web-app + PostgreSQL example.

## Data-at-Rest Encryption

The data partition (`/data`) is always **LUKS2-encrypted with authenticated encryption (AEAD)**, providing both confidentiality and per-sector integrity protection. The encryption key can be:

| Mode | Source | How |
|------|--------|-----|
| **BYOK** | Operator-supplied passphrase | Passed via cloud instance metadata or configuration |
| **Auto-generated** | Random 256-bit key | Generated at first boot when no external key is provided |

At boot, `luks-data.service` runs before `data.mount`:
1. Reads the passphrase from instance metadata (BYOK) or generates one
2. Formats the partition with LUKS2 on first boot, or opens an existing volume
3. Writes the key origin (`"external"` or `"enclave-generated"`) to `/run/luks/dek-origin`
4. The manager reads the origin and publishes it as **OID 2.6** in every RA-TLS certificate

Clients can verify data-at-rest encryption status and key provenance in the TLS handshake.

## Building

```bash
# Requires Go 1.25+ (Privasys fork with RA-TLS challenge-response support)
go build -o manager ./cmd/manager/
```

## Running

```bash
# Start the workload launcher and management API
manager serve \
  --attestation-backend tdx \
  --ca-cert /data/ca.crt \
  --ca-key /data/ca.key \
  --machine-name prod1 \
  --hostname example.com \
  --oidc-issuer https://auth.example.com
```

See [docs/setup.md](docs/setup.md) for all flags and configuration options.

## Releases

Each tagged release publishes:

| Artifact | Description |
|----------|-------------|
| **dm-verity root hash** | SHA-256 of every byte on the read-only root filesystem — the primary code identity measurement |
| **Disk image** | Bootable TDX Confidential VM image (cloud-specific formats produced by CI) |
| **Disk tarball** | `enclave-os-virtual-VERSION.tar.gz` (GitHub Release asset) |

The dm-verity root hash is embedded in the kernel command line (`roothash=...`) and extended into **RTMR[1]** at boot. Clients can verify it via RA-TLS by inspecting the TDX quote in the server's certificate.

See [GitHub Releases](https://github.com/Privasys/enclave-os-virtual/releases) for the full list of measurements.

## Product Family

| Product | TEE | Workload Model | Repo |
|---------|-----|----------------|------|
| **Enclave OS (Mini)** | Intel SGX | WASM modules | [enclave-os-mini](https://github.com/Privasys/enclave-os-mini) |
| **Enclave OS (Virtual)** | Intel TDX / AMD SEV-SNP | OCI containers | This repo |

Both share the same RA-TLS attestation model, OID arc, and Merkle tree design.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

[GNU Affero General Public License v3.0](LICENSE)
