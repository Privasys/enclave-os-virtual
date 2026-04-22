# Enclave OS (Virtual)

**Container workloads inside Confidential VMs, attested end-to-end.**

Enclave OS (Virtual) runs OCI containers inside [Intel TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html) (or AMD SEV-SNP) Confidential VMs. Every container image digest, environment variable, volume mount, and platform configuration is measured into a deterministic Merkle tree and embedded in X.509 certificate extensions via RA-TLS. Clients can verify the full workload stack in a single TLS handshake - no out-of-band attestation protocol required.

Part of the [Privasys](https://privasys.org) Confidential Computing platform, alongside [Enclave OS (Mini)](https://github.com/Privasys/enclave-os-mini) (SGX/WASM).

## Architecture

```
┌────────────────────────────────────────────────────────┐
│  Intel TDX / AMD SEV-SNP Confidential VM               │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Enclave OS (Virtual)                            │  │
│  │                                                  │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  │  │
│  │  │ ra-tls-    │  │ Workload   │  │ Management │  │  │
│  │  │ caddy      │  │ Launcher   │  │ Server     │  │  │
│  │  │ (TLS +     │  │ (containerd│  │ (HTTP on   │  │  │
│  │  │  reverse   │  │  lifecycle)│  │  localhost)│  │  │
│  │  │  proxy)    │  │            │  │            │  │  │
│  │  └─────┬──────┘  └─────┬──────┘  └────────────┘  │  │
│  │        │               │                         │  │
│  │        │    ┌──────────┴──────────┐              │  │
│  │        │    │     containerd      │              │  │
│  │        │    └──────────┬──────────┘              │  │
│  │        │    ┌──────────┴──────────┐              │  │
│  │        └────┤  OCI Containers     │              │  │
│  │             │  ┌─────┐  ┌──────┐  │              │  │
│  │             │  │App  │  │ DB   │  │              │  │
│  │             │  │     │  │      │  │              │  │
│  │             │  └─────┘  └──────┘  │              │  │
│  │             └─────────────────────┘              │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│   dm-verity root │ UKI Secure Boot │ measured /etc/    │
└────────────────────────────────────────────────────────┘
```

## How it works

1. **Boot** — The VM starts from a dm-verity protected, UKI Secure Boot image built with [cvm-images](https://github.com/Privasys/cvm-images).

2. **Dynamic Loading** — The manager starts with zero containers. Operators call `POST /api/v1/containers` (authenticated via OIDC bearer token) to load containers at runtime. Each request specifies a digest-pinned OCI image reference, environment, volumes, and ports.

3. **Pull & Verify** — OCI images are pulled via containerd. Each image digest is verified against the pinned `@sha256:...` reference in the load request.

4. **Merkle Tree** — A platform Merkle tree and per-container Merkle trees are recomputed after every load/unload from the CA cert, image digests, and container configs.

5. **RA-TLS Certificates** — The Merkle roots and container metadata are embedded as X.509 extensions in RA-TLS certificates, alongside the TDX/SEV-SNP attestation quote.

6. **TLS Handshake** — Clients connecting via TLS receive a certificate chain that proves: which TEE is running, what OS image booted, which containers are deployed (by digest), and how they're configured.

7. **Health & Metrics** — The management API exposes `/healthz`, `/readyz`, `/api/v1/status`, and Prometheus `/metrics` over RA-TLS at `manager.<machine-name>.<hostname>`.

## Image-Declared Volumes

Container images can declare persistent disk mounts via the `ai.privasys.volume`
OCI label. The manager reads the label at container start and bind-mounts the
host path into the container. This lets each image be self-describing - no
hardcoded volume configuration in the management service.

```dockerfile
LABEL ai.privasys.volume="/mnt/model-gemma4-31b:/models:ro"
```

Format: `<host-path>:<container-path>[:<options>]`

## OS Images

The VM disk images are built by [cvm-images](https://github.com/Privasys/cvm-images)
and published as GitHub Releases. Two variants are available for Intel TDX:

| Variant | GCP Image Family | CI Workflow | Tag Pattern | Description |
|---------|-----------------|-------------|-------------|-------------|
| **Base** | `privasys-tdx` | `build-tdx-base.yml` | `tdx-base-v*` | CPU-only workloads |
| **GPU** | `privasys-tdx-gpu` | `build-tdx-gpu.yml` | `tdx-gpu-v*` | NVIDIA GPU workloads (H100, etc.) |

Both variants share the same partition layout, boot chain, and security
properties:

- **Root filesystem**: erofs (read-only) with dm-verity integrity
- **Boot**: UEFI Secure Boot via shim-signed + grub-efi-amd64-signed
- **Partitions**: ESP (512 MB), root + verity hash, data (2 GB LUKS2+AEAD), containers (LVM, remaining disk)
- **Kernel**: Ubuntu HWE 6.19 with CVM guard patch (BadAML mitigation)

The GPU variant adds:

- `nvidia-driver-590-server-open`, `cuda-toolkit-13-0`, `nvidia-container-toolkit`
- containerd configured with `nvidia-container-runtime` as default runtime
- Kernel parameters: `iommu=pt intel_iommu=on nvidia.NVreg_ConfidentialComputing=1`

### Building locally

```bash
# Base image (generic)
cd images/tdx-base && sudo mkosi build

# Base image (GCP profile)
cd images/tdx-base && sudo mkosi --profile gcp build

# GPU image (GCP profile)
cd images/tdx-gpu && sudo mkosi --profile gcp build
```

See the [cvm-images README](https://github.com/Privasys/cvm-images) for full
build instructions and cloud deployment guides.

## OID Extensions

All Privasys OIDs live under the arc `1.3.6.1.4.1.65230`:

| OID | Name | Description |
|-----|------|-------------|
| `1.2.840.113741.1.5.5.1.6` | TDX Quote | Intel TDX attestation quote |
| `1.2.840.113741.1.13.1.0` | SGX Quote | Intel SGX attestation quote |
| `1.3.6.1.4.1.65230.1.1` | Platform Config Merkle Root | SHA-256 root of the platform config tree |
| `1.3.6.1.4.1.65230.2.4` | Runtime Version Hash | SHA-256 of the runtime (containerd) version string |
| `1.3.6.1.4.1.65230.2.5` | Combined Workloads Hash | SHA-256 covering all container image digests |
| `1.3.6.1.4.1.65230.2.6` | Data Encryption Key Origin | `"byok:<fingerprint>"` or `"generated"` — proves data-at-rest encryption and key provenance |
| `1.3.6.1.4.1.65230.2.7` | Attestation Servers Hash | SHA-256 of the attestation server URL list |
| `1.3.6.1.4.1.65230.3.1` | Container Config Merkle Root | SHA-256 root of a per-container config tree |
| `1.3.6.1.4.1.65230.3.2` | Container Image Digest | Raw SHA-256 digest of the OCI image |
| `1.3.6.1.4.1.65230.3.3` | Container Image Ref | Full OCI image reference string |
| `1.3.6.1.4.1.65230.3.4` | Container Volume Encryption | `"byok:<fingerprint>"` or `"generated"` — present only when encrypted volume is attached |

## Workload Manifest

```yaml
version: "1"
platform:
  machine_name: prod1
  hostname: example.com
  ca_cert: /data/ca.crt
  ca_key: /data/ca.key
  attestation_servers:
    - https://as.privasys.org/verify
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

The disk has two encrypted regions:

| Partition | Size | Purpose | Encryption |
|-----------|------|---------|------------|
| **OS data** (`/data`) | 2 GB | CA cert+key, manager.env | LUKS2+AEAD, single key (BYOK or auto-generated) |
| **Container volumes** | Remaining disk | Per-container writable storage | LUKS2+AEAD per LVM volume, independent key per container |

### OS data partition

At boot, `luks-data.service` runs before `data.mount`:
1. Reads the passphrase from instance metadata (BYOK) or generates one
2. Formats the partition with LUKS2+AEAD on first boot, or opens an existing volume
3. Writes the key origin (`"byok:<fingerprint>"` or `"generated"`) to `/run/luks/dek-origin`
4. The manager reads the origin and publishes it as **OID 2.6** in every RA-TLS certificate

### Per-container encrypted volumes

Each container receives an independent **LVM logical volume** with its own LUKS2+AEAD encryption key. Keys are never shared between containers and never stored on the OS data partition — they are held only in TEE-encrypted memory at runtime.

| Key source | Mechanism |
|------------|----------|
| **BYOK** | Per-container key provided in the `POST /api/v1/containers` request |
| **Enclave Vaults** | Key fetched from the vault constellation via mutual RA-TLS |

The container volumes partition fills all remaining disk space. Choose your disk size at instance creation time (e.g. `--create-disk=size=50` for ~46 GB of container storage). Online resize is not supported because `--integrity aead` (dm-integrity) cannot be grown in place.

## Kernel hardening (BadAML mitigation)

The disk image ships a patched Ubuntu HWE kernel with the **CVM guard** - a
downstream patch that blocks ACPI AML bytecode from accessing memory pages
marked as encrypted/private on TDX and SEV-SNP VMs.

**Background:** On confidential VMs the host VMM controls the ACPI tables
supplied to the guest. A malicious host can inject SSDT tables containing AML
bytecode that reads or writes arbitrary guest physical addresses, including
private (encrypted) pages. This was publicly documented as "BadAML" (Takekoshi
et al., ACM CCS 2025, BlackHat EU 2024). No mainline kernel fix exists as of
6.19.

**Mitigation:** The CVM guard hooks `acpi_ex_system_memory_space_handler()` and
walks the page tables for the target address before every AML memory access. If
the page's encryption bit is set (private), the access is denied with
`AE_AML_ILLEGAL_ADDRESS`. On non-CVM systems the guard is a no-op. The kernel
command line also includes `acpi_no_initrd_table_override` to prevent ACPI table
injection via the initrd.

The patched kernel is built automatically by `build/kernel/build-kernel.sh` and
installed into the image via mkosi's `PackageDirectories`. See
`build/kernel/patches/` for the patch source.

## Building

```bash
# Requires Go 1.25+ (Privasys fork with RA-TLS challenge-response support)
go build -o manager ./cmd/manager/
```

## Running

```bash
# Start the workload launcher and management API
manager serve \
  --attestation-servers https://as.privasys.org/verify \
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

The dm-verity root hash is embedded in the kernel command line (`roothash=...`) and measured into **RTMR[2]** at boot (via CC MR 3). RTMR[1] (CC MR 2) measures the EFI boot path (shim and GRUB binaries). Together, a remote verifier can confirm the exact bootloader AND root filesystem by checking RTMR[1] and RTMR[2] in the TDX quote.

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
