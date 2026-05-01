# Remote Attestation TLS (RA-TLS)

## Why RA-TLS?

Standard TLS proves that a client is talking to the holder of a private key.
But it says nothing about **what software** is running on the other end, or
**what configuration** it is using.

RA-TLS solves this by embedding **hardware attestation evidence** directly
in the X.509 certificate.  When a client connects, it receives cryptographic
proof of:

1. **What platform is running** — the TDX or SEV-SNP measurement of the
   Confidential VM (launch digest, firmware hash)
2. **What containers are loaded** — deterministic Merkle roots over every
   loaded container's image digest, environment, volumes, and command
3. **What the VM reports** — the `ReportData` field (64 bytes chosen by the
   enclave, binding the TLS key to the quote)
4. **What runtime is in use** — the runtime version hash embedded in the
   certificate

All of this is verified **before the TLS handshake completes**.  The client
can reject connections to VMs running unknown images, wrong configurations,
or an untrusted runtime — without trusting the server operator.

---

## Architecture

```
                      Internet
                         │
                         ▼
┌────────────────────────────────────────────────────────┐
│  Intel TDX / AMD SEV-SNP  Confidential VM              │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Caddy  (RA-TLS module)                          │  │
│  │                                                  │  │
│  │  • Terminates TLS with RA-TLS certificates       │  │
│  │  • Embeds TDX/SEV-SNP quote in every certificate │  │
│  │  • Reads per-hostname OID extensions from        │  │
│  │    /run/manager/extensions/<hostname>.json       │  │
│  │  • Routes by SNI to correct upstream             │  │
│  └────┬──────────────────────────────────────┬──────┘  │
│       │                                      │         │
│       ▼                                      ▼         │
│  ┌─────────────┐              ┌─────────────────────┐  │
│  │ Manager API │              │  Container (myapp)  │  │
│  │ (localhost: │              │  (localhost:8080)   │  │
│  │  9443)      │              │                     │  │
│  └─────────────┘              └─────────────────────┘  │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Launcher                                        │  │
│  │  • Writes OID extension files to extensions_dir  │  │
│  │  • Registers / removes Caddy routes              │  │
│  │  • Recomputes Merkle trees on every load/unload  │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│   dm-verity root │ Secure Boot │ measured rootfs       │
└────────────────────────────────────────────────────────┘
```

The architectural difference from [enclave-os-mini](https://github.com/Privasys/enclave-os-mini)
(SGX) is **who performs TLS termination**: in enclave-os-mini the enclave
binary itself handles TLS via rustls, while in enclave-os-virtual a
dedicated **Caddy process** (with the RA-TLS issuance module) does.
Both run inside a hardware enclave — SGX for mini, TDX/SEV-SNP for virtual —
so the TLS private key and plaintext traffic are always protected by
hardware memory encryption.  The trade-off is TCB size: SGX enclaves have a
minimal TCB (just the enclave binary), whereas a TDX VM includes the full
kernel and userspace.  The attestation guarantees are otherwise equivalent —
every certificate embeds a hardware quote binding the TLS key to the
platform measurement.

The manager provides the Privasys OID extensions (Merkle roots, image
digests, etc.) via a shared filesystem directory that the RA-TLS module reads
during certificate issuance.

---

## Certificate Trust Chain

```
Root CA (operator-provisioned)
 └── Intermediary CA (inside the VM, /data/ca.crt)
      ├── Platform RA-TLS certificate (management API hostname)
      │        ├── TDX/SGX Quote         (OID 1.2.840.113741.1.5.5.1.6)
      │        ├── Platform Merkle Root  (OID 1.3.6.1.4.1.65230.1.1)
      │        ├── Runtime Version Hash  (OID 1.3.6.1.4.1.65230.2.4)
      │        ├── Combined Workloads Hash (OID 1.3.6.1.4.1.65230.2.5)
      │        ├── DEK Origin            (OID 1.3.6.1.4.1.65230.2.6)
      │        └── Attestation Servers   (OID 1.3.6.1.4.1.65230.2.7)
      │
      ├── Container RA-TLS cert: "myapp.prod1.example.com"
      │        ├── TDX/SGX Quote         (OID 1.2.840.113741.1.5.5.1.6)
      │        ├── Config Merkle Root    (OID 1.3.6.1.4.1.65230.3.1)
      │        ├── Image Digest          (OID 1.3.6.1.4.1.65230.3.2)
      │        └── Image Ref             (OID 1.3.6.1.4.1.65230.3.3)
      │
      └── Container RA-TLS cert: "postgres.prod1.example.com"
               ├── ...
               └── ...
```

### Intermediary CA

The intermediary CA certificate and private key (ECDSA P-256) are provisioned
by the operator and baked into the image:

| File | Path |
|------|------|
| CA certificate | `/data/ca.crt` |
| CA private key | `/data/ca.key` |

Both are passed to Caddy via `--ca-cert` and `--ca-key`.  The CA private key
never leaves the VM — it exists only in TEE-encrypted memory and on the
LUKS-encrypted data partition.

### Leaf Certificates

A fresh leaf certificate is generated for each TLS connection in
challenge-response mode, or cached for up to 24 hours in deterministic mode.
The process (performed by Caddy's RA-TLS module):

1. Generate an **ECDSA P-256 key pair** inside the TEE
2. Compute `ReportData`:
   ```
   report_data = SHA-512( SHA-256(SPKI_DER) || binding )
   ```
   where `SPKI_DER` is the 91-byte DER-encoded `SubjectPublicKeyInfo` of
   the leaf public key — the same structure whose SHA-256 appears as
   "Public Key SHA-256" in standard X.509 certificate viewers.
   - **Challenge mode**: `binding` = nonce from ClientHello extension `0xFFBB`
   - **Deterministic mode**: `binding` = creation timestamp (`"2006-01-02T15:04Z"`)
3. Request a **TDX quote** (or SGX quote) with the `ReportData`
4. Read per-hostname OID extensions from `<extensions_dir>/<hostname>.json`
5. Build the X.509 certificate with the quote extension + OID extensions
6. Sign with the intermediary CA key

### Client Verification

Clients verify an RA-TLS certificate in three steps:

1. **Standard TLS** — verify the certificate chain against the root CA
2. **Hardware quote** — extract the TDX/SGX quote from the Intel OID,
   verify the DCAP signature, check the platform measurement
3. **Configuration state** — check the Privasys OID extensions (Merkle
   roots, image digests, runtime version hash) against known-good values

---

## X.509 OID Extensions

Every RA-TLS certificate contains custom non-critical X.509 extensions
that encode the VM's attestation data and configuration state.

### OID Hierarchy

```
1.2.840.113741.1.5.5.1.6              Intel TDX DCAP Quote
1.2.840.113741.1.13.1.0               Intel SGX DCAP Quote

1.3.6.1.4.1.65230                     Privasys arc
├── 1.1                               Platform Config Merkle Root
├── 2.*                               Platform-wide module OIDs
│   ├── 2.4                           Runtime Version Hash
│   ├── 2.5                           Combined Workloads Hash
│   ├── 2.6                           Data Encryption Key Origin
│   └── 2.7                           Attestation Servers Hash
└── 3.*                               Per-container OIDs
    ├── 3.1                           Container Config Merkle Root
    ├── 3.2                           Container Image Digest
    ├── 3.3                           Container Image Ref
    └── 3.4                           Container Volume Encryption
```

### Platform-Wide OIDs

Present in the **management API certificate** (platform hostname).

| OID | Name | Value | Size |
|-----|------|-------|------|
| `1.2.840.113741.1.5.5.1.6` | TDX Quote | Raw DCAP quote bytes | ~4 KB |
| `1.3.6.1.4.1.65230.1.1` | Platform Config Merkle Root | SHA-256 hash | 32 bytes |
| `1.3.6.1.4.1.65230.2.4` | Runtime Version Hash | SHA-256 of containerd version string | 32 bytes |
| `1.3.6.1.4.1.65230.2.5` | Combined Workloads Hash | SHA-256 of all image digests | 32 bytes |
| `1.3.6.1.4.1.65230.2.6` | Data Encryption Key Origin | `"byok:<fingerprint>"` | variable |
| `1.3.6.1.4.1.65230.2.7` | Attestation Servers Hash | SHA-256 of server URL list | 32 bytes |

### Per-Container OIDs

Present in **per-container certificates** (container hostname via SNI).

| OID | Name | Value | Size |
|-----|------|-------|------|
| `1.2.840.113741.1.5.5.1.6` | TDX Quote | Raw DCAP quote bytes | ~4 KB |
| `1.3.6.1.4.1.65230.3.1` | Container Config Merkle Root | SHA-256 tree of container config | 32 bytes |
| `1.3.6.1.4.1.65230.3.2` | Container Image Digest | SHA-256 of OCI image manifest | 32 bytes |
| `1.3.6.1.4.1.65230.3.3` | Container Image Ref | Full image reference string | variable |
| `1.3.6.1.4.1.65230.3.4` | Container Volume Encryption | `"byok:<fingerprint>"` or `"generated"` — omitted when no volume | variable |

---

## Building Trust: Platform Measurement and Configuration

### The Three Pillars of Trust

**Pillar 1: Platform identity (TDX/SNP measurement)**

The hardware quote contains the platform measurement — a hash of the VM's
initial state (firmware, kernel, initrd).  Combined with dm-verity and
Secure Boot, this proves the exact disk image and boot chain.

**Pillar 2: Configuration identity (Merkle root)**

Knowing the platform is correct is necessary but not sufficient.  The same
VM image can run different containers with different configurations:

- Different container images loaded
- Different environment variables
- Different volume mounts
- Different CA certificates

The **Platform Config Merkle Root** (OID `1.3.6.1.4.1.65230.1.1`) captures
all of these inputs in a single 32-byte hash.

**Pillar 3: Container-level verification (per-container OIDs)**

Each container with an external hostname gets its own RA-TLS certificate
with container-specific OID extensions.  This allows clients to verify the
exact image digest and configuration of the container they are connecting
to, without learning about other containers on the same VM.

### Platform Merkle Tree

The platform-wide Merkle tree includes these leaves (alphabetically sorted):

| Leaf name | Input |
|-----------|-------|
| `platform.attestation_servers` | Sorted, newline-joined attestation server URLs |
| `platform.ca_cert` | Intermediary CA certificate (DER bytes) |
| `container.<name>.image_digest` | SHA-256 digest of each loaded container |

Each leaf hash is `SHA-256(data)`.  The root is:

```
root = SHA-256( leaf_hash_0 || leaf_hash_1 || … || leaf_hash_N )
```

The platform Merkle root **changes on every container load/unload** because
the set of `container.*.image_digest` leaves changes.

### Per-Container Merkle Tree

Each container gets its own Merkle tree with these leaves:

| Leaf name | Input |
|-----------|-------|
| `container.<name>.command_hash` | SHA-256 of serialised command |
| `container.<name>.env_hash` | SHA-256 of sorted env vars |
| `container.<name>.image_digest` | SHA-256 of OCI image manifest |
| `container.<name>.image_ref` | Full image reference string |
| `container.<name>.name` | Container name |
| `container.<name>.volumes_hash` | SHA-256 of sorted volume mounts |

**Note**: The `vault_token` field (used for runtime secrets) is deliberately
excluded from the Merkle tree.  Changing the vault token does not change the
container's attested identity.

### Combined Workloads Hash (OID 2.5)

For clients that want a single-check covering all loaded containers:

```
combined = SHA-256( name_1 || digest_1 || name_2 || digest_2 || … )
```

Containers are sorted by name for determinism.

### Verification Strategies

Clients can choose their verification depth:

| Strategy | What to check | Trust level |
|----------|--------------|-------------|
| **TDX measurement only** | Hardware quote → platform matches known value | VM image is correct, but containers unknown |
| **Measurement + Merkle root** | + OID `1.3.6.1.4.1.65230.1.1` | VM image and full container set verified |
| **Fast-path module OIDs** | + OIDs `2.4`, `2.5`, `2.6`, `2.7` | Verify runtime version, container set, encryption provenance, and attestation servers without Merkle audit |
| **Per-container verification** | + OIDs `3.1`, `3.2`, `3.3`, `3.4` (via SNI) | Verify a specific container's image, configuration, and volume encryption |
| **Full Merkle audit** | Request manifest, recompute root | Complete transparency of all inputs |

---

## Challenge-Response vs. Deterministic Mode

### Challenge Mode (Client → Server)

The client sends a random nonce in a TLS ClientHello extension (`0xFFBB`).
The RA-TLS module binds this nonce into the TDX/SGX quote's `ReportData`:

```
report_data = SHA-512( SHA-256(SPKI_DER) || nonce )
```

Here `SPKI_DER` is the full 91-byte `SubjectPublicKeyInfo` — its SHA-256 is
the standard public key fingerprint shown by any X.509 viewer.

This proves the certificate was generated **in response to this specific
connection**.  The certificate is valid for 5 minutes and is never cached.

**Requires:** Go 1.25+ Privasys fork (`github.com/Privasys/go`, branch `ratls`)
with the `ratls` build tag.

**Use case:** High-security scenarios where certificate freshness is critical.

### Deterministic Mode

When no nonce is present, the RA-TLS module uses the creation timestamp as binding:

```
report_data = SHA-512( SHA-256(SPKI_DER) || "2006-01-02T15:04Z" )
```

The certificate is cached by certmagic for up to 24 hours.

A verifier can reproduce the `ReportData` from the certificate alone: read
the public key and `NotBefore` field, apply the same formula, and compare
against the quote's `ReportData`.

**Use case:** Standard operation — avoids re-generating quotes for every
connection while still providing time-bound freshness.

---

## Per-Container Certificates and SNI Routing

### Why per-container certificates?

A single Confidential VM can host many containers simultaneously.
Per-container certificates solve two requirements:

1. **Workload isolation** — each client only sees the image digest,
   configuration Merkle root, and image reference of the container it
   connects to.  A client connecting to `myapp` learns nothing about
   `postgres` or any other container.

2. **Independent lifecycle** — adding, removing, or updating one container
   does not invalidate other containers' certificates.

### How It Works

The Caddy reverse proxy uses **SNI-based routing**:

1. Client connects to `myapp.prod1.example.com:443`
2. Caddy matches the SNI hostname to a registered route
3. The RA-TLS module reads `/run/manager/extensions/myapp.prod1.example.com.json`
4. If in challenge-response mode: generate fresh key + TDX quote + extensions
5. If in deterministic mode: serve cached cert (auto-renewed every 24h)
6. TLS established — Caddy reverse-proxies the plaintext to the **manager**
   (`localhost:9443`), not directly to the container
7. The manager dispatches by `Host`: the platform hostname hits the
   management API mux; every other host is reverse-proxied to its
   registered container loopback (e.g. `localhost:8080`)

Routing through the manager lets the **session-relay middleware**
(`internal/sessionrelay`) intercept SDK traffic uniformly: any host can
receive `POST /__privasys/session-bootstrap` and `application/privasys-sealed+cbor`
requests without the container app implementing the protocol. Since the
manager, Caddy, and the container all live inside the same TDX-measured
TCB (dm-verity rootfs + measured boot), terminating the SDK session at
the manager is no weaker than terminating it at the container — the same
hardware quote attests both.

### Route Lifecycle

When the operator loads a container:

```
POST /api/v1/containers
{
  "name": "myapp",
  "image": "ghcr.io/example/myapp@sha256:abc123...",
  "port": 8080
}
```

The launcher:

1. Pulls and verifies the image digest
2. Starts the container via containerd
3. Derives the hostname: `myapp.<machine-name>.<hostname>`
4. Recomputes all Merkle trees
5. Writes OID extensions to `/run/manager/extensions/myapp.<machine-name>.<hostname>.json`
6. Registers a Caddy route: `myapp.<machine-name>.<hostname>` → `localhost:9443` (manager)
7. Registers the container upstream with the manager's host router
   (`Host` → `localhost:8080`) so the manager can reverse-proxy after
   running the session-relay middleware
8. Updates the platform extensions (combined workloads hash changed)

When unloading:

1. Removes the Caddy route
2. Unregisters the host from the manager's router
3. Deletes the extension file
4. Stops the container
5. Recomputes attestation (platform Merkle root changes)

### Platform vs. per-container: what goes where

| Scope | Certificate | OIDs present |
|-------|-------------|-------------|
| **Platform** | Management API hostname | TDX Quote, Platform Merkle Root (`1.1`), Runtime Version Hash (`2.4`), Combined Workloads Hash (`2.5`), DEK Origin (`2.6`), Attestation Servers Hash (`2.7`) |
| **Per-container** | Container hostname (via SNI) | TDX Quote, Container Merkle Root (`3.1`), Image Digest (`3.2`), Image Ref (`3.3`), Volume Encryption (`3.4`) |

---

## Extension File Format

The launcher writes per-hostname JSON files to the extensions directory.
Each file is an array of OID extension objects:

```json
[
  {
    "oid": "1.3.6.1.4.1.65230.3.1",
    "value": "dGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIFNIQS0yNTYgaGFzaA=="
  },
  {
    "oid": "1.3.6.1.4.1.65230.3.2",
    "value": "YWJjMTIzZGVmNDU2..."
  },
  {
    "oid": "1.3.6.1.4.1.65230.3.3",
    "value": "Z2hjci5pby9leGFtcGxlL215YXBwQHNoYTI1NjphYmMxMjMuLi4="
  }
]
```

Files are written atomically (write to `.tmp` → rename) to avoid the RA-TLS
module reading partial data.

The RA-TLS module reads `<extensions_dir>/<hostname>.json` on every cert
issuance and appends the extensions alongside the hardware attestation quote.

---

## Caddy Configuration

The RA-TLS module is configured as a Caddy TLS issuer:

```
{
  tls {
    issuer ra_tls {
      backend        tdx
      ca_cert        /data/ca.crt
      ca_key         /data/ca.key
      extensions_dir /run/manager/extensions
    }
  }
}
```

| Directive | Description |
|-----------|-------------|
| `backend` | TEE attestation backend: `tdx` or `sgx` |
| `ca_cert` | Path to intermediary CA certificate PEM |
| `ca_key` | Path to intermediary CA private key PEM |
| `extensions_dir` | Directory for per-hostname OID extension files |

Routes are managed dynamically via the Caddy admin API:

```
POST /load  →  Full Caddy JSON config (routes + TLS policy)
```

The manager maintains the route table in memory and reloads Caddy's config
on every container load/unload.

### Manager Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--caddy-listen` | `:443` | External HTTPS listen address |
| `--extensions-dir` | `/run/manager/extensions` | OID extension files directory |
| `--machine-name` | — | Machine name — determines all RA-TLS hostnames |
| `--hostname` | — | **Required.** Hostname suffix appended to the machine name |
| `--ca-cert` | — | **Required.** Intermediary CA certificate for RA-TLS |
| `--ca-key` | — | **Required.** Intermediary CA private key for RA-TLS |

---

## Comparison with Enclave OS (Mini)

| Feature | Enclave OS (Mini) (SGX) | Enclave OS (Virtual) (CVM) |
|---------|----------------------|--------------------------|
| **TEE** | Intel SGX enclave | Intel TDX / AMD SEV-SNP VM |
| **TLS termination** | Enclave binary (rustls) | Caddy (RA-TLS module) |
| **Key generation** | Inside enclave, sealed to MRENCLAVE | Inside TEE, managed by certmagic |
| **CA storage** | Sealed to disk via `sgx_tseal` | LUKS2 + AEAD integrity on data partition (`/data/`) |
| **Quote per-cert** | Yes (per-connection in challenge mode) | Yes (per-connection in challenge mode) |
| **Workload type** | WASM apps | OCI containers |
| **Per-workload certs** | Per-app via SNI | Per-container via SNI |
| **OID arc** | Same (`1.3.6.1.4.1.65230`) | Same (`1.3.6.1.4.1.65230`) |
| **Module OIDs** | `2.1` Egress CA, `2.5` Combined workloads, `2.7` Attestation servers | `2.4` Runtime version, `2.5` Combined workloads, `2.6` DEK origin, `2.7` Attestation servers |
| **Challenge extension** | `0xFFBB` in ClientHello | `0xFFBB` in ClientHello |
| **Mutual RA-TLS** | Full bidirectional (vault GetSecret) | Server-side (container verification) |
| **ReportData formula** | Same: `SHA-512(SHA-256(pk) \|\| binding)` | Same: `SHA-512(SHA-256(pk) \|\| binding)` |

Both platforms share the same **Privasys OID arc**, **challenge-response
protocol**, and **ReportData formula**, making it possible to write a single
RA-TLS client that verifies certificates from either platform.

---

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **Key binding** | The TLS public key is cryptographically bound to the TDX/SGX quote via ReportData |
| **Platform identity** | TDX measurement proves the VM image, firmware, and boot chain |
| **Config identity** | Platform Merkle root proves all loaded containers and their configurations |
| **Data encryption provenance** | OID 2.6 publishes the operator-supplied (BYOK) DEK fingerprint for the data partition |
| **Container identity** | Per-container OIDs prove the exact image digest, reference, and config |
| **Freshness** | Challenge nonce or timestamp prevents replay of old certificates |
| **CA isolation** | The CA private key is on the LUKS-encrypted data partition (AEAD integrity-protected) inside the TEE |
| **Honest reporter** | The VM cannot suppress configuration state — Merkle roots change with every load/unload |
| **Digest pinning** | Only images with matching `@sha256:` digests are loaded — no tag-based pulls |
| **Runtime exclusion** | Vault tokens are excluded from attestation — runtime secrets don't change the attested identity |

---

## Client Libraries

The [ra-tls-clients](https://github.com/Privasys/ra-tls-clients) repository
provides client libraries in multiple languages that can verify RA-TLS
certificates from both enclave-os-mini and enclave-os-virtual:

| Language | Package | Challenge-Response |
|----------|---------|-------------------|
| Rust | `ra-tls-clients/rust` | Yes (via custom rustls) |
| Go | `ra-tls-clients/go` | Yes (via Privasys/go fork) |
| Python | `ra-tls-clients/python` | Deterministic only |
| .NET | `ra-tls-clients/dotnet` | Deterministic only |
| TypeScript | `ra-tls-clients/typescript` | Deterministic only |

See [ra-tls-clients README](https://github.com/Privasys/ra-tls-clients)
for usage examples.
