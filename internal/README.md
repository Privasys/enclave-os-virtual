# internal/

Internal packages implementing the Enclave OS (Virtual) runtime.

| Package | Description |
|---------|-------------|
| `manager` | Management API server (HTTP on localhost, OIDC auth middleware, Prometheus metrics, TLS rotation) |
| `auth` | OIDC-only bearer token verification, JWKS discovery, role checking |
| `caddy` | Caddy admin API client for dynamic RA-TLS route management |
| `container` | OCI container lifecycle via containerd (pull, create, health checks) |
| `extensions` | Per-hostname OID extension file writer for Caddy's RA-TLS module |
| `launcher` | Workload orchestrator — dynamic load/unload with attestation + Caddy wiring |
| `manifest` | Workload manifest format, validation, and per-container Merkle trees |
| `merkle` | Deterministic SHA-256 Merkle tree for configuration attestation |
| `oids` | X.509 OID extension definitions for RA-TLS certificates |

## Documentation

- [API Reference](../docs/api.md) — All management endpoints
- [Authentication & Bootstrap](../docs/bootstrap.md) — Auth model and bootstrap sequence
- [RA-TLS Architecture](../docs/ra-tls.md) — Certificate chain, OID extensions, Caddy integration
- [Setup & Configuration](../docs/setup.md) — Certificates, OIDC, flags
