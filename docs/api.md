# API Reference

The management API is exposed exclusively through Caddy on `:443` at
`manager.<machine-name>.<hostname>`, secured with RA-TLS. All endpoints
except `/healthz` and `/api/v1/clock/poll` (authenticated by its signature)
require an OIDC bearer token in the `Authorization` header.

See [setup.md](setup.md) for configuration and OIDC provider setup.

## Endpoints

| Method | Path | Auth | Role | Description |
|--------|------|------|------|-------------|
| GET | `/healthz` | None | — | Liveness probe |
| GET | `/readyz` | Bearer | Monitoring+ | Readiness probe |
| GET | `/api/v1/status` | Bearer | Monitoring+ | Container statuses |
| GET | `/metrics` | Bearer | Monitoring+ | Prometheus metrics |
| POST | `/api/v1/containers` | Bearer | Manager | Load a container |
| DELETE | `/api/v1/containers/{name}` | Bearer | Manager | Unload a container |
| PUT | `/api/v1/tls` | Bearer | Manager | Rotate intermediary CA cert+key |
| PUT | `/api/v1/attestation-servers` | Bearer | Manager | Update attestation servers (URLs + tokens) |
| PUT | `/api/v1/clock/config` | Bearer | Manager | Pin the clock monitor (key, incident URL) |
| POST | `/api/v1/clock/poll` | Ed25519 signature | — | Clock monitor floor poll |

"Monitoring+" means the `privasys-platform:monitoring` role or the
`privasys-platform:manager` role (manager implies monitoring).

---

### GET /healthz

Liveness probe for infrastructure health checks (load balancers, Kubernetes).
Always returns 200 with no authentication.

**Response** `200 OK`

```json
{ "status": "ok" }
```

---

### GET /readyz

Readiness probe. Returns 200 when all loaded containers are healthy, or when
no containers have been loaded yet (waiting for first load).

**Response** `200 OK`

```json
{ "status": "ready", "containers": 0 }
```

**Response** `503 Service Unavailable`

```json
{ "status": "not_ready" }
```

---

### GET /api/v1/status

Returns the current status of all loaded containers as a JSON array.

**Response** `200 OK`

```json
[
  {
    "name": "myapp",
    "image": "ghcr.io/example/myapp@sha256:abc123...",
    "status": "running"
  },
  {
    "name": "postgres",
    "image": "docker.io/library/postgres@sha256:def456...",
    "status": "healthy"
  }
]
```

Container status values: `pending`, `pulling`, `running`, `healthy`, `unhealthy`, `stopped`, `failed`.

---

### GET /metrics

Prometheus metrics endpoint. Exports:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `enclave_os_containers_loaded` | Gauge | — | Number of loaded containers |
| `enclave_os_container_status` | Gauge | `name`, `image` | Container status (0=unknown, 1=running, 2=healthy, 3=unhealthy) |
| `enclave_os_api_requests_total` | Counter | `method`, `path`, `status` | Total API requests |

---

### POST /api/v1/containers

Load a new container. The image must be digest-pinned (`@sha256:...`). If
the bearer token carries a `containers` claim, the image digest must match
a permitted entry.

**Request body**

```json
{
  "name": "myapp",
  "image": "ghcr.io/example/myapp@sha256:abc123...",
  "port": 8000,
  "env": {
    "DATABASE_HOST": "localhost"
  },
  "volumes": ["/data/myapp:/data"],
  "command": ["serve"],
  "internal": false,
  "storage": "2G",
  "health_check": {
    "http": "http://127.0.0.1:8000/healthz",
    "interval_seconds": 10,
    "timeout_seconds": 5,
    "retries": 3
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Unique container identifier |
| `image` | string | yes | OCI image reference with digest |
| `port` | int | yes | Container listening port. Must NOT be `8080` (reserved for the platform) — apps listen on the management-service-allocated `$PORT`. |
| `env` | object | no | Environment variables |
| `volumes` | string[] | no | Host:container mount paths |
| `command` | string[] | no | Override default entrypoint |
| `internal` | bool | no | If true, not externally accessible |
| `health_check` | object | no | Health check (see below) |
| `vault_token` | string | no | Injected as `VAULT_TOKEN` env var (runtime secret, excluded from attestation) |
| `storage` | string | no | Per-container encrypted volume size (e.g. `"1G"`, `"500M"`). Creates a LUKS2+AEAD LV, mounted at `/data` inside the container. Measured into attestation. |
| `storage_key` | string | no | LUKS passphrase for the per-container volume. If omitted, a random 256-bit key is generated inside the enclave (runtime secret, excluded from attestation). |

**Hostname derivation** — External hostnames are derived automatically from
the instance's `--machine-name` and `--hostname` flags:
`<name>.<machine-name>.<hostname>`.  For example, loading a container
named `registry` on machine `prod1` with hostname `example.com` creates
the hostname `registry.prod1.example.com`.  Containers with `"internal": true`
do not receive an external hostname or Caddy route.

**Health check fields**

| Field | Type | Description |
|-------|------|-------------|
| `http` | string | HTTP GET URL for health check |
| `tcp` | string | TCP address (host:port) to probe |
| `interval_seconds` | int | Seconds between checks (default: 5) |
| `timeout_seconds` | int | Seconds before check times out (default: 3) |
| `retries` | int | Consecutive failures before unhealthy (default: 3) |

**Response** `201 Created`

```json
{
  "name": "myapp",
  "image": "ghcr.io/example/myapp@sha256:abc123...",
  "digest": "a1b2c3d4...",
  "status": "running"
}
```

**Error responses**

| Status | Condition |
|--------|-----------|
| 400 | Invalid request body or missing required fields |
| 401 | Missing or invalid bearer token |
| 403 | Insufficient role or image not permitted by token policy |
| 500 | Container failed to start |

---

### DELETE /api/v1/containers/{name}

Unload a running container by name. If the bearer token carries a
`containers` claim, the name must match a permitted entry.

**Response** `200 OK`

```json
{
  "name": "myapp",
  "status": "unloaded"
}
```

**Error responses**

| Status | Condition |
|--------|-----------|
| 400 | Missing container name |
| 401 | Missing or invalid bearer token |
| 403 | Insufficient role or unload not permitted by token policy |
| 500 | Failed to stop/remove container |

---

### PUT /api/v1/tls

Rotate the intermediary CA certificate and private key used by Caddy's RA-TLS
module for certificate issuance. The new certificate must have the **same
CN** as the current one — changing the CN is rejected because RA-TLS
hostnames are derived from it.

After a successful update the manager:
1. Writes the new cert and key to disk (atomically)
2. Reloads the Caddy configuration so the RA-TLS module uses the new CA
3. Recomputes the platform Merkle tree (the CA cert is a leaf)

**Request body**

```json
{
  "ca_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "ca_key": "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ca_cert` | string | yes | PEM-encoded CA certificate (must be CA=true, same CN) |
| `ca_key` | string | yes | PEM-encoded CA private key |

**Response** `200 OK`

```json
{
  "status": "updated",
  "cn": "Privasys Intermediary CA",
  "not_before": "2026-01-01T00:00:00Z",
  "not_after": "2027-01-01T00:00:00Z"
}
```

**Error responses**

| Status | Condition |
|--------|----------|
| 400 | Missing fields, invalid PEM, not a CA cert, or CN mismatch |
| 401 | Missing or invalid bearer token |
| 403 | Insufficient role |
| 500 | Failed to write files or reload Caddy |

---

### PUT /api/v1/attestation-servers

Replace the attestation server list (URLs and optional bearer tokens).
Changes take effect immediately: the Merkle tree and OID extensions are
recomputed so that subsequent RA-TLS certificates reflect the new
attestation servers hash (OID `1.3.6.1.4.1.65230.2.7`).

Bearer tokens are sent as `Authorization: Bearer <token>` when the
platform verifies quotes against authenticated attestation servers.

**Request body**

```json
{
  "servers": [
    { "url": "https://as.privasys.org/", "token": "eyJhbGciOiJSUzI1NiIs..." },
    { "url": "https://as.your-server.com/" }
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `servers` | array | yes | Attestation server entries |
| `servers[].url` | string | yes | Attestation server verification URL |
| `servers[].token` | string | no | Optional OIDC bearer token |

**Response** `200 OK`

```json
{
  "status": "attestation_servers_updated",
  "server_count": 2,
  "hash": "a1b2c3d4..."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `server_count` | int | Number of attestation servers now configured |
| `hash` | string | Hex-encoded SHA-256 of the canonical URL list |

**Error responses**

| Status | Condition |
|--------|----------|
| 400 | Missing or empty servers array |
| 401 | Missing or invalid bearer token |
| 403 | Insufficient role |

---

### PUT /api/v1/clock/config

Pin the clock monitor: the platform service that polls this runtime with a
signed "the time is at least T" and receives its clock incidents (see
[Trusted time](../README.md#trusted-time)). Sent by the management service.
The config is kept on the encrypted `/data` volume.

**Request body**

```json
{
  "enclave_id": "3f0c...-uuid",
  "monitor_key": "base64url, no padding, 32-byte Ed25519 public key",
  "monitor_key_id": "0123456789abcdef",
  "incident_url": "https://monitor.example/api/v1/clock/incidents",
  "config_version": 3
}
```

| Field | Type | Description |
|-------|------|-------------|
| `enclave_id` | string | The id the management service knows this enclave by. Must match the manager's `--enclave-id` when one is set |
| `monitor_key` | string | The monitor's Ed25519 public key |
| `monitor_key_id` | string | First 16 hex characters of lowercase hex SHA-256 of the raw 32-byte key; must match `monitor_key` |
| `incident_url` | string | `https://` URL incidents are posted to |
| `config_version` | int | A lower version than the one held is refused; the same version is a no-op; a higher one replaces the config |

**Response** `200 OK`

```json
{ "status": "ok", "monitor_key_id": "0123456789abcdef", "config_version": 3 }
```

**Error responses**

| Status | Condition |
|--------|----------|
| 400 | Invalid body, key, key id, URL or enclave id |
| 401 | Missing or invalid bearer token |
| 403 | Insufficient role |
| 409 | `config_version` lower than the one held |

---

### POST /api/v1/clock/poll

The clock monitor's poll. No bearer token: the Ed25519 signature under the
pinned monitor key is the authentication, and the reply is authentic through
the RA-TLS channel it travels on. Reached on the enclave's `-mgr` hostname
(or by IP), which gateways keep routing while an enclave is quarantined.

**Request body**

```json
{ "enclave_id": "3f0c...-uuid", "t_ms": 1789000000000, "seq": 42,
  "key_id": "0123456789abcdef", "sig": "base64url" }
```

`sig` is the Ed25519 signature of the UTF-8 bytes of these lines joined with
`\n` (no trailing newline): `privasys-clock-floor/v1`, `enclave_id`, `t_ms`,
`seq` (decimal).

The runtime compares `t_ms` with its host clock. Within 10 s, the host time
is confirmed and raises the floor. Otherwise it asks NTS servers, which
decide whether the monitor or the host is wrong; a wrong host freezes
trusted time at the NTS time and flags the clock. A `t_ms` below the floor is
ignored (a replay or a slow monitor).

**Response** `200 OK`

```json
{ "enclave_id": "3f0c...-uuid", "runtime": "virtual",
  "host_time_ms": 1789000000123, "trusted_time_ms": 1789000000123,
  "floor_ms": 1789000000123, "flagged": false, "reason": "",
  "verdict": "in_sync",
  "nts": { "time_ms": 0, "servers": [] },
  "config_key_id": "0123456789abcdef" }
```

| Field | Description |
|-------|-------------|
| `verdict` | `in_sync`, `monitor_clock_wrong`, `host_clock_wrong` or `ignored_stale` |
| `flagged`, `reason` | The clock's flag: `host_clock_wrong` or `host_behind_floor`. `reason` is `nts_unreachable` with `trusted_time_ms` 0 while the runtime has no trusted time (boot fetch or a refetch failing) |
| `nts` | The NTS result this poll used, when it needed one (`time_ms` 0 otherwise) |
| `config_key_id` | The monitor key id this runtime holds; the management service re-pushes the config until it matches |

**Error responses**

| Status | Condition |
|--------|----------|
| 400 | Malformed body |
| 401 | Wrong enclave id, key id, or signature |
| 409 | No clock monitor pinned yet |
| 503 | Host and monitor disagree and NTS is unreachable: the runtime fails closed until NTS answers |

---

## Error format

All error responses use a consistent JSON envelope:

```json
{ "error": "description of the problem" }
```

## Authentication header

```
Authorization: Bearer <token>
```

The token is an OIDC bearer token issued by the configured provider.
See [setup.md](setup.md) for OIDC provider setup.
