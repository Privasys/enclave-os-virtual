# API Reference

The manager exposes a single HTTPS endpoint (default `:9443`) for both
management and monitoring operations. All endpoints except `/healthz`
require a bearer token in the `Authorization` header.

See [bootstrap.md](bootstrap.md) for the authentication model and
[setup.md](setup.md) for configuration.

## Endpoints

| Method | Path | Auth | Role | Description |
|--------|------|------|------|-------------|
| GET | `/healthz` | None | — | Liveness probe |
| GET | `/readyz` | Bearer | Monitoring+ | Readiness probe |
| GET | `/api/v1/status` | Bearer | Monitoring+ | Container statuses |
| GET | `/metrics` | Bearer | Monitoring+ | Prometheus metrics |
| GET | `/api/v1/tls` | Bearer | Monitoring+ | TLS certificate metadata |
| PUT | `/api/v1/tls` | Bearer | Manager | Rotate TLS certificate |
| POST | `/api/v1/containers` | Bearer | Manager | Load a container |
| DELETE | `/api/v1/containers/{name}` | Bearer | Manager | Unload a container |

"Monitoring+" means the `enclave-os-virtual:monitoring` role, the
`enclave-os-virtual:manager` role, or an operations certificate JWT.

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
  "hostname": "myapp.example.com",
  "port": 8080,
  "env": {
    "DATABASE_HOST": "localhost"
  },
  "volumes": ["/data/myapp:/data"],
  "command": ["serve"],
  "internal": false,
  "health_check": {
    "http": "http://127.0.0.1:8080/healthz",
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
| `hostname` | string | no | External hostname for SNI routing |
| `port` | int | yes | Container listening port |
| `env` | object | no | Environment variables |
| `volumes` | string[] | no | Host:container mount paths |
| `command` | string[] | no | Override default entrypoint |
| `internal` | bool | no | If true, not externally accessible |
| `health_check` | object | no | Health check (see below) |
| `vault_token` | string | no | Injected as `VAULT_TOKEN` env var (runtime secret, excluded from attestation) |

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

### GET /api/v1/tls

Returns metadata about the current TLS certificate (does not expose the
private key).

**Response** `200 OK`

```json
{
  "subject": "Enclave OS Virtual Instance",
  "issuer": "Privasys Intermediate CA",
  "dns_names": ["*.inst.privasys.org"],
  "not_before": "2026-03-01T00:00:00Z",
  "not_after": "2027-03-01T00:00:00Z",
  "fingerprint": "a1b2c3d4...",
  "serial": "123456789"
}
```

---

### PUT /api/v1/tls

Rotate the server TLS certificate at runtime. The new certificate and key
are validated, persisted to disk, and hot-swapped into the running TLS
listener without restart. This extends the image lifespan — the baked-in
certificate bootstraps TLS, and subsequent rotations happen via this endpoint.

**Request body**

```json
{
  "cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "key": "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----\n"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cert` | string | yes | PEM-encoded certificate (may include chain) |
| `key` | string | yes | PEM-encoded private key |

The `cert` field can include the full chain (leaf + intermediate) concatenated.
Body is limited to 1 MB.

**Response** `200 OK`

```json
{
  "subject": "Enclave OS Virtual Instance",
  "dns_names": ["*.inst.privasys.org"],
  "not_after": "2028-03-01T00:00:00Z",
  "fingerprint": "e5f6a7b8...",
  "status": "rotated"
}
```

**Error responses**

| Status | Condition |
|--------|-----------|
| 400 | Missing fields, invalid PEM, or cert/key mismatch |
| 401 | Missing or invalid bearer token |
| 403 | Insufficient role (manager required) |
| 500 | Failed to persist certificate to disk |

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

The token is either an operations certificate JWT (ES256) or an OIDC bearer
token. See [bootstrap.md](bootstrap.md) for details on both token types.
