# API Reference

The management API is exposed exclusively through Caddy on `:443` at
`manager.<machine-name>.<hostname>`, secured with RA-TLS. All endpoints
except `/healthz` require an OIDC bearer token in the `Authorization` header.

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

"Monitoring+" means the `enclave-os-virtual:monitoring` role or the
`enclave-os-virtual:manager` role (manager implies monitoring).

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
| `port` | int | yes | Container listening port |
| `env` | object | no | Environment variables |
| `volumes` | string[] | no | Host:container mount paths |
| `command` | string[] | no | Override default entrypoint |
| `internal` | bool | no | If true, not externally accessible |
| `health_check` | object | no | Health check (see below) |
| `vault_token` | string | no | Injected as `VAULT_TOKEN` env var (runtime secret, excluded from attestation) |

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

Rotate the intermediary CA certificate and private key used by ra-tls-caddy
for RA-TLS certificate issuance. The new certificate must have the **same
CN** as the current one — changing the CN is rejected because RA-TLS
hostnames are derived from it.

After a successful update the manager:
1. Writes the new cert and key to disk (atomically)
2. Reloads the Caddy configuration so ra-tls-caddy uses the new CA
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
