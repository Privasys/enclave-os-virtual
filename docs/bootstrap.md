# Authentication & Bootstrap

Enclave OS Virtual starts empty — no containers, no OIDC provider. This
document explains the two authentication mechanisms and how the initial
bootstrap works.

See also: [API Reference](api.md) · [Setup & Configuration](setup.md)

## Authentication methods

Every API request (except `GET /healthz`) must carry a bearer token in the
`Authorization: Bearer <token>` header. The manager accepts two token types:

### 1. Operations Certificate JWT (break-glass)

A short-lived JWT signed with the Privasys operations private key (ECDSA
P-256). The corresponding public certificate is baked into the image at
`/etc/enclave-os/operations.crt` and cannot be changed at runtime.

| Field | Value |
|-------|-------|
| Algorithm | ES256 |
| Issuer (`iss`) | `privasys-operations` |
| Expiry (`exp`) | Required, typically 5–15 minutes |

This token type is **always accepted**, regardless of OIDC configuration. It
receives implicit `manager` role privileges. Use it for:

- **Bootstrap**: loading the first containers before any OIDC
  provider exists.
- **Break-glass**: emergency access when OIDC is unavailable.
- **Automation**: CI/CD pipelines that deploy directly.

### 2. OIDC bearer token

A standard JWT issued by the configured OIDC provider. The manager
discovers signing keys via `/.well-known/openid-configuration` → JWKS,
with a 5-minute cache.

| Field | Value |
|-------|-------|
| Algorithm | RS256, RS384, RS512, ES256, ES384, ES512 |
| Audience (`aud`) | `enclave-os-virtual` |
| Issuer (`iss`) | Must match `--oidc-issuer` |

## Roles

Two roles control what the bearer can do:

| Role | Claim value | Access |
|------|-------------|--------|
| Manager | `enclave-os-virtual:manager` | Full: load/unload containers, status, metrics |
| Monitoring | `enclave-os-virtual:monitoring` | Read-only: readyz, status, metrics |

The manager checks for roles in three claim locations (to support different
providers):

1. **Role-claim map**: `urn:zitadel:iam:org:project:roles` (default) — a
   map where the role name is a key.
2. **Standard**: `roles` — a flat string array.
3. **Keycloak**: `realm_access.roles` — a nested string array.

Operations certificate JWTs do not need a role claim — they always have
manager-level access.

## Containers claim (policy)

Both token types support an optional `containers` claim to restrict which
containers the bearer can load/unload:

```json
{
  "containers": [
    { "name": "myapp", "digest": "sha256:abc123..." },
    { "name": "postgres", "digest": "sha256:def456..." }
  ]
}
```

- **Load**: the image reference must contain the `@<digest>` of a permitted
  entry.
- **Unload**: the container name must match a permitted entry.
- **Omitted claim**: all containers are permitted (implicit full trust).

## Bootstrap sequence

```
┌───────────────────────────────────────────────────────────┐
│  1. Instance boots — manager starts with no containers    │
│     Only operations cert JWT is accepted                  │
│                                                           │
│  2. Operator signs a short-lived JWT with the             │
│     operations private key, containing:                   │
│     { iss: "privasys-operations", exp: ...,               │
│       containers: [{ name: "myapp", digest: "..." },      │
│                    { name: "postgres", digest: "..." }] } │
│                                                           │
│  3. POST /api/v1/containers with operations JWT           │
│     → loads application + database containers             │
│                                                           │
│  4. OIDC provider starts (if loaded)                      │
│     Now OIDC tokens are also accepted                     │
│                                                           │
│  5. Subsequent operations use OIDC bearer tokens:         │
│     - enclave-os-virtual:manager for mutations            │
│     - enclave-os-virtual:monitoring for read-only         │
└───────────────────────────────────────────────────────────┘
```
