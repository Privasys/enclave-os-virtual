# Authentication & Bootstrap

Enclave OS (Virtual) uses OIDC bearer tokens as the sole authentication
mechanism. The OIDC provider must be running **before** the enclave
instance boots.

See also: [API Reference](api.md) · [Setup & Configuration](setup.md)

## Authentication

Every API request (except `GET /healthz`) must carry a bearer token in the
`Authorization: Bearer <token>` header.

The token is a standard JWT issued by the configured OIDC provider. The
manager discovers signing keys via `/.well-known/openid-configuration` →
JWKS, with a 5-minute cache.

| Field | Value |
|-------|-------|
| Algorithm | RS256, RS384, RS512, ES256, ES384, ES512 |
| Audience (`aud`) | `enclave-os-virtual` |
| Issuer (`iss`) | Must match `--oidc-issuer` |

## Roles

Two roles control what the bearer can do:

| Role | Claim value | Access |
|------|-------------|--------|
| Manager | `privasys-platform:manager` | Full: load/unload containers, status, metrics |
| Monitoring | `privasys-platform:monitoring` | Read-only: readyz, status, metrics |

Manager access implies monitoring access.

The manager checks for roles in three claim locations (to support different
providers):

1. **Role-claim map**: `urn:zitadel:iam:org:project:roles` (default) — a
   map where the role name is a key.
2. **Standard**: `roles` — a flat string array.
3. **Keycloak**: `realm_access.roles` — a nested string array.

## Containers claim (policy)

Tokens support an optional `containers` claim to restrict which
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

The OIDC provider runs on a separate (classic) VM and must be reachable
before the enclave instance is started. This avoids a chicken-and-egg
problem — the enclave can verify tokens from boot.

```
┌───────────────────────────────────────────────────────────┐
│  0. OIDC provider is already running on a classic VM      │
│     (e.g. Zitadel, Keycloak, or any OIDC-compliant IdP)   │
│                                                           │
│  1. Instance boots — manager starts with no containers    │
│     --oidc-issuer points to the external OIDC provider    │
│                                                           │
│  2. Operator obtains an OIDC token with manager role:     │
│     { aud: "enclave-os-virtual",                          │
│       roles: ["privasys-platform:manager"],               │
│       containers: [{ name: "myapp", digest: "..." }] }    │
│                                                           │
│  3. POST /api/v1/containers with OIDC bearer token        │
│     → loads application containers                        │
│                                                           │
│  4. Subsequent operations use OIDC bearer tokens:         │
│     - privasys-platform:manager for mutations             │
│     - privasys-platform:monitoring for read-only          │
└───────────────────────────────────────────────────────────┘
```
