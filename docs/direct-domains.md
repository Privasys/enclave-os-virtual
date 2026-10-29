# Direct domains

A direct domain is an adopter hostname whose TLS ends in the enclave, with a
publicly trusted certificate the enclave obtains itself. The platform
gateway splices the name at L4 and never holds a certificate for it, so it
sees ciphertext only, and the browser loads the app's page straight from
measured code.

The app's platform hostname is unchanged: it stays the attested address that
RA-TLS clients dial. A direct domain is an extra name on the same app route.

## The legs a request can arrive on

The runtime stamps `X-Privasys-Transport` on every request it hands to an app
(and strips any value a client sent):

| Transport | How the request arrived | Who read it | Client verified the enclave |
|---|---|---|---|
| `attested` | TLS ended here with the RA-TLS leaf | the enclave only | could (RA-TLS clients do) |
| `sealed` | body sealed under a session key, through the gateway | the enclave only | yes, through the session bootstrap |
| `public` | plaintext on the gateway-terminated leg, declared surface only | the gateway too | no |
| `direct` | TLS ended here with the publicly trusted certificate of a direct name | the enclave only | no |

The leg of a request on a direct name is decided from the connection, never
from the request: the certificate getter records which certificate each
connection was served, and anything not positively served the RA-TLS leaf
(a resumed session included) is the direct leg.

## Certificates

- The owner names the domains in the signed app policy (`domains`). Only those
  names are ever requested.
- The ACME account key is a one-way branch of the app's vault-backed volume
  key, so only measurements the vault releases that key to can use the
  account, and it survives upgrades. An app without a vault-backed volume
  cannot have direct domains.
- The adopter's DNS carries a CAA record pinning issuance to that account
  (RFC 8657), for example
  `shop.example.com. CAA 0 issue "letsencrypt.org; accounturi=<account>; validationmethods=tls-alpn-01"`.
  Nobody else, the platform included, can then obtain a certificate for the
  name.
- Each certificate key is generated in the enclave and stored on the encrypted
  `/data` volume, in the storage root it shares with Caddy.
- Issuance uses ACME TLS-ALPN-01 only. Caddy answers the challenge from the
  shared storage; the manager places the orders.
- No order is placed until a validation would reach this enclave. Before
  every issuance (first order, retry, renewal) the manager publishes a
  throwaway TLS-ALPN-01 challenge in the shared storage, connects to the name
  through public DNS offering only `acme-tls/1`, and checks the certificate it
  gets back carries that challenge. Until it does (no DNS yet, or the gateway
  not yet passing the challenge to this enclave), it waits and probes again,
  from two minutes up to every fifteen, without contacting the CA, so the
  CA's failed-validation allowance is never used up by an order that could
  not succeed. Each domain's status carries the last probe:
  `"probe": {"ok", "checked_at", "error"}`.

On a direct name a client offering the `privasys-ratls/1` ALPN still gets the
RA-TLS leaf, with the direct name in its SAN and the app's extensions.

## Binding the public certificate to the attestation

OID `1.3.6.1.4.1.65230.7.4` (direct domain keys) on the app's RA-TLS leaves
lists each direct name with the SHA-256 of its public certificate's
SubjectPublicKeyInfo:

```
shop.example.com sha256:6adac656e60f30144a8bdfe402d786b014dead22f88000a68dcfcacd4311e28b
```

A browser cannot check an attestation, but anyone who attests the app can
compare this value with the certificate the direct name presents. OID
`7.3` (the accepted app policy) identifies the signed document that lists the
names.

## Certificate Transparency watch

Every six hours (jittered) each direct name is searched on crt.sh. Any
unexpired certificate whose key this host did not obtain is logged, counted
in `enclave_os_direct_foreign_certificates{name}` and listed in the status
endpoint. With a CAA record in place there should never be one.

## Private routes on a direct name

By default a direct name gets what the gateway-terminated leg gets: sealed
bodies, plus the declared static and public surfaces. An app can serve its
private routes on direct names too, by declaring in its measured manifest:

```json
{
  "surfaces": {
    "static": ["/", "/assets/"],
    "direct": "private"
  }
}
```

Then a request to a private path on a direct name reaches the app with
transport `direct`. If it carries `Authorization: Bearer <token>`, the
runtime verifies the token against the identity provider configured with
`--oidc-issuer` and requires its audience to be this app: `app:<app id hex>`,
the app's platform hostname, or one of its direct names (never the platform
audience, so a token minted for one app is refused by every other). On
success the token is removed and replaced by:

| Header | Value |
|---|---|
| `X-Privasys-Sub` | the token's subject (the same header the sealed leg carries) |
| `X-Privasys-Attestation-Level` | `verified` when the sign-in was the wallet, `unverified` otherwise |

A token that cannot be verified is refused with 401. No token is an anonymous
request. The direct leg never makes an end user a payer: a priced route
answers 402 unless a spend token names one.

## Client addresses

A spliced connection reaches the enclave from the gateway's address. The
control plane pushes the gateways' addresses to the host with
`PUT /api/v1/edge/proxy-protocol {"from": ["ip or cidr", ...]}` (manager
role); the list is kept on `/data` and survives restarts and runtime rolls.
Caddy then reads a PROXY protocol v2 header on connections from those
addresses only, so per-client rate limits see the real client on direct
names. A header from anyone else is ignored, and a connection without one is
served unchanged. An empty list turns it off.

The gateway sends the header per route, and the control plane marks a direct
route for it only after this host's status reports the list active and
covering every gateway. A host that does not expect a header therefore never
receives one, and nothing has to be enabled in a particular order. Never over
an egress tunnel.

## Manager flags and status

| Flag | Default | Description |
|---|---|---|
| `--direct-storage` | `/data/caddy/caddy` | Storage root shared with Caddy (Caddy's own default, on `/data`). Empty disables direct domains. |
| `--direct-ca` | Let's Encrypt | ACME directory URL |
| `--proxy-protocol-from` | empty | Bootstrap only: gateway addresses (CIDR or IP), env `PROXY_PROTOCOL_FROM`. A list pushed by the control plane replaces it. |

`GET /api/v1/containers/{name}/direct` (manager role) returns:

```json
{
  "supported": true,
  "account_uri": "https://acme-v02.api.letsencrypt.org/acme/acct/123",
  "domains": [
    {"name": "shop.example.com", "issued": true,
     "not_after": "2027-01-27T10:45:21Z", "spki_sha256": "6adac656..."}
  ],
  "ct_checked_at": "2026-10-29T18:00:00Z",
  "ct_error": "",
  "foreign_certificates": [],
  "proxy_protocol": {"supported": true, "active": true, "from": ["203.0.113.10/32"]}
}
```
