# Egress tunnels: enclaves with no open ports

An enclave reached through an egress tunnel accepts no inbound connection at
all. It dials out to every platform-gateway instance and holds a multiplexed
connection to each; the gateways carry client traffic, and the management
service's calls to the manager API, down those connections. The host needs
outbound TCP 443 and nothing else: no public IP, no port forward, no firewall
exception.

This is the transport for hosts we do not operate (a university machine room,
a customer's rack) and the intended default for new enclaves.

## Trust

The tunnel changes the transport, not the trust model.

- TLS still ends inside the TD. A tunnel stream carries exactly the bytes a
  TCP connection to the enclave's :443 would: the client's own RA-TLS
  handshake (splice), or the gateway's RA-TLS handshake with its OID policy
  check (terminate, sealed-WebSocket mux). The gateway and the host see the
  same ciphertext they see today.
- The tunnel itself is authenticated with the enclave's attested identity
  (`enclaveauth`: a leaf issued by the enclave's own CA, a TDX quote binding
  that leaf's key, and a signature over the upgrade request's method, path
  and body). The gateway holds no enclave key material: it forwards the
  signed request to the management service, which verifies it and names the
  enclave. A forged tunnel could only attract traffic it cannot decrypt; the
  check keeps routing honest and makes that a non-event.
- Inside the enclave, tunnel streams are delivered to Caddy on loopback.
  Nothing in Caddy or the manager trusts an external peer's address (the
  manager's in-enclave checks look at the Caddy-to-manager hop, which is
  loopback for direct traffic too), and every stream is its own loopback
  connection, so per-connection state stays per client.

## Protocol (`privasys-tunnel/1`)

```
enclave                               gateway                          management
   │ TCP :443, TLS 1.3                   │                                   │
   │ SNI tunnel.<apps domain>            │                                   │
   │ ALPN privasys-tunnel/1 ────────────►│ (recognised before route lookup)  │
   │ POST /__privasys/tunnel             │                                   │
   │ Upgrade: privasys-tunnel/1          │                                   │
   │ X-Enclave-Id/-Identity/-Challenge/  │                                   │
   │   -Evidence/-Ts/-Nonce/-Sig         │                                   │
   │ {"enclave_id","gateway"} ──────────►│ POST /api/v1/internal/tunnel/     │
   │                                     │      authorize ──────────────────►│ verify signature,
   │                                     │ ◄──────────────── {"enclave_id"}  │ quote, CA, nonce
   │ ◄──────── 101 Switching Protocols   │                                   │
   │ ═══════════ yamux session ═════════ │                                   │
   │ ◄── stream: [1][u16 n][client addr] │                                   │
   │      then raw bytes ⇄ Caddy :443    │                                   │
```

- The gateway is the yamux client (it opens streams); the enclave accepts.
- Stream preamble: `u8 version (1) | u16 BE length | client address`. The
  address is informational (logs); it is not authenticated and grants
  nothing.
- yamux keepalives every 15 s; a dead path is dropped within ~30 s and the
  enclave reconnects with jittered exponential backoff (1 s to 1 min).

## Routing

- A route whose `upstream` is `tunnel:<enclave_id>` is dialed by opening a
  stream on that enclave's session at the gateway instance that received the
  client. Every other upstream is dialed over TCP as before, so direct and
  tunnelled enclaves coexist.
- Gateway instances share no state (DNS round-robin), so an enclave holds a
  tunnel to **each** instance: `TUNNEL_GATEWAYS` lists them individually.
- The management API is reached the same way, through the enclave's
  `<enclave>-mgr` route.

## Configuration

Enclave (`/data/manager.env`, delivered in the redeem payload's
`manager_env`):

| Key | Meaning |
|---|---|
| `TUNNEL_GATEWAYS` | Comma-separated gateway instances, `host:port`. Empty = no tunnel (reached directly). |
| `TUNNEL_SERVER_NAME` | TLS name presented to the gateways. Default `tunnel.<HOSTNAME_SUFFIX>`. |

Gateway: `-tunnels` / `GATEWAY_TUNNELS=true` (requires terminate mode, whose
public certificate the tunnel TLS uses).

Management service: a tunnelled enclave's routes carry `tunnel:<id>`
upstreams, its manager API calls go through the gateway's `-mgr` route, and it
has no dialable `gateway_host`.
