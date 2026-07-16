// Copyright (c) Privasys. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

// Package network gives each container its OWN network namespace behind a
// host bridge, replacing the historical "every container shares the host
// network namespace" model (see bugs-and-fixes #45).
//
// Why: the platform co-locates multiple, mutually-untrusting apps on one
// enclave. Under host networking they shared one loopback, so app A's
// 127.0.0.1:<port> service (e.g. an embedded Postgres) was reachable by app B.
// With a private netns per container, 127.0.0.1 is private to each app, and
// bridge PORT ISOLATION stops apps reaching each other's bridge IP too — the
// gateway (manager) and egress are the only reachable peers.
//
// Model:
//   - One host bridge "privasys0" with the manager/gateway at 10.88.0.1/16.
//   - Each container gets a veth pair: the host end is an ISOLATED bridge port,
//     the container end is "eth0" with a DETERMINISTIC IP derived from the
//     container's allocated $PORT (10.88.<port/256>.<port%256>). Ports are
//     already unique per enclave (the launcher dedupes them), so the mapping is
//     1:1 and stable across manager restarts — no IP state to persist/replay.
//   - Egress is NAT/masquerade out of the host's default interface.
//   - The container reaches the manager at the gateway (10.88.0.1:9443); the
//     launcher injects PRIVASYS_MANAGER_URL so the in-container SDK targets it.
//
// It shells out to `ip`/`bridge`/`iptables`/`sysctl` (matching how the rest of
// the codebase drives `vgs`/`cryptsetup`/`mountpoint`); there is no netlink
// dependency in the tree.
package network

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"go.uber.org/zap"
)

const (
	// BridgeName is the host bridge every container attaches to.
	BridgeName = "privasys0"
	// GatewayIP is the bridge address; the manager binds here so containers
	// (and the host: Caddy, health probes) can reach it.
	GatewayIP = "10.88.0.1"
	// gatewayCIDR is GatewayIP with the /16 the container subnet lives in.
	gatewayCIDR = "10.88.0.1/16"
	// Subnet is the container address space.
	Subnet = "10.88.0.0/16"
	// ManagerPort is the plain-HTTP management API port the SDK calls back on.
	ManagerPort = 9443
	// ResolvConfPath is the resolv.conf bind-mounted over /etc/resolv.conf of
	// every container. The host's own file points at systemd-resolved's
	// 127.0.0.53 stub, which inside a private netns is the container's own
	// (empty) loopback — Setup materialises the REAL upstream nameservers
	// here instead.
	ResolvConfPath = "/run/containers-dns/resolv.conf"
	// HostsPath is the /etc/hosts bind-mounted over every container's own
	// (see writeHosts for why). Same directory as ResolvConfPath so one
	// MkdirAll covers both.
	HostsPath = "/run/containers-dns/hosts"
	// upstreamResolvConf is where systemd-resolved keeps the real upstream
	// nameserver list (as opposed to /etc/resolv.conf's stub pointer).
	upstreamResolvConf = "/run/systemd/resolve/resolv.conf"
	// fallbackNameserver{Primary,Secondary} are the public resolvers written
	// into the container resolv.conf when no usable upstream is available.
	// This used to be the link-local metadata IP (169.254.169.254), but
	// containers are now firewalled off that address (Setup drops
	// container->link-local; it exposes the VM's SA token and boot secrets),
	// and pointing untrusted DNS at the untrusted host metadata plane leaked
	// query names. Cloudflare + Google, reachable from any cloud via egress.
	fallbackNameserverPrimary   = "1.1.1.1"
	fallbackNameserverSecondary = "8.8.8.8"
	// linkLocalCIDR is the range every major cloud's instance metadata service
	// sits on (169.254.169.254 on GCE/AWS/Azure). Containers are dropped from
	// reaching it — see Setup.
	linkLocalCIDR = "169.254.0.0/16"
)

// ContainerIP is the deterministic bridge IP for a container listening on the
// given (enclave-unique) port. Stable across restarts, so a manager replay
// re-derives the same address with no persisted allocator.
func ContainerIP(port int) string {
	return fmt.Sprintf("10.88.%d.%d", (port>>8)&0xff, port&0xff)
}

// ManagerURL is the callback URL injected into containers as
// PRIVASYS_MANAGER_URL. Plain HTTP — Caddy terminates TLS on :443; the
// management API itself listens plain on the gateway.
func ManagerURL() string {
	return fmt.Sprintf("http://%s:%d", GatewayIP, ManagerPort)
}

// hostVeth is the host-side veth name for a container port. Kept short and
// unique (<=15 chars: "pv" + up to 5 digits = 7).
func hostVeth(port int) string { return fmt.Sprintf("pv%d", port) }

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// quiet runs a command whose failure is expected/ignorable (idempotent adds,
// best-effort deletes).
func quiet(name string, args ...string) { _ = exec.Command(name, args...).Run() }

// Setup creates the bridge, gateway address, forwarding and egress NAT. It is
// idempotent — safe to call on every manager boot.
func Setup(log *zap.Logger) error {
	if _, err := net.InterfaceByName(BridgeName); err != nil {
		if err := run("ip", "link", "add", BridgeName, "type", "bridge"); err != nil {
			return fmt.Errorf("network: create bridge: %w", err)
		}
	}
	quiet("ip", "addr", "add", gatewayCIDR, "dev", BridgeName) // idempotent
	if err := run("ip", "link", "set", BridgeName, "up"); err != nil {
		return fmt.Errorf("network: bridge up: %w", err)
	}
	// Enable IPv4 forwarding so egress from the container subnet is routed out.
	// Written to /proc directly to avoid a procps/sysctl binary dependency in
	// the minimal enclave image.
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("network: ip_forward: %w", err)
	}
	// Egress masquerade (check-then-add so it is idempotent). The table flag
	// must precede the command: iptables parses `-A <chain>` as one unit.
	nat := []string{"POSTROUTING", "-s", Subnet, "!", "-o", BridgeName, "-j", "MASQUERADE"}
	if exec.Command("iptables", append([]string{"-t", "nat", "-C"}, nat...)...).Run() != nil {
		if err := run("iptables", append([]string{"-t", "nat", "-A"}, nat...)...); err != nil {
			return fmt.Errorf("network: masquerade: %w", err)
		}
	}
	// Block containers from the cloud metadata plane. A co-located, untrusted
	// app that reached 169.254.169.254 could mint the VM's service-account
	// token (the default compute SA: project-wide GCS read + Pub/Sub) and read
	// boot secrets delivered as instance attributes — the /data LUKS
	// passphrase and the bootstrap service key. The manager and host reach
	// metadata from the host netns (a local OUTPUT path, never forwarded), so
	// this FORWARD drop leaves platform access untouched. Inserted at the head
	// of FORWARD so it wins over any later accept rule; check-then-insert keeps
	// it idempotent across manager reboots.
	block := []string{"FORWARD", "-s", Subnet, "-d", linkLocalCIDR, "-j", "DROP"}
	if exec.Command("iptables", append([]string{"-C"}, block...)...).Run() != nil {
		if err := run("iptables", "-I", "FORWARD", "1", "-s", Subnet, "-d", linkLocalCIDR, "-j", "DROP"); err != nil {
			return fmt.Errorf("network: metadata guard: %w", err)
		}
	}
	// The management API binds on all interfaces so BOTH the host (Caddy,
	// health probes at localhost:9443) and containers (at the gateway) reach it
	// on one listener. Close it on the external interface: accept :9443 only
	// from loopback and the bridge, drop the rest. Keeps host-side callers
	// unchanged while the manager is no longer exposed on the VM's public IP.
	// Three rules because iptables rejects two -i matches in one rule; the
	// ACCEPTs must precede the DROP, which appending in order guarantees.
	port := fmt.Sprintf("%d", ManagerPort)
	guards := [][]string{
		{"INPUT", "-p", "tcp", "--dport", port, "-i", "lo", "-j", "ACCEPT"},
		{"INPUT", "-p", "tcp", "--dport", port, "-i", BridgeName, "-j", "ACCEPT"},
		{"INPUT", "-p", "tcp", "--dport", port, "-j", "DROP"},
	}
	for _, g := range guards {
		if exec.Command("iptables", append([]string{"-C"}, g...)...).Run() != nil {
			if err := run("iptables", append([]string{"-A"}, g...)...); err != nil {
				return fmt.Errorf("network: manager-port guard: %w", err)
			}
		}
	}
	if err := writeResolvConf(); err != nil {
		return fmt.Errorf("network: resolv.conf: %w", err)
	}
	if err := writeHosts(); err != nil {
		return fmt.Errorf("network: hosts: %w", err)
	}
	log.Info("container network ready",
		zap.String("bridge", BridgeName), zap.String("gateway", GatewayIP), zap.String("subnet", Subnet))
	return nil
}

// writeResolvConf publishes the container resolv.conf from systemd-resolved's
// real upstreams, with any link-local metadata resolver stripped (see
// buildResolvConf), falling back to public DNS. Containers reach the result
// through the bridge NAT.
func writeResolvConf() error {
	if err := os.MkdirAll("/run/containers-dns", 0o755); err != nil {
		return err
	}
	return os.WriteFile(ResolvConfPath, buildResolvConf(), 0o644)
}

// buildResolvConf returns the container resolv.conf body: systemd-resolved's
// upstream nameservers with any link-local metadata resolver (169.254.x)
// removed, falling back to public DNS when that leaves none. The strip is
// essential, not cosmetic: on GCE the DHCP-issued upstream IS the metadata IP
// (169.254.169.254), so copying it verbatim would black-hole container DNS now
// that Setup drops container->link-local. Only nameserver lines are
// propagated; search/options are dropped (they reference host-internal zones
// containers should not chase).
func buildResolvConf() []byte {
	raw, _ := os.ReadFile(upstreamResolvConf) // nil on error → falls back to public DNS
	return resolvConfFrom(raw)
}

// resolvConfFrom is the pure core of buildResolvConf, split out so the
// link-local strip (a fleet-wide DNS outage if it regresses) is unit-testable
// without the filesystem.
func resolvConfFrom(upstream []byte) []byte {
	var nameservers []string
	for _, line := range strings.Split(string(upstream), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if strings.HasPrefix(fields[1], "169.254.") {
				continue // link-local metadata resolver — unreachable from containers
			}
			nameservers = append(nameservers, fields[1])
		}
	}
	if len(nameservers) == 0 {
		nameservers = []string{fallbackNameserverPrimary, fallbackNameserverSecondary}
	}
	var b strings.Builder
	b.WriteString("# generated by enclave-os-virtual\n")
	for _, ns := range nameservers {
		b.WriteString("nameserver " + ns + "\n")
	}
	return []byte(b.String())
}

// hostsContent is the /etc/hosts published to every container. Minimal images
// (distroless, scratch, alpine slims) frequently ship without an /etc/hosts,
// or without a `localhost` entry — the host runtime is normally responsible
// for synthesising one (Docker/podman both do). Since containers moved into a
// private netns, nothing was writing it, so a `localhost` lookup fell through
// to DNS and got NXDOMAIN — the fleet embed/rerank bug (a Go service dialling
// localhost). Pinning it here also fail-closes a hardening gap: without the
// entry, `localhost` resolution goes to the bridge upstream resolvers, where a
// hostile resolver could answer it with a routable address and pull
// loopback-assumed traffic out of the TEE. Both families, because Go/glibc
// resolve `localhost` to v4 and v6.
const hostsContent = `127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
`

// writeHosts publishes the shared container /etc/hosts. Static content, so it
// is written once per manager boot alongside the resolv.conf; the per-container
// bridge IP is deliberately NOT added here (would force a per-container file),
// as the localhost entry is all the isolation model needs.
func writeHosts() error {
	if err := os.MkdirAll("/run/containers-dns", 0o755); err != nil {
		return err
	}
	return os.WriteFile(HostsPath, []byte(hostsContent), 0o644)
}

// Attach wires a freshly-created container (identified by its init PID, i.e.
// its netns) to the bridge on its deterministic IP. Call after the containerd
// task is created but BEFORE it is started. Returns the assigned IP.
func Attach(log *zap.Logger, pid int, port int) (string, error) {
	ip := ContainerIP(port)
	host := hostVeth(port)
	tmp := "tmp" + host
	ns := fmt.Sprintf("%d", pid)

	// Clear any stale veth from a prior failed attempt (best-effort).
	quiet("ip", "link", "del", host)

	if err := run("ip", "link", "add", host, "type", "veth", "peer", "name", tmp); err != nil {
		return "", fmt.Errorf("network: veth add: %w", err)
	}
	fail := func(err error) (string, error) { quiet("ip", "link", "del", host); return "", err }

	// Move the peer into the container's netns.
	if err := run("ip", "link", "set", tmp, "netns", ns); err != nil {
		return fail(fmt.Errorf("network: move veth to netns %s: %w", ns, err))
	}
	// Host side: attach to the bridge as an ISOLATED port (can talk to the
	// bridge/gateway and out to egress, but NOT to other isolated ports =
	// other containers), and bring it up.
	if err := run("ip", "link", "set", host, "master", BridgeName); err != nil {
		return fail(fmt.Errorf("network: enslave %s: %w", host, err))
	}
	if err := run("bridge", "link", "set", "dev", host, "isolated", "on"); err != nil {
		return fail(fmt.Errorf("network: isolate %s: %w", host, err))
	}
	if err := run("ip", "link", "set", host, "up"); err != nil {
		return fail(fmt.Errorf("network: host veth up: %w", err))
	}
	// Container side (via nsenter into its netns): eth0 + address + routes + lo.
	nse := func(args ...string) error {
		return run("nsenter", append([]string{"-t", ns, "-n"}, args...)...)
	}
	if err := nse("ip", "link", "set", tmp, "name", "eth0"); err != nil {
		return fail(fmt.Errorf("network: rename to eth0: %w", err))
	}
	if err := nse("ip", "addr", "add", ip+"/16", "dev", "eth0"); err != nil {
		return fail(fmt.Errorf("network: addr %s: %w", ip, err))
	}
	if err := nse("ip", "link", "set", "eth0", "up"); err != nil {
		return fail(fmt.Errorf("network: eth0 up: %w", err))
	}
	if err := nse("ip", "link", "set", "lo", "up"); err != nil {
		return fail(fmt.Errorf("network: lo up: %w", err))
	}
	if err := nse("ip", "route", "add", "default", "via", GatewayIP); err != nil {
		return fail(fmt.Errorf("network: default route: %w", err))
	}
	log.Info("container attached to bridge",
		zap.Int("port", port), zap.String("ip", ip), zap.String("veth", host))
	return ip, nil
}

// Detach removes a container's veth (both ends go with the host end). Safe to
// call on a container that was never attached.
func Detach(port int) {
	quiet("ip", "link", "del", hostVeth(port))
}
