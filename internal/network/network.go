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
	log.Info("container network ready",
		zap.String("bridge", BridgeName), zap.String("gateway", GatewayIP), zap.String("subnet", Subnet))
	return nil
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
