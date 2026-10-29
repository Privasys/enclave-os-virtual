package launcher

// PROXY protocol on direct splices: which addresses (the platform gateways)
// this host trusts for a PROXY protocol v2 header carrying a direct client's
// address. The control plane pushes the list; it is kept on /data so it
// survives restarts and runtime rolls. The control plane asks a gateway to
// send the header for a route only once this host reports the list active,
// so a header never reaches a host that does not expect one.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/Privasys/enclave-os-virtual/internal/directtls"
)

type proxyProtocolFile struct {
	From []string `json:"from"`
}

// loadProxyProtocolFrom returns the persisted list, or nil when none was
// ever pushed (the bootstrap flag then applies).
func loadProxyProtocolFrom(path string) ([]string, bool) {
	if path == "" {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var f proxyProtocolFile
	if json.Unmarshal(data, &f) != nil {
		return nil, false
	}
	return f.From, true
}

// SetProxyProtocolFrom replaces the trusted gateway addresses, persists them
// and reconfigures Caddy. An empty list turns the PROXY header off.
func (l *Launcher) SetProxyProtocolFrom(from []string) ([]string, error) {
	if l == nil || l.caddyClient == nil {
		return nil, fmt.Errorf("caddy integration is not configured on this host")
	}
	applied, err := l.caddyClient.SetProxyProtocolFrom(from)
	if err != nil {
		return nil, err
	}
	if l.cfg.ProxyProtocolStatePath != "" {
		data, _ := json.Marshal(proxyProtocolFile{From: applied})
		if err := os.MkdirAll(filepath.Dir(l.cfg.ProxyProtocolStatePath), 0o700); err == nil {
			tmp := l.cfg.ProxyProtocolStatePath + ".tmp"
			if err := os.WriteFile(tmp, data, 0o600); err == nil {
				err = os.Rename(tmp, l.cfg.ProxyProtocolStatePath)
			}
			if err != nil {
				l.log.Warn("proxy protocol list applied but not persisted", zap.Error(err))
			}
		}
	}
	l.log.Info("proxy protocol sources set", zap.Strings("from", applied))
	return applied, nil
}

// ProxyProtocolStatus reports whether this host reads a PROXY header, and
// from where, for the direct status.
func (l *Launcher) ProxyProtocolStatus() *directtls.ProxyProtocolStatus {
	if l == nil || l.caddyClient == nil {
		return nil
	}
	from := l.caddyClient.ProxyProtocolFrom()
	return &directtls.ProxyProtocolStatus{Supported: true, Active: len(from) > 0, From: from}
}
