module github.com/Privasys/enclave-os-virtual

go 1.26.0

toolchain go1.26.10

// RA-TLS v2 builds with stock Go: no TLS extension, no fork (the evidence
// exchange runs after the handshake over the RFC 8446 exporter).
// Build with: go build ./cmd/manager

require (
	enclave-os-mini/clients/go v0.0.0
	github.com/Privasys/enclave-vaults-client/go v0.0.0
	github.com/beevik/ntp v1.6.0
	github.com/beevik/nts v0.3.3
	github.com/caddyserver/certmagic v0.25.6
	github.com/coder/websocket v1.8.15
	github.com/containerd/containerd/api v1.10.0
	github.com/containerd/containerd/v2 v2.2.10
	github.com/containerd/errdefs v1.0.0
	github.com/containerd/platforms v1.0.0-rc.2
	github.com/ebitengine/purego v0.10.1
	github.com/fxamacker/cbor/v2 v2.9.6
	github.com/hashicorp/yamux v0.1.2
	github.com/mholt/acmez/v3 v3.1.7
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.1
	github.com/opencontainers/runtime-spec v1.3.0
	github.com/prometheus/client_golang v1.23.2
	go.uber.org/zap v1.28.0
	golang.org/x/crypto v0.58.0
	golang.org/x/sync v0.24.0
	golang.org/x/sys v0.49.0
	gopkg.in/yaml.v3 v3.0.1
)

// Sibling checkouts: ra-tls-clients' module path (enclave-os-mini/clients/go)
// is not resolvable, so both SDKs are consumed via replace — the org-wide
// pattern (management-service does the same). CI clones the two repos to
// these relative locations; locally they match the standard workspace
// layout (Privasys/{platform,enclave-os}/...).
replace (
	enclave-os-mini/clients/go => ../../platform/ra-tls-clients/go
	github.com/Privasys/enclave-vaults-client/go => ../../platform/enclave-vaults-client/go
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Microsoft/hcsshim v0.14.1 // indirect
	github.com/aead/cmac v0.0.0-20160719120800-7af84192f0b1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/caddyserver/zerossl v0.1.6 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/cgroups/v3 v3.1.2 // indirect
	github.com/containerd/continuity v0.4.5 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/plugin v1.0.0 // indirect
	github.com/containerd/ttrpc v1.2.7 // indirect
	github.com/containerd/typeurl/v2 v2.2.3 // indirect
	github.com/cyphar/filepath-securejoin v0.5.1 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/libdns/libdns v1.1.1 // indirect
	github.com/miekg/dns v1.1.73 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/capability v0.4.0 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/sequential v0.6.0 // indirect
	github.com/moby/sys/signal v0.7.1 // indirect
	github.com/moby/sys/user v0.5.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/opencontainers/runtime-tools v0.9.1-0.20251114084447-edf4cb3d2116 // indirect
	github.com/opencontainers/selinux v1.15.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/secure-io/siv-go v0.0.0-20180922214919-5ff40651e2c4 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.60.0 // indirect
	go.opentelemetry.io/otel v1.45.0 // indirect
	go.opentelemetry.io/otel/metric v1.45.0 // indirect
	go.opentelemetry.io/otel/trace v1.45.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260817212433-ac3dfec99bb1 // indirect
	google.golang.org/grpc v1.85.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
	tags.cncf.io/container-device-interface v1.1.0 // indirect
	tags.cncf.io/container-device-interface/specs-go v1.1.0 // indirect
)

// Caddy is built as a separate binary via xcaddy in build.sh (not embedded
// in the manager). The RA-TLS module (caddy/ratls/) and caddy are not Go
// dependencies of this module - they are only build-time dependencies of
// the image.
// github.com/Privasys/enclave-os-virtual/caddy/ratls
// github.com/caddyserver/caddy/v2 v2.9.1
// github.com/google/go-tdx-guest v0.3.1

replace github.com/secure-io/siv-go => ./third_party/siv-go
