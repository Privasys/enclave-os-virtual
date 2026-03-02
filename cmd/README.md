# cmd/

Entry points for Enclave OS Virtual binaries.

## manager

The `manager` binary is the main process running inside the Confidential VM. It connects to containerd, starts the management API, and orchestrates container lifecycle.

```bash
manager serve [flags]
```

See [docs/setup.md](../docs/setup.md) for all flags and configuration options.
See [docs/api.md](../docs/api.md) for the management API reference.
