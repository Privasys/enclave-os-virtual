# build/

Image build infrastructure for Enclave OS (Virtual).

## Dependencies

Both base and GPU images depend on [cvm-images](https://github.com/Privasys/cvm-images)
for infrastructure-layer configs:

- **common/** - SSH hardening, GCE key lookup, network config, sysctl, volatile
  mounts (tmp, var-log, var-tmp), tmpfiles, and resolv.conf
- **images/tdx-base/** - TDX boot chain (kernel cmdline, Secure Boot, signed GRUB),
  and post-installation scripts (vmlinuz symlink, GRUB install)
- **images/tdx-gpu/** (GPU only) - NVIDIA APT repos, driver pinning, prepare
  scripts, nvidia-persistenced enable, and GPU kernel cmdline

The build script (`build.sh`) fetches cvm-images automatically. In a monorepo
workspace it symlinks to `../../infra/cvm-images`; otherwise it clones from
GitHub.

## image/

[mkosi](https://github.com/systemd/mkosi)-based build configuration that produces a UKI (Unified Kernel Image) with Secure Boot and dm-verity root filesystem. The resulting image boots directly into the Confidential VM with an immutable, measured root filesystem.

See [docs/setup.md](../docs/setup.md) for the on-image file layout.
