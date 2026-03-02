# build/

Image build infrastructure for Enclave OS Virtual.

## image/

[mkosi](https://github.com/systemd/mkosi)-based build configuration that produces a UKI (Unified Kernel Image) with Secure Boot and dm-verity root filesystem. The resulting image boots directly into the Confidential VM with an immutable, measured root filesystem.

See [docs/setup.md](../docs/setup.md) for the on-image file layout.
