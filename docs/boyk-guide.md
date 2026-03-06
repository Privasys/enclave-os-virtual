# BYOK Deployment Guide

## Generate a strong passphrase

On your local machine:

```powershell
# Generate a 256-bit random passphrase (base64-encoded, 44 chars)
python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Or with OpenSSL:

```bash
openssl rand -base64 32
```

**Store this passphrase securely** (password manager, hardware security module, Privasys Enclave Vaults, etc.). It is the only key that can unlock your data partition. If you lose it and the instance is destroyed, the data is unrecoverable.

## Create the production instance

Pass the passphrase via the `luks-passphrase` metadata attribute. The luks-setup script reads it from the GCP metadata server at boot and uses it to format (first boot) or unlock (subsequent boots) the LUKS2 volume. The OID 2.6 `DataEncryptionKeyOrigin` will report `external`.

```bash
gcloud compute instances create enclave-os-production \
    --project=privasys-production \
    --zone=europe-west9-a \
    --machine-type=c3-standard-4 \
    --network-interface=nic-type=GVNIC \
    --maintenance-policy=TERMINATE \
    --create-disk=auto-delete=yes,boot=yes,image=projects/production-123456/global/images/enclave-os-virtual-v0-12-0,size=12,type=pd-balanced \
    --shielded-secure-boot \
    --shielded-vtpm \
    --shielded-integrity-monitoring \
    --confidential-compute-type=TDX \
    --tags=https-server \
    --metadata=luks-passphrase=YOUR_PASSPHRASE_HERE
```

Replace `YOUR_PASSPHRASE_HERE` with the value you generated above.

## What happens at first boot

1. luks-data.service runs luks-setup before `data.mount`
2. Script fetches `luks-passphrase` from GCP metadata → sets `KEY_SOURCE=byok`
3. Detects `/dev/disk/by-partlabel/data` is NOT yet LUKS → runs `cryptsetup luksFormat --type luks2 --integrity aead`
4. Opens the volume → creates ext4 on `/dev/mapper/data-crypt`
5. Writes `external` to `/run/luks/dek-origin` → OID 2.6 reports `external` in the RA-TLS certificate

## On reboots

The same metadata passphrase unlocks the existing LUKS volume. No re-format occurs.
