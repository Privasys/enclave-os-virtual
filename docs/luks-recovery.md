# LUKS Data Recovery

This guide explains how to recover data from the LUKS2-encrypted data partition
of an Enclave OS (Virtual) instance. You will need the **passphrase** that was used
when the instance was first booted (BYOK) or, if the instance used an
auto-generated key, the passphrase from that single boot session (which is only
available in memory while the instance is running).

> **Prerequisite:** You must have the LUKS passphrase. Without it, the data
> is cryptographically unrecoverable.

---

## Scenario: Export and mount on a recovery VM

The production instance's boot disk contains four partitions:

| # | Label | Filesystem | Purpose |
|---|-------|-----------|---------|
| 1 | `esp` | vfat | EFI System Partition |
| 2 | `root` | erofs | Read-only root (dm-verity protected) |
| 3 | `root-verity` | DM_verity_hash | Verity hash tree |
| 4 | `data` | LUKS2 (AEAD) → ext4 | Encrypted + integrity-protected application data |

Only partition 4 contains user data. The procedure below attaches the disk to a
standard (non-confidential) VM and unlocks the LUKS volume with your passphrase.

### 1. Stop the production instance (or snapshot its disk)

```bash
# Option A — stop the instance and detach the disk
gcloud compute instances stop enclave-os-production \
    --project=privasys-production --zone=europe-west9-a

gcloud compute instances detach-disk enclave-os-production \
    --disk=enclave-os-production \
    --project=privasys-production --zone=europe-west9-a

# Option B — create a snapshot instead (non-destructive)
gcloud compute disks snapshot enclave-os-production \
    --project=privasys-production --zone=europe-west9-a \
    --snapshot-names=enclave-data-recovery-$(date +%Y%m%d)

# Then create a disk from the snapshot
gcloud compute disks create recovery-disk \
    --project=privasys-production --zone=europe-west9-a \
    --source-snapshot=enclave-data-recovery-$(date +%Y%m%d)
```

### 2. Create a recovery VM and attach the disk

```bash
gcloud compute instances create recovery-vm \
    --project=privasys-production --zone=europe-west9-a \
    --machine-type=e2-medium \
    --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud

# Attach the production disk (or recovery-disk from snapshot)
gcloud compute instances attach-disk recovery-vm \
    --disk=enclave-os-production \
    --project=privasys-production --zone=europe-west9-a \
    --device-name=enclave-disk
```

### 3. SSH into the recovery VM

```bash
gcloud compute ssh recovery-vm \
    --project=privasys-production --zone=europe-west9-a
```

### 4. Identify the data partition

```bash
# The attached disk appears as /dev/sdb (or /dev/nvme1n1 on newer VMs).
# List partitions:
sudo lsblk -o NAME,SIZE,TYPE,FSTYPE,PARTLABEL

# You should see something like:
#   sdb       12G  disk
#   ├─sdb1   512M  part  vfat     esp
#   ├─sdb2   ~5G   part  erofs    root
#   ├─sdb3   ~34M  part           root-verity
#   └─sdb4    10G  part  crypto_LUKS  data

# Alternatively, find by partition label:
sudo blkid | grep data
# → /dev/sdb4: ... TYPE="crypto_LUKS" PARTLABEL="data"
```

### 5. Unlock the LUKS volume

```bash
# Install cryptsetup if not present
sudo apt-get update && sudo apt-get install -y cryptsetup

# Open the LUKS volume with your passphrase
# Replace YOUR_PASSPHRASE with your actual BYOK passphrase
printf '%s' 'YOUR_PASSPHRASE' | sudo cryptsetup luksOpen /dev/sdb4 data-recovery --key-file=-

# Verify it opened
ls /dev/mapper/data-recovery
```

### 6. Mount and access the data

```bash
sudo mkdir -p /mnt/enclave-data
sudo mount /dev/mapper/data-recovery /mnt/enclave-data

# Browse the recovered data
ls -la /mnt/enclave-data/

# Copy data to the recovery VM's local disk, GCS, etc.
# Example — copy to a GCS bucket:
gcloud storage cp -r /mnt/enclave-data/ gs://my-recovery-bucket/enclave-data/
```

### 7. Clean up

```bash
# Unmount and close the LUKS volume
sudo umount /mnt/enclave-data
sudo cryptsetup luksClose data-recovery

# Detach and delete the recovery VM when done
exit
gcloud compute instances detach-disk recovery-vm \
    --disk=enclave-os-production \
    --project=privasys-production --zone=europe-west9-a

gcloud compute instances delete recovery-vm \
    --project=privasys-production --zone=europe-west9-a --quiet
```

---

## Scenario: Live export from a running instance

If the instance is still running, you can copy data out through the application
layer (e.g. the manager API) or, if you have serial console / SSH access:

```bash
# On the running enclave instance, the LUKS volume is already mounted at /data
# Copy files to a GCS bucket directly:
gcloud storage cp -r /data/ gs://my-backup-bucket/enclave-data/
```

> **Note:** Serial console access requires `enable-oslogin=TRUE` and
> appropriate IAM permissions. The read-only root filesystem does not include
> SSH by default.

---

## Scenario: Migrate data to a new instance

To move the encrypted data to a new Enclave OS (Virtual) instance:

1. **Snapshot** the production disk (see step 1 above).
2. **Create a new instance** using the snapshot as the boot disk, with the
   **same** `luks-passphrase` in metadata:

```bash
gcloud compute instances create enclave-os-production-v2 \
    --project=privasys-production --zone=europe-west9-a \
    --machine-type=c3-standard-4 \
    --network-interface=nic-type=GVNIC \
    --maintenance-policy=TERMINATE \
    --create-disk=auto-delete=yes,boot=yes,source-snapshot=enclave-data-recovery-20260305,size=12,type=pd-balanced \
    --shielded-secure-boot \
    --shielded-vtpm \
    --shielded-integrity-monitoring \
    --confidential-compute-type=TDX \
    --tags=https-server \
    --metadata=luks-passphrase=YOUR_PASSPHRASE
```

The `luks-setup` script will detect the existing LUKS volume on partition 4 and
unlock it with the provided passphrase. No data loss occurs.

---

## Key management best practices

| Practice | Rationale |
|----------|-----------|
| Use BYOK in production | Auto-generated keys exist only in memory for a single boot — data is lost on reboot/termination |
| Store the passphrase in a secrets manager | e.g. GCP Secret Manager, HashiCorp Vault, 1Password |
| Rotate the passphrase periodically | Use `cryptsetup luksChangeKey` on the unlocked volume |
| Test recovery before production | Run through this procedure on a staging instance first |
| Keep disk snapshots | Snapshots preserve the encrypted bytes — you can always recover later with the correct passphrase |

---

## Passphrase rotation

To change the LUKS passphrase on a running instance (with serial console access):

```bash
# Add a new passphrase (you'll be prompted for the old one first)
sudo cryptsetup luksChangeKey /dev/disk/by-partlabel/data

# Then update the instance metadata to match
gcloud compute instances add-metadata enclave-os-production \
    --project=privasys-production --zone=europe-west9-a \
    --metadata=luks-passphrase=NEW_PASSPHRASE
```

Alternatively, use `luksAddKey` to add a second passphrase before removing the
old one (safer — avoids a window where no working key exists):

```bash
printf '%s' 'OLD_PASSPHRASE' | sudo cryptsetup luksAddKey /dev/disk/by-partlabel/data --key-file=- <<< 'NEW_PASSPHRASE'
printf '%s' 'OLD_PASSPHRASE' | sudo cryptsetup luksRemoveKey /dev/disk/by-partlabel/data --key-file=-
```
