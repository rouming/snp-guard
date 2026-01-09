# Initrd Support: initramfs-tools and dracut

SnpGuard supports both major Linux initrd systems: **initramfs-tools** (used by Ubuntu/Debian) and **dracut** (used by RedHat/CentOS/Fedora and derivatives).

## Automatic Detection

The repack script (`scripts/repack-initrd.sh`) automatically detects which initrd format is being used and installs the appropriate hook:

### Detection Logic

1. **initramfs-tools**: Detected by presence of `scripts/` directory
2. **dracut**: Detected by presence of `lib/dracut/hooks` or `usr/lib/dracut/hooks` directory

If both are detected (rare), both hooks will be installed for maximum compatibility.

## initramfs-tools (Ubuntu, Debian)

### Hook Location
```
scripts/local-top/snpguard_attest
```

### Boot Phase
- **Phase**: `local-top`
- **Timing**: After network initialization, before root filesystem mounting
- **Purpose**: Ensures network is available for attestation, but runs before disk decryption

### Hook Structure
```bash
#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case $1 in prereqs) prereqs; exit 0 ;; esac

# Attestation logic here
```

### Supported Distributions
- Ubuntu (all versions)
- Debian (all versions)
- Linux Mint
- Other Debian-based distributions

## dracut (RedHat, CentOS, Fedora)

### Hook Location
```
lib/dracut/hooks/pre-mount/99-snpguard.sh
```
or
```
usr/lib/dracut/hooks/pre-mount/99-snpguard.sh
```

### Boot Phase
- **Phase**: `pre-mount`
- **Timing**: Before root filesystem mounting
- **Purpose**: Runs after network is available but before root mount

### Hook Structure
```bash
#!/bin/bash
# SnpGuard attestation hook for dracut

# Attestation logic here
```

### Supported Distributions
- RedHat Enterprise Linux (RHEL)
- CentOS
- Fedora
- Rocky Linux
- AlmaLinux
- Oracle Linux
- Other RHEL-based distributions

## Boot Sequence

Both hooks follow a similar boot sequence:

```
1. Kernel loads
2. Initrd starts
3. Network initialization
4. [SnpGuard Hook Runs Here] ← Attestation happens
   - Reads rd.attest.url from /proc/cmdline
   - Calls snpguard-client
   - Receives secret
5. Root filesystem mounting
6. Disk decryption (using secret from step 4)
7. System boot continues
```

## Hook Behavior

Both hooks implement the same logic:

1. **Parse kernel command line** for `rd.attest.url=...`
2. **Wait for network** (2 second delay to ensure network is up)
3. **Call attestation client**: `/bin/snpguard-client --url "$ATTEST_URL"`
4. **Capture secret** to `/tmp/disk-secret`
5. **Handle errors**: Exit with error if attestation fails

## Usage

The repack script handles everything automatically:

```bash
./scripts/repack-initrd.sh /path/to/original-initrd.img /path/to/new-initrd.img
```

The script will:
1. Extract the initrd (using `unmkinitramfs` if available, or manual cpio extraction)
2. Install `snpguard-client` binary
3. Detect the initrd format
4. Install the appropriate hook
5. Repack the initrd

## Verification

After repacking, you can verify the hook was installed:

### For initramfs-tools:
```bash
# Extract and check
unmkinitramfs new-initrd.img /tmp/check
ls -la /tmp/check/main/scripts/local-top/snpguard_attest
```

### For dracut:
```bash
# Extract and check
cd /tmp/check
zcat new-initrd.img | cpio -idm
ls -la lib/dracut/hooks/pre-mount/99-snpguard.sh
```

## Troubleshooting

### Hook Not Running

1. **Check hook exists**: Verify the hook file is present in the repacked initrd
2. **Check permissions**: Ensure the hook has execute permissions (`chmod +x`)
3. **Check boot logs**: Look for "SnpGuard: Starting attestation..." messages
4. **Verify kernel parameter**: Ensure `rd.attest.url=...` is in kernel command line

### Wrong Hook Installed

- The script auto-detects the format
- If detection fails, both hooks will be installed
- This is safe and ensures compatibility

### Network Not Available

- Both hooks include a 2-second delay to allow network initialization
- If network is still not available, the attestation will fail
- Ensure network is configured in the initrd (standard for both systems)

## Differences Between Systems

| Feature | initramfs-tools | dracut |
|---------|----------------|--------|
| Hook location | `scripts/local-top/` | `lib/dracut/hooks/pre-mount/` |
| Hook name | `snpguard_attest` | `99-snpguard.sh` |
| Script type | `/bin/sh` | `/bin/bash` |
| Prereq function | Required | Not used |
| Detection | `scripts/` directory | `dracut/hooks/` directory |

## Best Practices

1. **Test before production**: Always test the repacked initrd in a VM first
2. **Verify hook execution**: Check boot logs to confirm the hook runs
3. **Network configuration**: Ensure network is properly configured in initrd
4. **Backup original**: Keep a backup of the original initrd image
5. **Documentation**: Document which initrd format you're using
