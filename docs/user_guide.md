# SnpGuard User Guide

## Quick Start

### 1. Build the Project

```bash
# Build everything
make build

# Or build separately
make build-server
make build-client
```

### 2. Initialize Database

```bash
make db-setup
```

This creates the SQLite database at `data/snpguard.db`.

### 3. Start the Server

```bash
export DATABASE_URL="sqlite://data/snpguard.db?mode=rwc"
make run-server
```

Or with custom credentials:

```bash
export DATABASE_URL="sqlite://data/snpguard.db?mode=rwc"
export SNPGUARD_USERNAME="admin"
export SNPGUARD_PASSWORD="your-password"
make run-server
```

### 4. Access Management UI

Open your browser and navigate to:
```
http://localhost:3000
```

Log in with your credentials (default: `admin` / `secret`).

## Creating an Attestation Record

### Step 1: Generate Keys

First, generate the EC private keys for ID-Block and Auth-Block:

```bash
# ID-Block key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out id-block-key.pem

# Auth-Block key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out id-auth-key.pem
```

**Important**: Keep these keys secure! They are used to generate the ID-Block and Auth-Block, but are not stored by the service.

### Step 2: Prepare Boot Artifacts

You'll need:
- **Firmware**: OVMF firmware binary (usually `OVMF_CODE.fd` or `AmdSev-OVMF.fd`)
- **Kernel**: Linux kernel binary (e.g., `vmlinuz-6.8.0-55-generic`)
- **Initrd**: Initial ramdisk image (e.g., `initrd.img-6.8.0-55-generic`)

### Step 3: Fill the Form

1. Click **"Create New Record"** in the management UI
2. Fill in the form:
   - **OS Name**: A descriptive name (e.g., "Ubuntu 22.04 Production")
   - **ID Block Key**: Upload the `id-block-key.pem` file
   - **Auth Block Key**: Upload the `id-auth-key.pem` file
   - **Firmware**: Upload the firmware `.fd` file
   - **Kernel**: Upload the kernel binary
   - **Initrd**: Upload the initrd image
   - **Kernel Parameters**: Base kernel parameters (e.g., `console=ttyS0 root=UUID=...`)
   - **vCPUs**: Number of virtual CPUs (e.g., `4`)
   - **vCPU Type**: Select your EPYC variant (EPYC, EPYC-Milan, EPYC-Rome, EPYC-Genoa)
   - **Service URL**: The HTTPS URL of your attestation service (e.g., `https://attest.example.com`)
   - **Disk Secret**: The secret to release upon successful attestation

3. Click **"Generate & Save"**

The service will:
- Generate measurements using `snpguest`
- Create ID-Block and Auth-Block
- Compute key digests
- Store the record

### Step 4: Download Artifacts

After creation, you can download:
- **ID-Block** and **Auth-Block** binaries
- **Tarball** (`artifacts.tar.gz`) with all files
- **SquashFS** (`artifacts.squashfs`) image

These artifacts need to be provided to your VM boot process.

## Preparing the Guest VM

### Step 1: Repack Initrd

The initrd needs to include the `snpguard-client` binary and the attestation hook.

```bash
make repack INITRD_IN=/path/to/original-initrd.img INITRD_OUT=/path/to/new-initrd.img
```

Or manually:

```bash
./scripts/repack-initrd.sh /path/to/original-initrd.img /path/to/new-initrd.img
```

**Prerequisites**:
- The client binary must be built: `make build-client`
- `snpguest` tool must be available in the initrd's PATH

### Step 2: Configure Kernel Parameters

Add the attestation URL to your kernel command line:

```
rd.attest.url=https://your-attestation-service.com
```

For example, in GRUB:

```grub
linux /vmlinuz root=UUID=... rd.attest.url=https://attest.example.com
initrd /new-initrd.img
```

### Step 3: Boot the VM

Boot the VM. The attestation will happen automatically during the initrd phase, after network initialization but before root filesystem mounting.

## Managing Attestation Records

### Viewing Records

The main page shows all attestation records with:
- **Status**: Active (green) or Disabled (gray)
- **OS Name**: Click to view/edit
- **Requests**: Number of successful attestations
- **Actions**: Edit or Delete

### Editing Records

Click on an OS name to view/edit the record.

You can:
- **Enable/Disable**: Toggle the attestation record
- **Update Fields**: Change OS name, secret, kernel parameters, etc.
- **Upload New Files**: Replace firmware, kernel, initrd, or keys
- **Download Artifacts**: Get ID-Block, Auth-Block, tarball, or SquashFS

**Note**: Uploading new files or changing the service URL will regenerate the ID-Block and Auth-Block.

### Disabling Records

You can temporarily disable an attestation record:
- Click the **"Disable"** button on the record view page
- Or use the toggle checkbox in the edit form

Disabled records will cause attestation requests to fail, but the record remains in the database.

### Deleting Records

Click **"Delete"** on the main page or record view page. This permanently removes the record and all associated artifacts.

## Using the Client Directly

You can also use the client tool directly (useful for testing):

```bash
snpguard-client --url https://attest.example.com
```

The client will:
1. Request a nonce
2. Generate an attestation report
3. Send it for verification
4. Output the secret to stdout on success

**Example** (piping secret to cryptsetup):

```bash
SECRET=$(snpguard-client --url https://attest.example.com)
echo -n "$SECRET" | cryptsetup luksOpen /dev/sda2 root_crypt --key-file=-
```

## Troubleshooting

### Client Connection Issues

**Problem**: Client fails to connect to server

**Solutions**:
- Verify the URL is correct and uses HTTPS
- Check network connectivity from the guest VM
- Ensure TLS certificate is valid
- Check server logs for errors

### Attestation Fails

**Problem**: Attestation verification fails

**Solutions**:
1. **Check Record Status**: Ensure the attestation record is enabled
2. **Verify Key Digests**: The ID-Block and Auth-Block keys must match those used to create the record
3. **Check CPU Family**: Ensure the vCPU type matches your actual CPU
4. **Review Server Logs**: Check for detailed error messages
5. **Verify Report**: Ensure `snpguest` is generating valid reports

### Report Verification Fails

**Problem**: Server cannot verify the attestation report

**Solutions**:
- Ensure `snpguest` is installed and in PATH on the server
- Check network connectivity to AMD KDS (for certificate fetching)
- Verify the attestation report is not corrupted
- Check that the CPU family detection is correct

### File Upload Issues

**Problem**: File upload fails or is rejected

**Solutions**:
- Check file size limits:
  - Firmware: <10 MB
  - Kernel: <50 MB
  - Initrd: <50 MB
- Ensure files are in the correct format
- Check server disk space

### Initrd Repacking Issues

**Problem**: Repacked initrd doesn't work

**Solutions**:
- Ensure `snpguest` is available in the initrd
- Verify the client binary is built for the correct architecture
- Check that the initrd format is supported (initramfs-tools or dracut)
- Test the repacked initrd in a VM before production use

## Best Practices

### Security

1. **Use Strong Passwords**: Set strong credentials for the management UI
2. **Enable TLS**: Always use HTTPS in production
3. **Secure Key Storage**: Keep ID-Block and Auth-Block keys secure
4. **Network Security**: Restrict access to the attestation service
5. **Regular Updates**: Keep the server and dependencies updated

### Key Management

1. **Backup Keys**: Keep secure backups of ID-Block and Auth-Block keys
2. **Key Rotation**: Consider rotating keys periodically
3. **Separate Keys**: Use different keys for different environments (dev, staging, prod)

### Monitoring

1. **Request Counts**: Monitor the request count to detect unusual activity
2. **Failed Attestations**: Set up alerts for failed attestation attempts
3. **Server Logs**: Regularly review server logs for errors

### Performance

1. **Certificate Caching**: Consider caching AMD certificates to reduce latency
2. **Database Optimization**: For large deployments, consider PostgreSQL
3. **Artifact Storage**: For distributed deployments, use shared storage

## Advanced Usage

### Custom Initrd Hooks

You can customize the initrd hook script to integrate with your specific boot process. The hook is installed at:
- `scripts/local-top/snpguard_attest` (initramfs-tools)
- `lib/dracut/hooks/pre-mount/99-snpguard.sh` (dracut)

### API Integration

You can integrate the attestation API into your own tools. See `docs/api.md` for details.

### Environment Variables

**Server**:
- `DATABASE_URL`: Database connection string (required)
- `SNPGUARD_USERNAME`: Management UI username (default: "admin")
- `SNPGUARD_PASSWORD`: Management UI password (default: "secret")
- `TLS_CERT`: Path to TLS certificate (optional, for HTTPS)
- `TLS_KEY`: Path to TLS private key (optional, for HTTPS)

**Client**:
- No environment variables required

## Getting Help

- **Documentation**: See `docs/` directory for detailed documentation
- **Issues**: Open an issue on the GitHub repository
- **Logs**: Check server logs for detailed error messages
