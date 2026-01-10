# SnpGuard - SEV-SNP Attestation Service

**SnpGuard** is an open-source SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging) attestation service written in Rust. It provides a secure, scalable solution for verifying the integrity and authenticity of guest virtual machines running on AMD EPYC processors with SEV-SNP support.

## Motivation

SEV-SNP provides hardware-based memory encryption and integrity protection for virtual machines. However, to fully leverage these security features, you need a way to:

1. **Verify VM Integrity**: Ensure that a guest VM is running the expected firmware, kernel, and initrd images
2. **Secure Secret Release**: Only release secrets (e.g., disk encryption keys) to VMs that pass attestation
3. **Centralized Management**: Manage attestation policies and secrets from a central service
4. **Automated Boot Process**: Integrate attestation seamlessly into the VM boot process

SnpGuard addresses these needs by providing:
- A **management frontend** for configuring attestation records
- An **attestation service** that verifies SEV-SNP reports using AMD's certificate chain
- A **lightweight client** that runs in the guest VM's initrd to perform attestation during boot
- **HTTPS/TLS communication** with Protocol Buffers for secure, efficient data exchange

## Architecture

```
┌─────────────────┐         HTTPS/TLS + Protobuf        ┌──────────────────┐
│  Guest VM       │ ───────────────────────────────────> │  SnpGuard Server │
│  (initrd)       │                                       │                 │
│                 │ <─────────────────────────────────── │  - Verifies     │
│  snpguard-client│         Nonce + Attestation Report    │    Reports      │
│                 │                                       │  - Releases     │
│  Uses snpguest  │                                       │    Secrets      │
│  tool           │                                       │  - Manages      │
└─────────────────┘                                       │    Records      │
                                                          └──────────────────┘
                                                                     │
                                                                     │ HTTP
                                                                     ▼
                                                          ┌──────────────────┐
                                                          │  Management UI    │
                                                          │  (Web Frontend)  │
                                                          └──────────────────┘
```

## Features

- ✅ **HTTPS/TLS Communication**: Secure attestation protocol using TLS with certificate verification
- ✅ **Protocol Buffers**: Efficient binary serialization for attestation messages
- ✅ **AMD Certificate Verification**: Automatic fetching and verification of AMD VCEK certificates
- ✅ **CPU Family Detection**: Automatic detection of CPU family (Genoa, Milan, Turin) from attestation reports
- ✅ **Management Web UI**: Modern, user-friendly interface for managing attestation records
- ✅ **Static Client Binary**: Client built with musl libc for inclusion in initrd images
- ✅ **Initrd Integration**: Scripts for embedding attestation into both initramfs-tools and dracut initrds
- ✅ **Artifact Generation**: Automatic generation of ID-Block and Auth-Block from user-provided keys
- ✅ **Secret Management**: Secure storage and release of secrets upon successful attestation

## Prerequisites

### Server Requirements

- Rust toolchain (1.70+)
- SQLite (for database)
- `mksquashfs` (for SquashFS artifact generation)
- `tar` and `gzip` (for tarball generation)
- TLS certificate and key (for production HTTPS)

**Note**: The `snpguest` tool is now included as a git submodule and built automatically as part of the project.

### Client Requirements (in Guest VM)

- `snpguest` tool in the initrd (can be built from the included submodule)
- Network connectivity during boot
- Kernel parameter: `rd.attest.url=https://your-attestation-service.com`

## Building

### Build Everything

```bash
make build
```

This builds the server, statically-linked client, and `snpguest` tool.

### Build Server Only

```bash
make build-server
```

### Build Client Only (Static, musl)

```bash
make build-client
```

The client is built for `x86_64-unknown-linux-musl` to avoid glibc dependencies.

### Build snpguest Tool Only (Static, musl)

```bash
make build-snpguest
```

The `snpguest` tool is built from the included git submodule for `x86_64-unknown-linux-musl`.

## Setup

### 1. Initialize Database

```bash
make db-setup
```

This creates the SQLite database and runs migrations.

### 2. Configure Authentication (Optional)

Set environment variables for management UI authentication:

```bash
export SNPGUARD_USERNAME="admin"
export SNPGUARD_PASSWORD="your-secure-password"
```

Default credentials are `admin`/`secret` if not set.

### 3. Configure TLS (Production)

For production, provide TLS certificate and key:

```bash
export TLS_CERT="/path/to/cert.pem"
export TLS_KEY="/path/to/key.pem"
```

### 4. Run Server

```bash
export DATABASE_URL="sqlite://data/snpguard.db?mode=rwc"
make run-server
```

Or manually:

```bash
export DATABASE_URL="sqlite://data/snpguard.db?mode=rwc"
cargo run --bin snpguard-server
```

The server will listen on:
- **Management UI**: `http://localhost:3000` (or `https://` if TLS is configured)
- **Attestation API**: `http://localhost:3000/attestation/*` (or `https://` if TLS is configured)

## Usage

### Creating an Attestation Record

1. **Access Management UI**: Navigate to `http://localhost:3000` and log in
2. **Click "Create New Record"**
3. **Fill in the form**:
   - **OS Name**: Descriptive name for this VM configuration
   - **ID Block Key**: PEM-encoded EC private key (secp384r1)
     ```bash
     openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out id-block-key.pem
     ```
   - **Auth Block Key**: PEM-encoded EC private key (secp384r1)
     ```bash
     openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out id-auth-key.pem
     ```
   - **Firmware Image**: OVMF firmware binary (<10 MB)
   - **Kernel Binary**: Linux kernel image (<50 MB)
   - **Initrd Image**: Initial ramdisk (<50 MB)
   - **Kernel Parameters**: Additional kernel command-line parameters
   - **vCPUs**: Number of virtual CPUs
   - **vCPU Type**: EPYC, EPYC-Milan, EPYC-Rome, or EPYC-Genoa
   - **Service URL**: HTTPS URL of this attestation service
   - **Secret**: Secret to be released upon successful attestation

4. **Click "Generate & Save"**

The service will:
- Generate measurements using `snpguest`
- Create ID-Block and Auth-Block
- Compute key digests for lookup
- Store the attestation record

### Downloading Artifacts

From the record view page, you can download:
- **ID-Block** and **Auth-Block** binaries
- **Tarball** (`artifacts.tar.gz`) with all files at root level
- **SquashFS** (`artifacts.squashfs`) with proper permissions

### Preparing Guest VM

1. **Repack Initrd** with the attestation client:

```bash
make repack INITRD_IN=/path/to/original-initrd.img INITRD_OUT=/path/to/new-initrd.img
```

Or manually:

```bash
./scripts/repack-initrd.sh /path/to/original-initrd.img /path/to/new-initrd.img
```

The repack script automatically detects and supports both:
- **initramfs-tools** (Ubuntu, Debian): Installs hook at `scripts/local-top/snpguard_attest`
- **dracut** (RedHat, CentOS, Fedora): Installs hook at `lib/dracut/hooks/pre-mount/99-snpguard.sh`

Both hooks run after network initialization but before root filesystem mounting, ensuring attestation happens at the correct boot phase.

2. **Ensure `snpguest` is in initrd**: The script expects `snpguest` to be available in the initrd's PATH

3. **Configure Kernel Parameters**: Add to your kernel command line:

```
rd.attest.url=https://your-attestation-service.com
```

4. **Boot the VM**: The attestation will happen automatically during boot

### Attestation Flow

1. **Guest VM boots** and network is initialized
2. **Initrd hook runs** (`snpguard_attest` script)
3. **Client requests nonce** from attestation service via HTTPS
4. **Client generates report** using `snpguest report` with the nonce
5. **Client sends report** to attestation service
6. **Service verifies**:
   - Fetches AMD certificates (CA and VCEK)
   - Verifies certificate chain
   - Verifies attestation report signature
   - Extracts key digests from report
   - Looks up matching attestation record
   - Checks if record is enabled
7. **Service responds** with success and secret (if verification passes)
8. **Client outputs secret** to stdout (can be piped to `cryptsetup` or other tools)

## API Reference

### Attestation Endpoints

#### POST `/attestation/nonce`

Request a random 64-byte nonce for attestation report generation.

**Request** (Protobuf):
```protobuf
message NonceRequest {
  string vm_id = 1;
}
```

**Response** (Protobuf):
```protobuf
message NonceResponse {
  bytes nonce = 1;  // 64 bytes
}
```

#### POST `/attestation/verify`

Verify an attestation report and return secret if successful.

**Request** (Protobuf):
```protobuf
message AttestationRequest {
  bytes report_data = 1;
  string cpu_family_hint = 2;  // Optional: "genoa", "milan", "turin"
}
```

**Response** (Protobuf):
```protobuf
message AttestationResponse {
  bool success = 1;
  bytes secret = 2;
  string error_message = 3;
}
```

### Management Endpoints

- `GET /` - List all attestation records
- `GET /create` - Create new record form
- `POST /create` - Submit new record
- `GET /view/:id` - View/edit record
- `POST /view/:id` - Update record
- `POST /toggle/:id` - Enable/disable record
- `GET /delete/:id` - Delete record
- `GET /download/:id/:file` - Download artifact

## Command Line

### Client

```bash
snpguard-client --url https://attestation-service.com
```

The client:
- Connects to the attestation service via HTTPS
- Requests a nonce
- Generates an attestation report using `snpguest`
- Sends the report for verification
- Outputs the secret to stdout on success

## Security Considerations

1. **TLS Certificates**: Always use valid TLS certificates in production. The client verifies certificates to prevent man-in-the-middle attacks.

2. **Key Management**: The ID-Block and Auth-Block private keys should be kept secure. They are used to generate the blocks but are not stored by the service (only their digests are stored).

3. **Secret Storage**: Secrets are stored in the database. Consider encrypting the database or using a secrets management system for production.

4. **Network Security**: Ensure the attestation service is only accessible from trusted networks or use firewall rules.

5. **Nonce Verification**: While the current implementation focuses on signature verification, consider implementing stricter nonce tracking for additional security.

## Troubleshooting

### Client fails to connect

- Verify TLS certificate is valid
- Check network connectivity from guest VM
- Ensure `rd.attest.url` kernel parameter is set correctly

### Attestation fails

- Check that the attestation record exists and is enabled
- Verify that the key digests match (ID-Block and Auth-Block keys)
- Ensure CPU family detection is correct
- Check server logs for detailed error messages

### Report verification fails

- Verify `snpguest` is installed and in PATH
- Check network connectivity to AMD KDS (for certificate fetching)
- Ensure the attestation report is valid and not corrupted

## Development

### Project Structure

```
snp-guard/
├── snpguest/            # Git submodule: AMD SEV-SNP tool
├── src/
│   ├── client/          # Attestation client (for initrd)
│   ├── server/          # Attestation service
│   └── common/          # Shared protobuf definitions
├── entity/              # Database entities
├── migration/          # Database migrations
├── protos/              # Protocol buffer definitions
├── ui/                  # Web UI templates
├── scripts/             # Utility scripts
└── docs/                # Documentation
```

### Running Tests

```bash
cargo test
```

### Code Formatting

```bash
cargo fmt
```

### Linting

```bash
cargo clippy
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[Specify your license here]

## References

- [AMD SEV-SNP Documentation](https://www.amd.com/en/developer/sev.html)
- [snpguest Tool](https://github.com/virtee/snpguest) (included as git submodule)
- [SEV-SNP Attestation Guide](https://rouming.github.io/2025/04/01/coco-with-amd-sev.html)

## Support

For issues and questions, please open an issue on the GitHub repository.
