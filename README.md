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
┌─────────────────┐          HTTPS/TLS + Protobuf         ┌──────────────────┐
│  Guest VM       │ ────────────────────────────────────> │  SnpGuard Server │
│  (initrd)       │                                       │                  │
│                 │ <──────────────────────────────────── │  - Verifies      │
│  snpguard-client│         Nonce + Attestation Report    │    Reports       │
│                 │                                       │  - Releases      │
│  Uses sev lib   │                                       │    Secrets       │
│  tool           │                                       │  - Manages       │
└─────────────────┘                                       │    Records       │
                                                          └──────────────────┘
                                                                     │
                                                                     │ HTTP
                                                                     ▼
                                                          ┌──────────────────┐
                                                          │  Management UI   │
                                                          │  (Web Frontend)  │
                                                          └──────────────────┘
```

## Features

- **HTTPS/TLS Communication**: Secure attestation protocol using TLS with certificate verification
- **Protocol Buffers**: Efficient binary serialization for attestation messages
- **AMD Certificate Verification**: Automatic fetching and verification of AMD VCEK certificates
- **CPU Family Detection**: Automatic detection of CPU family (Genoa, Milan, Turin) from attestation reports
- **Management Web UI**: Modern, user-friendly interface for managing attestation records
- **Static Client Binary**: Client built with musl libc for inclusion in initrd images
- **Initrd Integration**: Scripts for embedding attestation into both initramfs-tools and dracut initrds
- **Artifact Generation**: Automatic generation of ID-Block and Auth-Block from user-provided keys
- **Secret Management**: Secure storage and release of secrets upon successful attestation

## Prerequisites

### Server Requirements

- Rust toolchain (1.70+)
- SQLite (for database)
- `mksquashfs` (for SquashFS artifact generation)
- `tar` and `gzip` (for tarball generation)
- TLS certificate and key (for production HTTPS)

**Note**: The `snpguest` tool is now included as a git submodule and built automatically as part of the project.

### Client Requirements (in Guest VM)

- SEV-SNP enabled hardware and guest firmware
- Network connectivity during boot
- Kernel parameter: `rd.attest.url=https://your-attestation-service.com`

## Building

### Initial Setup

If you're cloning the repository for the first time, initialize the git submodules:

```bash
git submodule update --init --recursive
```

This is required because `snpguest` is included as a git submodule.

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

### 2. Configure DATA_DIR (single persistence root)

All persistent state lives under one directory (default `/data`). Override for local dev:

```bash
export DATA_DIR="$(pwd)/data"
```

Expected layout (created automatically on startup):

```
/data/
 ├── tls/            (server.crt, server.key, ca.pem)
 ├── auth/           (master.pw.hash, ingestion.key, ingestion.pub)
 ├── db/             (snpguard.sqlite)
 ├── artifacts/
 │    ├── attestations/<attestation-id>/
 │    └── tmp/
 └── logs/
```

### 3. Authentication

On first start the service:
- Generates a Diceware passphrase (EFF large wordlist), prints it once to the console.
- Stores only the Argon2 hash at `/data/auth/master.pw.hash` (or `${DATA_DIR}/auth/master.pw.hash`).

Tokens (created from the web UI) can be used as Bearer tokens for management APIs.

### 4. TLS (required)

If `/data/tls/server.crt` and `/data/tls/server.key` are absent, the service auto-generates a self-signed pair (and `ca.pem`) for development. Provide your own by placing them under `/data/tls/` before start.

### 5. Run Server

```bash
DATA_DIR="$(pwd)/data" make run-server
```

Or manually:

```bash
DATA_DIR="$(pwd)/data" cargo run --bin snpguard-server
```

The server listens on HTTPS:
- **Management UI**: `https://localhost:3000`
- **Attestation API**: `https://localhost:3000/v1/attest/nonce` and `/v1/attest/report`
- **Management API**: `https://localhost:3000/v1/records/*`, `/v1/tokens/*`
- TLS cert/key are loaded from `${DATA_DIR}/tls` (auto-generated if missing).

## Usage

### Creating an Attestation Record

1. **Access Management UI**: Navigate to `https://localhost:3000` and log in
2. **Click "Create New Record"**
3. **Fill in the form**:
   - **OS Name**: Descriptive name for this VM configuration
   - **Unsealing Private Key**: PEM-encoded private key for unsealing secrets (will be encrypted and stored)
     ```bash
     openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out unsealing-private-key.pem
     ```
   - **Firmware Image**: OVMF firmware binary (<10 MB)
   - **Kernel Binary**: Linux kernel image (<50 MB)
   - **Initrd Image**: Initial ramdisk (<50 MB)
   - **Kernel Parameters**: Additional kernel command-line parameters
   - **vCPUs**: Number of virtual CPUs
   - **vCPU Type**: EPYC, EPYC-Milan, EPYC-Rome, or EPYC-Genoa
   - **Service URL**: HTTPS URL of this attestation service

**Note**: ID Block Key and Auth Block Key are now automatically generated by the server. You only need to provide the Unsealing Private Key.

4. **Click "Generate & Save"**

The service will:
- Generate ID Block Key and Auth Block Key automatically
- Generate measurements using `snpguest`
- Create ID-Block and Auth-Block
- Encrypt the unsealing private key with the ingestion public key (HPKE)
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
# If using auto-generated self-signed certs:
make repack INITRD_IN=/path/to/original-initrd.img INITRD_OUT=/path/to/new-initrd.img CA_CERT=./data/tls/server.crt
# Otherwise point CA_CERT at your CA / server cert:
# make repack ... CA_CERT=./certs/ca.pem
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

4. **Boot the VM**: The attestation will happen automatically during boot (client pins `/etc/snpguard/ca.pem`; no insecure TLS fallback)

### Attestation Flow

1. **Guest VM boots** and network is initialized
2. **Initrd hook runs** (`snpguard_attest` script)
3. **Client requests nonce** (64 bytes) from attestation service via HTTPS
4. **Client generates ephemeral session key** (X25519, 32 bytes public key)
5. **Client creates binding hash**: SHA512(server_nonce || client_pub_bytes) -> 64 bytes
6. **Client generates attestation report** with binding hash in report_data field using `snpguest report`
7. **Client sends attestation request** with report, server_nonce, client_pub_bytes, and sealed_blob (HPKE-encrypted VMK)
8. **Service verifies** (in strict order):
   - Parses report with sev call from bytes
   - Verifies stateless nonce from the report.report_data - must be generated by our code, signed with ephemeral secret, not expired (within +/- 60s window)
   - Verifies hash binding - SHA512(server_nonce || client_pub_bytes) must match report.report_data
   - Finds attestation record by report.image_id, report.id_key_digest, report.auth_key_digest
   - Checks if record is not disabled
   - Checks TCB (bootloader, TEE, SNP, microcode versions meet minimum requirements)
   - Checks VMPL (must be 0 for kernel level)
   - Verifies report certs (fetches AMD certificates from KDS, verifies certificate chain and report signature)
   - Reencrypts sealed blob (unseals VMK using unsealing private key, reseals for client session)
9. **Service responds** with success, encapped_key, and ciphertext (session-encrypted VMK)
10. **Client decrypts session response** to get VMK and outputs to stdout

**Security**: Nonce verification ensures the nonce was legitimately issued by the server before validating the binding hash, preventing replay attacks and ensuring the attestation report is bound to the specific session.

## API Reference

All API endpoints use HTTPS with Protocol Buffers (`application/x-protobuf`) for request/response payloads. For detailed API documentation, see [docs/api.md](docs/api.md).

### Attestation Endpoints

These endpoints are used by guest VMs during the attestation process.

#### POST `/v1/attest/nonce`

Request a random 64-byte nonce for attestation report generation.

**Request** (Protobuf):
```protobuf
message NonceRequest {}
```

**Note**: The request message is empty. The `vm_id` field is not used in the current implementation.

**Response** (Protobuf):
```protobuf
message NonceResponse {
  bytes nonce = 1;  // Exactly 64 bytes
}
```

#### POST `/v1/attest/report`

Verify an attestation report and return secret if successful.

**Request** (Protobuf):
```protobuf
message AttestationRequest {
  bytes report_data = 1;  // SEV-SNP attestation report (binary)
}
```

**Response** (Protobuf):
```protobuf
message AttestationResponse {
  bool success = 1;
  bytes secret = 2;  // Secret to release (if success)
  string error_message = 3;  // Error description (if !success)
}
```

### Management Endpoints

These endpoints require authentication (master password or Bearer token) and are used for managing attestation records.

- `GET /v1/records` - List records
- `GET /v1/records/{id}` - Get single record
- `POST /v1/records` - Create record
- `POST /v1/records/{id}/enable|disable` - Toggle enabled
- `DELETE /v1/records/{id}` - Delete record

**Note**: Attestation records are immutable. To make changes, delete the old record and create a new one.
- `GET /v1/records/{id}/export/tar|squash` - Export latest artifacts
- `GET /v1/tokens` / `POST /v1/tokens` / `POST /v1/tokens/{id}/revoke` - Manage tokens
- `GET /v1/health` - Health; accepts Bearer token (200 if valid)

## Command Line

### Client (subcommands)

```bash
# Store URL/token/CA after validating token via /v1/health
snpguard-client config login --url https://attest.example.com --token <TOKEN> --ca-cert ./ca.pem
snpguard-client config logout

# Attestation (uses pinned CA from config)
snpguard-client attest --url https://attest.example.com --ca-cert ./ca.pem --sealed-blob /path/to/sealed-vmk.bin | cryptsetup luksOpen /dev/sda2 root_crypt --key-file=-

# Management (defaults to stored config)
snpguard-client manage list
snpguard-client manage show <id>
snpguard-client manage create --os-name ubuntu --service-url https://attest.example.com \
  --unsealing-private-key unsealing-private-key.pem \
  --vcpus 4 --vcpu-type EPYC --kernel-params "console=ttyS0" \
  --firmware firmware-code.fd --kernel vmlinuz --initrd initrd.img
snpguard-client manage export --id <id> --format tar --out artifacts.tar.gz   # format: tar|squashfs
```

`manage show` now prints kernel params and artifact filenames; `manage list/show` also support `--json`.

## Security Considerations

1. **TLS Certificates**: Always use valid TLS certificates in production. The client verifies certificates to prevent man-in-the-middle attacks.

2. **Key Management**: 
   - ID-Block and Auth-Block keys are now generated automatically by the server and stored temporarily during record creation.
   - Unsealing private keys are encrypted with HPKE (Hybrid Public Key Encryption) using X25519HkdfSha256, HkdfSha256, and AesGcm256 before storage.
   - The ingestion private key (`/data/auth/ingestion.key`) must be backed up securely - if lost, encrypted keys cannot be recovered.
   - The ingestion public key is available via `GET /v1/keys/ingestion/public` for client-side encryption.

3. **Encryption**: Unsealing private keys are encrypted at rest using HPKE (Hybrid Public Key Encryption) with X25519HkdfSha256, HkdfSha256, and AesGcm256. The ingestion key pair is generated on server deployment and stored with restricted permissions (0400 for private key).

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

## Deployment

### Docker

Build and run the container:

```bash
# Build the image
docker build -t snp-guard .

# Run the container
docker run -p 3000:3000 -v ./data:/data snp-guard
```

### Docker Compose

For easier deployment with persistent storage:

```bash
docker-compose up -d
```

The application will be available at `https://localhost:3000`.

### Environment Variables

- `DATA_DIR`: Root persistence directory (default: `/data`)
- `RUST_LOG`: Log level (default: `info`)

### Master Password (Web UI)

- On first container start, the service generates a human-readable master password, prints it once to the logs, hashes it with Argon2, and stores only the hash.
- Keep that password safe; it is not stored in plaintext and won’t be shown again unless you delete the hash file to regenerate a new one.
- Web login uses HTTP Basic Auth; username is ignored—enter any value, and supply the master password in the password field.

### Attestation REST API (HTTPS + Protobuf)

- All attestation and management APIs are REST-style HTTPS with protobuf payloads (`application/x-protobuf`).
- Endpoints (prefix `/v1`):
  - `POST /v1/attest/nonce` -> `NonceResponse` (no request fields)
  - `POST /v1/attest/report` -> `AttestationRequest` / `AttestationResponse`
  - `GET /v1/records` -> `ListRecordsResponse`
  - `GET /v1/records/{id}` -> `GetRecordResponse`
  - `POST /v1/records` -> `CreateRecordRequest` / `CreateRecordResponse`
  - `POST /v1/records/{id}/enable` -> `ToggleEnabledResponse`
  - `POST /v1/records/{id}/disable` -> `ToggleEnabledResponse`
  - `GET /v1/records/{id}/export/tar|squash` -> latest artifacts (regenerated each time)
  - `GET /v1/tokens`, `POST /v1/tokens`, `POST /v1/tokens/{id}/revoke` -> token CRUD
  - `GET /v1/health` -> 200; with Bearer token returns 200 if valid else 401
- Attestation client uses the same protobuf messages over HTTPS with full TLS verification.
- Management routes are protected by master password or Bearer token (for automation).

### Attestation Report Parsing

- The server parses SEV-SNP attestation reports using the `sev` crate's `AttestationReport` type (virtee/sev). Offsets for policy, image_id, report_data (binding hash), key digests, and TCB come directly from the struct definitions, avoiding manual slicing.
- The attestation flow uses a binding hash (SHA512 of server_nonce || client_pub_bytes) embedded in the report's report_data field to ensure the report was generated with the correct session key.

### TLS and Client Pinning

- Server: HTTPS-only. Certs are read from `${DATA_DIR}/tls/server.crt` and `server.key`; if missing, a self-signed pair (and `ca.pem`) is auto-generated. No client certificate is required.
- Client: Always verifies TLS using a pinned CA cert at `/etc/snpguard/ca.pem` inside the initrd; system trust store is not used. No skip/unsafe mode.
- `scripts/repack-initrd.sh` installs the client and copies the CA cert from `${CA_CERT:-./certs/ca.pem}` to `/etc/snpguard/ca.pem` inside the initrd.

### Volumes

- `/data`: Persistent storage for the SQLite database

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

This project is licensed under the Apache License, Version 2.0.
See the [LICENSE](LICENSE) file for details.

## References

- [AMD SEV-SNP Documentation](https://www.amd.com/en/developer/sev.html)
- [snpguest Tool](https://github.com/virtee/snpguest) (included as git submodule)
- [SEV-SNP Attestation Guide](https://rouming.github.io/2025/04/01/coco-with-amd-sev.html)

## Support

For issues and questions, please open an issue on the GitHub repository.
