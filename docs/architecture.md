# SnpGuard Architecture

## Overview

SnpGuard is a SEV-SNP attestation service that verifies the integrity of guest VMs and releases secrets upon successful attestation. The system consists of three main components:

1. **Attestation Service** (Server)
2. **Attestation Client** (Guest VM)
3. **Management Frontend** (Web UI)

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Guest VM                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Initrd (initramfs-tools or dracut)                      │  │
│  │  - initramfs-tools: scripts/local-top/snpguard_attest  │  │
│  │  - dracut: lib/dracut/hooks/pre-mount/99-snpguard.sh   │  │
│  │  ┌────────────────────────────────────────────────────┐  │  │
│  │  │  snpguard-client (static binary, musl)             │  │  │
│  │  │  - Requests nonce                                  │  │  │
│  │  │  - Generates report via snpguest                  │  │  │
│  │  │  - Sends report for verification                  │  │  │
│  │  │  - Receives secret                                │  │  │
│  │  └────────────────────────────────────────────────────┘  │  │
│  │  ┌────────────────────────────────────────────────────┐  │  │
│  │  │  snpguest tool                                      │  │  │
│  │  │  - Generates attestation reports                   │  │  │
│  │  └────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  SEV-SNP Hardware                                              │
│  - Memory encryption                                            │
│  - Attestation report generation                                │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ HTTPS/TLS + Protobuf
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SnpGuard Server                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Attestation Service                                      │  │
│  │  - /attestation/nonce                                     │  │
│  │  - /attestation/verify                                    │  │
│  │  - Verifies AMD certificate chain                         │  │
│  │  - Validates attestation reports                          │  │
│  │  - Releases secrets                                       │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Management Service                                       │  │
│  │  - Web UI (HTML/CSS/JavaScript)                          │  │
│  │  - CRUD operations for attestation records               │  │
│  │  - Artifact generation and download                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Database (SQLite)                                       │  │
│  │  - Attestation records                                   │  │
│  │  - Key digests                                           │  │
│  │  - Secrets                                               │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Artifact Storage                                        │  │
│  │  - Firmware, kernel, initrd                              │  │
│  │  - ID-Block, Auth-Block                                  │  │
│  │  - Generated artifacts                                    │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ HTTPS
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Management User                              │
│  - Creates attestation records                                  │
│  - Uploads firmware/kernel/initrd                               │
│  - Configures secrets                                          │
│  - Downloads artifacts                                          │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### Attestation Service

**Responsibilities**:
- Generate random nonces for attestation
- Verify attestation reports using AMD's certificate chain (via integrated `snpguest`)
- Look up attestation records by key digests
- Release secrets upon successful verification

**Key Functions**:
1. **Nonce Generation**: Creates cryptographically secure 64-byte nonces
2. **Certificate Fetching**: Retrieves CA and VCEK certificates from AMD KDS
3. **Report Verification**: Validates report signatures and structure
4. **Key Digest Extraction**: Extracts ID_KEY_DIGEST and AUTHOR_KEY_DIGEST from reports
5. **Record Lookup**: Finds matching attestation records in database

### Attestation Client

**Responsibilities**:
- Request nonce from attestation service
- Generate attestation report using `snpguest`
- Send report for verification
- Receive and output secret

**Key Features**:
- Static binary (no glibc dependencies)
- Built with musl libc for initrd compatibility
- HTTPS client with certificate verification
- Protobuf message serialization

### Management Frontend

**Responsibilities**:
- Provide web UI for managing attestation records
- Handle file uploads (firmware, kernel, initrd, keys)
- Generate ID-Block and Auth-Block using integrated `snpguest`
- Serve artifact downloads

**Key Features**:
- Modern, responsive UI (Tailwind CSS)
- File upload with size validation
- Artifact generation (tarball, SquashFS)
- Enable/disable attestation records

## Data Flow

### Attestation Flow

```
1. Guest VM boots
   │
   ├─> Network initialized
   │
   ├─> Initrd hook runs (snpguard_attest)
   │
   ├─> Client requests nonce
   │   POST /attestation/nonce
   │   │
   │   └─> Server generates 64-byte nonce
   │       Returns: NonceResponse
   │
   ├─> Client generates report
   │   snpguest report report.bin nonce.bin
   │   │
   │   └─> SEV-SNP hardware generates report
   │
   ├─> Client sends report
   │   POST /attestation/verify
   │   │
   │   └─> Server verifies:
   │       ├─> Extract nonce (offset 0x50)
   │       ├─> Detect CPU family (0x188, 0x189)
   │       ├─> Fetch AMD certificates
   │       ├─> Verify certificate chain
   │       ├─> Verify report signature
   │       ├─> Extract key digests (0xE0, 0x110)
   │       ├─> Look up record
   │       └─> Check if enabled
   │
   └─> Server responds
       ├─> Success: AttestationResponse { success: true, secret: ... }
       └─> Failure: AttestationResponse { success: false, error_message: ... }
```

### Record Creation Flow

```
1. User fills form in web UI
   │
   ├─> Uploads: firmware, kernel, initrd, keys
   │
   ├─> Enters: OS name, vCPUs, vCPU type, kernel params, service URL, secret
   │
   └─> Submits form
       │
       ├─> Server saves files to artifacts/{id}/
       │
       ├─> Generates family-id and image-id from service URL
       │   family-id = first 16 bytes of SHA256(URL)
       │   image-id = last 16 bytes of SHA256(URL)
       │
       ├─> Runs integrated snpguest generate measurement
       │   --ovmf firmware-code.fd
       │   --kernel vmlinuz
       │   --initrd initrd.img
       │   --append "kernel-params rd.attest.url=..."
       │   --vcpus N
       │   --vcpu-type EPYC-*
       │
       ├─> Runs integrated snpguest generate id-block
       │   --id-file id-block.bin
       │   --auth-file id-auth.bin
       │
       ├─> Computes key digests
       │   snpguest generate key-digest id-block-key.pem
       │   snpguest generate key-digest id-auth-key.pem
       │
       └─> Saves record to database
           - id, os_name, secret, vcpu_type
           - id_key_digest, auth_key_digest
           - kernel_params, enabled, request_count
```

## Security Model

### Threat Model

**Threats**:
1. Man-in-the-middle attacks on attestation communication
2. Replay attacks using old attestation reports
3. Unauthorized access to management UI
4. Database compromise exposing secrets

**Mitigations**:
1. **TLS with Certificate Verification**: All communication uses HTTPS with verified certificates
2. **Nonce-based Reports**: Each report includes a fresh nonce from the server
3. **HTTP Basic Auth**: Management UI requires authentication
4. **Key Digest Lookup**: Only records with matching key digests can be verified
5. **Enable/Disable Toggle**: Records can be disabled without deletion

### Trust Boundaries

```
┌─────────────────────────────────────────┐
│  Trusted: SnpGuard Server               │
│  - Verifies AMD certificates             │
│  - Validates attestation reports        │
│  - Stores secrets securely               │
└─────────────────────────────────────────┘
              │
              │ HTTPS (verified)
              │
┌─────────────────────────────────────────┐
│  Trusted: Guest VM (SEV-SNP)            │
│  - Hardware-protected memory            │
│  - Authentic attestation reports         │
└─────────────────────────────────────────┘
```

## Database Schema

### attestation_records

```sql
CREATE TABLE attestation_records (
    id TEXT PRIMARY KEY,                    -- UUID
    os_name TEXT NOT NULL,                   -- Descriptive name
    request_count INTEGER NOT NULL DEFAULT 0, -- Number of successful attestations
    secret TEXT NOT NULL,                    -- Secret to release
    vcpu_type TEXT NOT NULL,                 -- EPYC variant
    enabled BOOLEAN NOT NULL DEFAULT TRUE,   -- Enable/disable flag
    id_key_digest BLOB NOT NULL,             -- ID-Block key digest (48 bytes)
    auth_key_digest BLOB NOT NULL,           -- Auth-Block key digest (48 bytes)
    created_at DATETIME NOT NULL,            -- Creation timestamp
    kernel_params TEXT NOT NULL,             -- Full kernel command line
    firmware_path TEXT NOT NULL,             -- Relative path to firmware
    kernel_path TEXT NOT NULL,               -- Relative path to kernel
    initrd_path TEXT NOT NULL                -- Relative path to initrd
);
```

## File Structure

```
artifacts/
└── {record-id}/
    ├── firmware-code.fd      # OVMF firmware
    ├── vmlinuz               # Kernel binary
    ├── initrd.img            # Initrd image
    ├── kernel-params.txt     # Kernel parameters
    ├── id-block-key.pem     # ID-Block private key
    ├── id-auth-key.pem      # Auth-Block private key
    ├── id-block.bin         # Generated ID-Block
    └── id-auth.bin           # Generated Auth-Block
```

## Dependencies

### External Tools

- **snpguest**: Included as git submodule, built automatically
  - Server: Generates measurements and blocks using integrated binary
  - Client: Generates attestation reports (available in guest OS)

- **mksquashfs**: Required for SquashFS artifact generation

- **tar/gzip**: Required for tarball generation

### Rust Crates

- **axum**: Web framework
- **sea-orm**: Database ORM
- **prost**: Protocol buffer support
- **reqwest**: HTTP client (client only)
- **rustls**: TLS implementation
- **askama**: Template engine

## Performance Considerations

1. **Certificate Fetching**: AMD certificate fetching happens over the network and may add latency. Consider caching certificates.

2. **Report Verification**: Cryptographic verification is CPU-intensive. Consider rate limiting or async processing for high-volume deployments.

3. **Database**: SQLite is suitable for small to medium deployments. For larger scale, consider PostgreSQL or MySQL.

4. **File Storage**: Artifacts are stored on the filesystem. For distributed deployments, consider object storage (S3, etc.).

## Scalability

### Horizontal Scaling

The attestation service can be scaled horizontally by:
1. Using a shared database (PostgreSQL/MySQL)
2. Using shared artifact storage (NFS, object storage)
3. Load balancing attestation endpoints
4. Session affinity for nonce tracking (if implemented)

### Vertical Scaling

For single-instance deployments:
1. Use a more powerful database (PostgreSQL)
2. Increase server resources
3. Optimize certificate caching
4. Use async processing for report verification

## Future Enhancements

1. **Nonce Tracking**: Implement proper nonce tracking with expiration
2. **Rate Limiting**: Add rate limiting to prevent abuse
3. **Audit Logging**: Log all attestation attempts
4. **Multi-tenancy**: Support multiple organizations/tenants
5. **API Keys**: Replace Basic Auth with API keys or OAuth
6. **Metrics**: Add Prometheus metrics for monitoring
7. **Distributed Storage**: Support S3-compatible storage for artifacts
