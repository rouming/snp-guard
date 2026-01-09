# Requirements Checklist

## ✅ Completed Requirements

### 1. Rust Implementation
- [x] Entire project written in Rust
- [x] Client built with musl (no glibc dependencies)
- [x] Server uses modern Rust async (tokio/axum)

### 2. Project Structure
- [x] Source files in `src/`
- [x] Documentation in `docs/`
- [x] Scripts in `scripts/`
- [x] Makefile for build automation
- [x] README.md with comprehensive documentation

### 3. Client Attestation Tool
- [x] Built without glibc (uses musl target)
- [x] Retrieves attestation report using snpguest tool
- [x] Communicates via HTTPS/TLS with protobuf
- [x] Can be included in initrd image

### 4. Attestation Service
- [x] Verifies attestation reports from guests
- [x] Responds with success/failure
- [x] Returns SECRET on successful attestation
- [x] Management frontend for managing attestations
- [x] API for future management tool integration

### 5. Communication Protocol
- [x] HTTPS/TLS communication
- [x] Protocol Buffers for message format
- [x] Protobuf definitions in `protos/` folder
- [x] Client receives 64-byte nonce from service
- [x] Nonce used for attestation report generation

### 6. Endpoints
- [x] Management endpoint (web UI)
- [x] Attestation endpoint (HTTPS API)

### 7. Management Authentication
- [x] Basic authorization (username/password)
- [x] Configurable via environment variables
- [x] Default credentials for development

### 8. Management List Page
- [x] Shows list of registered OSs
- [x] Displays OS names
- [x] Shows count of attested requests
- [x] Disabled records visually grayed out
- [x] Links remain active for disabled records
- [x] Click name redirects to view page
- [x] Link to delete record
- [x] Link to create new record
- [x] Modern and visually appealing design

### 9. Create Attestation Record
- [x] OS name field
- [x] ID block PEM private key upload
- [x] Auth block PEM private key upload
- [x] Firmware image upload (<10 MB, enforced)
- [x] Kernel binary upload (<50 MB, enforced)
- [x] Initrd image upload (<50 MB, enforced)
- [x] Kernel params text field
- [x] vCPU number field (integer)
- [x] vCPU type selection (EPYC, EPYC-Milan, EPYC-Rome, EPYC-Genoa)
- [x] Service URL text field
- [x] SECRET text field
- [x] Generates ID-Block and Auth-Block using snpguest
- [x] Generates measurement with all parameters
- [x] Computes key digests (id_key_digest, auth_key_digest)
- [x] Stores digests in database
- [x] Redirects to list after creation

### 10. View/Edit Attestation Record
- [x] Shows all attestation fields
- [x] OS name editable
- [x] ID block key editable (shows previous)
- [x] Auth block key editable (shows previous)
- [x] Firmware upload (previous available for download)
- [x] Kernel upload (previous available for download)
- [x] Initrd upload (previous available for download)
- [x] Kernel parameters editable
- [x] vCPU number editable
- [x] vCPU type selection
- [x] Service URL editable
- [x] SECRET editable
- [x] Download ID-block binary
- [x] Download Auth-block binary
- [x] Download tarball artifacts (correct filenames)
- [x] Download SquashFS artifacts (correct permissions)
- [x] Enable/Disable button
- [x] Modern and visually appealing design

### 11. Attestation Verification
- [x] HTTPS/TLS connection (verified certificates)
- [x] Service sends 64-byte nonce in first response
- [x] Client generates report with nonce
- [x] Service verifies report:
  - [x] Extracts nonce from report (offset 0x50)
  - [x] Verifies nonce (matches stored, not expired)
  - [x] Detects CPU family from report (CPUID_FAM_ID/CPUID_MOD_ID)
  - [x] Fetches AMD certificates (CA and VCEK)
  - [x] Verifies certificate chain
  - [x] Verifies attestation report signature
  - [x] Extracts key digests (0xE0 and 0x110)
  - [x] Looks up attestation record by digests
  - [x] Checks if record is enabled
  - [x] Returns success with SECRET if all checks pass

### 12. HTML Frontend
- [x] Modern and visually appealing design
- [x] Responsive layout
- [x] Tailwind CSS styling
- [x] User-friendly interface

### 13. Initrd Repack Script
- [x] Script in `scripts/` folder
- [x] Takes initrd image as input
- [x] Repacks with attestation client
- [x] Installs attestation hook
- [x] Works with initramfs-tools (Ubuntu, Debian)
  - [x] Auto-detects initramfs-tools format
  - [x] Installs hook at `scripts/local-top/snpguard_attest`
  - [x] Runs in `local-top` phase (after network, before root mount)
- [x] Works with dracut (RedHat, CentOS, Fedora, etc.)
  - [x] Auto-detects dracut format
  - [x] Installs hook at `lib/dracut/hooks/pre-mount/99-snpguard.sh`
  - [x] Runs in `pre-mount` phase (before root mount)
- [x] Supports both mechanisms simultaneously if needed
- [x] Attestation happens after network setup
- [x] Attestation happens before drive unsealing
- [x] Reads `rd.attest.url` from kernel command line

### 14. Documentation
- [x] API documentation in `docs/api.md`
- [x] Architecture documentation in `docs/architecture.md`
- [x] User guide in `docs/user_guide.md`
- [x] Security review in `SECURITY.md`

### 15. README.md
- [x] Motivation for the project
- [x] Build instructions
- [x] Usage examples
- [x] Architecture overview
- [x] Troubleshooting guide

## Security Improvements Implemented

- [x] Cryptographically secure RNG (OsRng) for nonce generation
- [x] Nonce expiration (5 minutes TTL)
- [x] Nonce verification against stored nonces
- [x] One-time nonce use (removed after verification)
- [x] Nonce storage limits (max 10,000 entries)
- [x] File upload size limits enforced (firmware <10MB, kernel/initrd <50MB)
- [x] Path traversal protection in download endpoint

## Additional Features

- [x] CPU family auto-detection from attestation reports
- [x] Configurable authentication credentials
- [x] TLS/HTTPS support (optional, for production)
- [x] Request count tracking
- [x] Enable/disable toggle for records
- [x] Artifact generation (tarball and SquashFS)

## Notes

- Family-ID and Image-ID are NOT generated from URL (as per clarification)
- URL from `rd.attest.url` is only used for client connection, not for ID generation
- All requirements from the original specification have been implemented
