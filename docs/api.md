# SnpGuard API Documentation

## Overview

SnpGuard provides two main API interfaces:

1. **Attestation API**: Used by guest VMs to perform attestation (HTTPS + Protobuf, REST)
2. **Management API**: Used by the web UI/automation for managing attestation records (HTTPS + Protobuf/JSON)

## Attestation API

The Attestation API uses HTTPS with Protocol Buffers for secure, efficient communication.

### Base URL

```
https://your-attestation-service.com
```

### Content-Type

All attestation endpoints use:
```
Content-Type: application/x-protobuf
```

### Endpoints

#### POST `/v1/attest/nonce`

Request a random 64-byte nonce for attestation report generation.

**Request**:
```protobuf
message NonceRequest {}
```

**Response** (200 OK):
```protobuf
message NonceResponse {
  bytes nonce = 1;  // Exactly 64 bytes of random data
}
```

**Error Responses**:
- `400 Bad Request`: Invalid protobuf message
- `500 Internal Server Error`: Server error generating nonce

**Example** (using curl):
```bash
# Note: This is for demonstration. In practice, use the client tool.
echo -n -e '\x0a\x05\x67\x75\x65\x73\x74' | \
  curl -X POST https://attest.example.com/attestation/nonce \
    -H "Content-Type: application/x-protobuf" \
    --data-binary @- \
    --output nonce.bin
```

#### POST `/v1/attest/report`

Verify an attestation report and return secret if successful.

**Request**:
```protobuf
message AttestationRequest {
  bytes report_data = 1;           // SEV-SNP attestation report (binary)
}
```

**Response** (200 OK):
```protobuf
message AttestationResponse {
  bool success = 1;                // true if attestation passed
  bytes secret = 2;                 // Secret to release (if success)
  string error_message = 3;        // Error description (if !success)
}
```

**Verification Process**:

1. Extract nonce from report (offset 0x50, 64 bytes)
2. Detect CPU family from report (cpuid fields parsed from AttestationReport)
3. Fetch AMD certificates (CA and VCEK) from AMD KDS using integrated `snpguest`
4. Verify certificate chain using integrated `snpguest`
5. Verify attestation report signature using integrated `snpguest`
6. Extract key digests:
   - ID_KEY_DIGEST at offset 0xE0 (48 bytes)
   - AUTHOR_KEY_DIGEST at offset 0x110 (48 bytes)
7. Look up attestation record by image_id + key digests, check policy flags/TCB minimums
8. Check if record is enabled
9. Return success with secret if all checks pass

**Error Responses**:
- `400 Bad Request`: Invalid protobuf message or report too short
- `500 Internal Server Error`: Server error during verification

**Example** (using curl):
```bash
# Generate report first (on guest VM)
snpguest report report.bin nonce.bin

# Send for verification
cat report.bin | \
  curl -X POST https://attest.example.com/attestation/verify \
    -H "Content-Type: application/x-protobuf" \
    --data-binary @- \
    --output response.bin
```

## Management API (HTTPS)

Authentication:
- Master password (Diceware, printed once, Argon2 hash stored)
- Bearer tokens for automation (create/revoke via web UI Tokens page)

Endpoints (protobuf payloads, `application/x-protobuf`):
- `GET/POST /v1/records` (list/create)
- `GET/DELETE /v1/records/{id}` (view/delete)
- `POST /v1/records/{id}/enable`, `/disable`
- `GET/POST /v1/tokens`, `POST /v1/tokens/{id}/revoke`

**Note**: Attestation records are immutable. To make changes, delete the old record and create a new one.

### Endpoints

#### GET `/`

List all attestation records.

**Response**: HTML page with table of records

#### GET `/create`

Display form for creating a new attestation record.

**Response**: HTML form

#### POST `/create`

Create a new attestation record.

**Request**: `multipart/form-data` with:
- `os_name` (text): Name of the OS/VM
- `id_key` (file): ID-Block private key (PEM)
- `auth_key` (file): Auth-Block private key (PEM)
- `firmware` (file): Firmware image (<10 MB)
- `kernel` (file): Kernel binary (<50 MB)
- `initrd` (file): Initrd image (<50 MB)
- `kernel_params` (text): Kernel command-line parameters
- `vcpus` (text): Number of vCPUs
- `vcpu_type` (text): EPYC, EPYC-Milan, EPYC-Rome, or EPYC-Genoa
- `service_url` (text): HTTPS URL of attestation service
- `secret` (text): Secret to release upon successful attestation

**Response**: Redirect to `/` on success, error page on failure

#### GET `/view/:id`

View an attestation record (read-only).

**Parameters**:
- `id`: UUID of the attestation record

**Response**: HTML page displaying record details (read-only)

**Note**: Attestation records are immutable. To make changes, delete this record and create a new one.

#### POST `/toggle/:id`

Toggle enabled/disabled status of an attestation record.

**Response**: Redirect to `/`

#### GET `/delete/:id`

Delete an attestation record.

**Response**: Redirect to `/`

#### GET `/download/:id/:file`

Download an artifact file.

**Parameters**:
- `id`: UUID of the attestation record
- `file`: Filename to download

**Available Files**:
- `id-block.bin`: ID-Block binary
- `id-auth.bin`: Auth-Block binary
- `firmware-code.fd`: Firmware image
- `vmlinuz`: Kernel binary
- `initrd.img`: Initrd image
- `kernel-params.txt`: Kernel parameters
- `artifacts.tar.gz`: Tarball with all files
- `artifacts.squashfs`: SquashFS image with all files

**Response**: Binary file download

## Protocol Buffer Definitions

See `protos/attestation.proto` for the complete protobuf schema.

## Error Handling

All endpoints return appropriate HTTP status codes:
- `200 OK`: Success
- `400 Bad Request`: Invalid request
- `401 Unauthorized`: Authentication required (management endpoints)
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error

Error messages in protobuf responses are human-readable strings.

## Rate Limiting

Currently, there is no rate limiting implemented. Consider adding rate limiting for production deployments.

## Security Considerations

1. **TLS**: Always use HTTPS in production. The attestation API requires TLS certificate verification.

2. **Authentication**: Use strong passwords for the management API. Consider implementing additional security measures (2FA, IP whitelisting) for production.

3. **Input Validation**: All file uploads are validated for size limits. File paths are sanitized to prevent directory traversal.

4. **Secret Storage**: Secrets are stored in the database. Consider encrypting the database or using a secrets management system.
