# SnpGuard API Documentation

## Overview

SnpGuard provides two main API interfaces:

1. **Attestation API**: Used by guest VMs to perform attestation (HTTPS + Protobuf)
2. **Management API**: Used by the web UI for managing attestation records (HTTP/HTTPS + HTML/JSON)

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

#### POST `/attestation/nonce`

Request a random 64-byte nonce for attestation report generation.

**Request**:
```protobuf
message NonceRequest {
  string vm_id = 1;  // Optional identifier for the VM
}
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

#### POST `/attestation/verify`

Verify an attestation report and return secret if successful.

**Request**:
```protobuf
message AttestationRequest {
  bytes report_data = 1;           // SEV-SNP attestation report (binary)
  string cpu_family_hint = 2;      // Optional: "genoa", "milan", "turin"
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
2. Detect CPU family from report (CPUID_FAM_ID at 0x188, CPUID_MOD_ID at 0x189)
3. Fetch AMD certificates (CA and VCEK) from AMD KDS using integrated `snpguest`
4. Verify certificate chain using integrated `snpguest`
5. Verify attestation report signature using integrated `snpguest`
6. Extract key digests:
   - ID_KEY_DIGEST at offset 0xE0 (48 bytes)
   - AUTHOR_KEY_DIGEST at offset 0x110 (48 bytes)
7. Look up attestation record by key digests
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

## Management API

The Management API is used by the web UI. It uses standard HTTP methods with HTML forms or JSON.

### Authentication

All management endpoints require HTTP Basic Authentication. Credentials can be set via:
- Environment variables: `SNPGUARD_USERNAME` and `SNPGUARD_PASSWORD`
- Default: `admin` / `secret`

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

View/edit an attestation record.

**Parameters**:
- `id`: UUID of the attestation record

**Response**: HTML form with current values

#### POST `/view/:id`

Update an attestation record.

**Request**: `multipart/form-data` (same fields as create, all optional)

**Response**: Redirect to `/view/:id` on success

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
