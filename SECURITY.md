# Security Review and Improvements

## Security Analysis

### Current Security Posture

#### ✅ Strengths
1. **TLS/HTTPS**: All communication uses TLS with certificate verification
2. **Protocol Buffers**: Binary serialization reduces parsing attack surface
3. **AMD Certificate Verification**: Proper certificate chain verification
4. **Key Digest Lookup**: Uses cryptographic digests for record matching
5. **Path Traversal Protection**: Basic checks in download endpoint

#### ⚠️ Security Concerns

1. **Nonce Generation (CRITICAL)**
   - **Issue**: Using `rand::thread_rng()` which is not cryptographically secure
   - **Risk**: Predictable nonces could allow replay attacks
   - **Fix**: Use `rand::rngs::OsRng` for cryptographically secure randomness

2. **Nonce Storage (HIGH)**
   - **Issue**: Nonces stored in HashMap with no expiration
   - **Risk**: Memory exhaustion via DoS, no nonce reuse prevention
   - **Fix**: Add expiration (TTL), limit storage size, verify nonce in reports

3. **Nonce Verification (HIGH)**
   - **Issue**: Nonces are generated but not verified against reports
   - **Risk**: Old reports could be replayed
   - **Fix**: Extract nonce from report and verify against stored nonces

4. **File Upload Size Limits (MEDIUM)**
   - **Issue**: No enforced size limits in code (only documented)
   - **Risk**: DoS via large file uploads, disk exhaustion
   - **Fix**: Enforce limits: firmware <10MB, kernel <50MB, initrd <50MB

5. **Secret Storage (MEDIUM)**
   - **Issue**: Secrets stored in plaintext in database
   - **Risk**: Database compromise exposes all secrets
   - **Fix**: Encrypt secrets at rest (AES-256-GCM with key derivation)

6. **Error Handling (LOW)**
   - **Issue**: Some `unwrap()` calls could cause panics
   - **Risk**: Service crashes, information leakage
   - **Fix**: Replace with proper error handling

7. **Rate Limiting (LOW)**
   - **Issue**: No rate limiting on endpoints
   - **Risk**: DoS attacks, resource exhaustion
   - **Fix**: Implement rate limiting (per-IP, per-endpoint)

8. **Input Validation (LOW)**
   - **Issue**: Limited validation on form inputs
   - **Risk**: Injection attacks, invalid data
   - **Fix**: Add comprehensive input validation

## Recommended Improvements

### Priority 1 (Critical - Implement Immediately)

1. **Use Cryptographically Secure RNG**
   ```rust
   use rand::rngs::OsRng;
   let mut rng = OsRng;
   ```

2. **Add Nonce Expiration and Verification**
   - Store nonces with timestamp
   - Verify nonce from report matches stored nonce
   - Expire nonces after 5 minutes
   - Limit nonce storage to prevent memory exhaustion

3. **Enforce File Upload Size Limits**
   - Add size checks before writing files
   - Return clear error messages

### Priority 2 (High - Implement Soon)

4. **Encrypt Secrets at Rest**
   - Use AES-256-GCM encryption
   - Derive encryption key from environment variable
   - Decrypt only when needed

5. **Improve Nonce Management**
   - Use bounded cache with LRU eviction
   - Add metrics for nonce generation/verification

### Priority 3 (Medium - Consider for Production)

6. **Add Rate Limiting**
   - Use `tower-governor` or similar
   - Different limits for attestation vs management endpoints

7. **Enhanced Input Validation**
   - Validate URLs, file names, kernel parameters
   - Sanitize all user inputs

8. **Audit Logging**
   - Log all attestation attempts (success/failure)
   - Log management operations
   - Include IP addresses, timestamps

9. **Session Management**
   - Replace Basic Auth with session-based auth
   - Add CSRF protection for management endpoints

## Implementation Notes

### Nonce Security
- Nonces should be one-time use only
- Store with expiration timestamp
- Verify nonce is used within time window
- Clear nonce after successful verification

### File Upload Security
- Validate file types (MIME type checking)
- Scan for malicious content (optional)
- Store files with restricted permissions
- Use secure temporary directories

### Database Security
- Use connection encryption
- Restrict database file permissions
- Regular backups with encryption
- Consider using PostgreSQL with encryption for production

## Threat Model

### Attack Vectors

1. **Replay Attacks**: Mitigated by nonce verification (when implemented)
2. **Man-in-the-Middle**: Mitigated by TLS certificate verification
3. **DoS**: Partially mitigated, needs rate limiting
4. **Database Compromise**: Partially mitigated, needs secret encryption
5. **File Upload Attacks**: Partially mitigated, needs size limits and validation

### Defense in Depth

- Network layer: Firewall rules, TLS
- Application layer: Input validation, rate limiting
- Data layer: Encryption at rest, access controls
- Monitoring: Logging, alerting
