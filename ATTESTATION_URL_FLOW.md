# Attestation URL Flow Verification

## Overview
This document verifies that `rd.attest.url=URL` is properly handled throughout the system.

## Flow Verification

### 1. Creating New Attestation Record ✅

**User Input:**
- Kernel Parameters field: `console=ttyS0 root=UUID=...`
- Service URL field: `https://attest.example.com`

**Processing:**
1. Server receives `kernel_params` and `service_url` separately
2. Server combines them: `full_params = "console=ttyS0 root=UUID=... rd.attest.url=https://attest.example.com"`
3. Server writes `full_params` to `kernel-params.txt`
4. Server uses `full_params` (with `rd.attest.url`) for `snpguest generate measurement`
5. Server stores `full_params` in database

**Result:**
- ✅ `kernel-params.txt` contains `rd.attest.url=URL`
- ✅ ID-Block/Auth-Block generated with `rd.attest.url` in measurement
- ✅ Database stores full kernel params including `rd.attest.url`

### 2. Editing Attestation Record ✅

**User Input:**
- Kernel Parameters field: Shows only base params (without `rd.attest.url`)
- Service URL field: Shows extracted URL from stored params

**Processing:**
1. Server extracts base params (strips `rd.attest.url`)
2. Server extracts or receives service URL
3. Server rebuilds: `full_params = base_params + " rd.attest.url=" + service_url`
4. Server **always** writes `full_params` to `kernel-params.txt`
5. If files updated OR params/URL changed, server regenerates blocks with `full_params`

**Result:**
- ✅ `kernel-params.txt` always contains `rd.attest.url=URL`
- ✅ Blocks regenerated with `rd.attest.url` when needed
- ✅ User never sees `rd.attest.url` in kernel params field

### 3. Downloading Artifacts ✅

**Tarball (`artifacts.tar.gz`):**
- Contains `kernel-params.txt` with `rd.attest.url=URL` ✅

**SquashFS (`artifacts.squashfs`):**
- Contains `kernel-params.txt` with `rd.attest.url=URL` ✅

### 4. Guest VM Boot Flow ✅

**Kernel Command Line:**
```
linux /vmlinuz root=UUID=... rd.attest.url=https://attest.example.com
```

**Initrd Hook Execution:**
1. Hook reads `/proc/cmdline`
2. Hook extracts `rd.attest.url=...` from kernel command line
3. Hook calls: `/bin/snpguard-client --url "$ATTEST_URL"`
4. Client connects to attestation service using URL from kernel cmdline

**Result:**
- ✅ URL read from kernel command line (not from kernel-params.txt)
- ✅ Client uses URL from `rd.attest.url` parameter
- ✅ Attestation happens automatically during boot

## Code Locations

### Server Side

1. **Create Action** (`src/server/web.rs:91-92`)
   ```rust
   let full_params = format!("{} rd.attest.url={}", fd.kernel_params, fd.service_url);
   fs::write(artifact_dir.join("kernel-params.txt"), &full_params).unwrap();
   ```

2. **Update Action** (`src/server/web.rs:204-219`)
   ```rust
   // Extract service URL
   // Rebuild full params with rd.attest.url
   // Always update kernel-params.txt
   fs::write(artifact_dir.join("kernel-params.txt"), &full_params).unwrap();
   ```

3. **Block Generation** (`src/server/web.rs:223-232`)
   ```rust
   snpguest_wrapper::generate_measurement_and_block(
       ...,
       &full_params,  // Includes rd.attest.url
       ...
   )
   ```

### Client Side (Initrd)

1. **Hook Script** (`scripts/repack-initrd.sh:64-81`)
   ```bash
   # Parse kernel cmdline for attestation URL
   for x in $(cat /proc/cmdline); do
       case $x in
           rd.attest.url=*)
               ATTEST_URL=${x#rd.attest.url=}
               ;;
       esac
   done
   
   /bin/snpguard-client --url "$ATTEST_URL"
   ```

### Templates

1. **Create Template** (`ui/templates/create.html:20`)
   - Shows kernel params field (without `rd.attest.url`)
   - Shows separate service URL field

2. **Edit Template** (`ui/templates/edit.html:87-91`)
   - Shows kernel params without `rd.attest.url` (stripped)
   - Shows service URL in separate field

## Verification Checklist

- [x] `rd.attest.url` is added to kernel params when creating record
- [x] `rd.attest.url` is added to kernel params when updating record
- [x] `kernel-params.txt` always contains `rd.attest.url=URL`
- [x] ID-Block/Auth-Block generated with `rd.attest.url` in measurement
- [x] Tarball contains `kernel-params.txt` with `rd.attest.url`
- [x] SquashFS contains `kernel-params.txt` with `rd.attest.url`
- [x] Kernel params field on web page does NOT show `rd.attest.url`
- [x] Service URL is shown in separate field on web page
- [x] Initrd hook reads `rd.attest.url` from `/proc/cmdline`
- [x] Client is called with URL from kernel command line

## Summary

All flows are correctly implemented:
- ✅ URL is automatically added to kernel params (never shown to user)
- ✅ `kernel-params.txt` always contains `rd.attest.url=URL`
- ✅ Blocks are generated with `rd.attest.url` in measurement
- ✅ Initrd hook reads URL from kernel command line (not from file)
- ✅ Client uses URL from kernel command line for attestation
