#!/bin/bash

# ==============================================================================
#  AMD SEV-SNP QEMU Launcher
#  Features: Auto-Artifacts, ID-Block Policy Extraction, SLIRP Network
# ==============================================================================

# --- Styling & Colors ---
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}${BOLD}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}${BOLD}[OK]${NC}   $1"; }
warn()  { echo -e "${YELLOW}${BOLD}[WARN]${NC} $1"; }
err()   { echo -e "${RED}${BOLD}[ERR]${NC}  $1"; }

# --- Default Parameters ---
HDA_FILE="debian-12-genericcloud-amd64.qcow2"
GUEST_SIZE_IN_MB="4096"
SMP_NCPUS="4"
CPU_TYPE="EPYC-Milan"
CONSOLE="serial" # Default to serial for cloud images
QEMU_BIN=/usr/bin/qemu-9.2
VNC_PORT=""
NO_NET="0"
FREEZE="0"
USE_VIRTIO="1"

# SEV-SNP Defaults
# 0x30000 = Bit 16 (SMT Allowed) | Bit 17 (Reserved, must be 1)
# This is the fallback if no ID Block is provided.
SEV_POLICY="0x30000" 
CBITPOS=51
REDUCED_PHYS_BITS=5

# Internal variables
ARTIFACTS_ARCHIVE=""
TEMP_DIR=""

# Checks
if [ id -u -ne 0 ]; then
    err "This script must be run as root (for KVM/SEV access)."
    exit 1
fi

if ! command -v od &> /dev/null; then
    err "'od' command not found. Please install coreutils."
    exit 1
fi

# Trap for cleanup
cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
    stty intr ^c 2>/dev/null # Restore CTRL-C
}
trap cleanup EXIT

# --- Helper Functions ---

usage() {
    echo -e "${BOLD}Usage:${NC} $0 [options]"
    echo ""
    echo "  --hda <file>          Path to disk image (default: $HDA_FILE)"
    echo "  --artifacts <tar.gz>  Path to artifacts archive (contains kernel, bios, id-blocks)"
    echo "  --mem <MB>            Guest memory in MB (default: $GUEST_SIZE_IN_MB)"
    echo "  --vcpus <n>           Number of vCPUs (default: $SMP_NCPUS)"
    echo "  --vcpu-type <type>    CPU Model (default: $CPU_TYPE, e.g. EPYC-Genoa)"
    echo "  --console <type>      'serial' (default) or 'qxl'"
    echo "  --vnc <display>       VNC display number (e.g., 0 for :0)"
    echo "  --nonet               Disable network"
    echo "  --freeze              Freeze CPU at startup (for debugging)"
    echo ""
    echo -e "${BOLD}Example:${NC}"
    echo "  sudo $0 --hda ubuntu.qcow2 --artifacts artifacts.tar.gz --vcpus 8"
    exit 1
}

# --- Argument Parsing ---

# We use a temporary array for QEMU args to avoid cluttering variables
QEMU_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hda|-hda)
            HDA_FILE="$2"
            shift 2
            ;;
        --artifacts|-artifacts)
            ARTIFACTS_ARCHIVE="$2"
            shift 2
            ;;
        --mem|-mem)
            GUEST_SIZE_IN_MB="$2"
            shift 2
            ;;
        --vcpus|-vcpus)
            SMP_NCPUS="$2"
            shift 2
            ;;
        --vcpu-type|-vcpu-type)
            CPU_TYPE="$2"
            shift 2
            ;;
        --console|-console)
            CONSOLE="$2"
            shift 2
            ;;
        --vnc|-vnc)
            VNC_PORT="$2"
            shift 2
            ;;
        --nonet|-nonet)
            NO_NET="1"
            shift 1
            ;;
        --freeze|-freeze)
            FREEZE="1"
            shift 1
            ;;
        *)
            usage
            ;;
    esac
done

# --- Artifact Extraction ---

UEFI_BIOS_CODE="AmdSev-OVMF.fd" # Fallback
KERNEL_FILE=""
INITRD_FILE=""
ID_BLOCK_FILE=""
ID_AUTH_FILE=""
KERNEL_PARAMS_STR=""

if [ -n "$ARTIFACTS_ARCHIVE" ]; then
    if [ ! -f "$ARTIFACTS_ARCHIVE" ]; then
        err "Artifacts file not found: $ARTIFACTS_ARCHIVE"
        exit 1
    fi

    info "Extracting artifacts from $ARTIFACTS_ARCHIVE..."
    TEMP_DIR=$(mktemp -d)

    # Extract to temp dir
    tar -xzf "$ARTIFACTS_ARCHIVE" -C "$TEMP_DIR"

    # Recursive finder helper
    find_artifact() {
        find "$TEMP_DIR" -name "$1" -print -quit
    }

    UEFI_BIOS_CODE=$(find_artifact "firmware-code.fd")
    KERNEL_FILE=$(find_artifact "vmlinuz")
    INITRD_FILE=$(find_artifact "initrd.img")
    ID_BLOCK_FILE=$(find_artifact "id-block.bin")
    ID_AUTH_FILE=$(find_artifact "id-auth.bin")
    KERNEL_PARAMS_FILE=$(find_artifact "kernel-params.txt")

    if [ -f "$KERNEL_PARAMS_FILE" ]; then
        KERNEL_PARAMS_STR=$(cat "$KERNEL_PARAMS_FILE")
    fi

    # --- AUTO-DETECT POLICY FROM ID BLOCK ---
    if [ -f "$ID_BLOCK_FILE" ]; then
        # Offset 0x58 (88 decimal) is the Policy field (64-bit)
        EXTRACTED_POLICY_HEX=$(od -An -j 88 -N 8 -t x8 "$ID_BLOCK_FILE" | tr -d ' \n')

        if [ -n "$EXTRACTED_POLICY_HEX" ]; then
            SEV_POLICY="0x${EXTRACTED_POLICY_HEX}"
            ok "ID Block found. Enforcing Policy: ${SEV_POLICY}"
        else
            warn "ID Block found but policy extraction failed. Using default."
        fi
    else
        warn "No ID Block in artifacts. Using generic Policy: ${SEV_POLICY}"
    fi

    ok "Artifacts loaded successfully."
else
    warn "No artifacts provided. Using system defaults."
fi

# --- Constructing QEMU Command ---

# Base System
QEMU_ARGS+=( "$QEMU_BIN" )
QEMU_ARGS+=( "-enable-kvm" )
QEMU_ARGS+=( "-cpu" "${CPU_TYPE}" )
QEMU_ARGS+=( "-machine" "q35,confidential-guest-support=sev0,vmport=off" )
QEMU_ARGS+=( "-smp" "${SMP_NCPUS},maxcpus=64" )
QEMU_ARGS+=( "-m" "${GUEST_SIZE_IN_MB}M,slots=5,maxmem=30G" )
QEMU_ARGS+=( "-no-user-config" )
QEMU_ARGS+=( "-nodefaults" )

# BIOS / Firmware
if [ -n "$UEFI_BIOS_CODE" ]; then
    QEMU_ARGS+=( "-bios" "$UEFI_BIOS_CODE" )
fi

# EFIShell disable
QEMU_ARGS+=( "-fw_cfg" "name=opt/org.tianocore/EFIShellSupport,string=no" )

# OVMF Debug logging
QEMU_ARGS+=( "-debugcon" "file:ovmf.log" "-global" "isa-debugcon.iobase=0x402" )

# --- SEV-SNP Configuration ---

SNP_PARAMS="id=sev0,cbitpos=${CBITPOS},reduced-phys-bits=${REDUCED_PHYS_BITS},policy=${SEV_POLICY}"

if [ -n "$ID_BLOCK_FILE" ]; then
    SNP_PARAMS+=",id-block=$(base64 -w0 "$ID_BLOCK_FILE")"
fi
if [ -n "$ID_AUTH_FILE" ]; then
    SNP_PARAMS+=",author-key-enabled=true,id-auth=$(base64 -w0 "$ID_AUTH_FILE")"
fi
if [ -n "$KERNEL_FILE" ]; then
    # Required for direct kernel boot measurement
    SNP_PARAMS+=",kernel-hashes=on"
fi

QEMU_ARGS+=( "-object" "sev-snp-guest,${SNP_PARAMS}" )

# --- Storage (VirtIO SCSI) ---

if [ -n "$HDA_FILE" ]; then
    if [[ "$HDA_FILE" == *".qcow2" ]]; then
        FORMAT="qcow2"
    else
        FORMAT="raw"
    fi
    QEMU_ARGS+=( "-device" "virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true" )
    QEMU_ARGS+=( "-drive" "file=${HDA_FILE},if=none,id=disk0,format=${FORMAT}" )
    QEMU_ARGS+=( "-device" "scsi-hd,drive=disk0,bootindex=1" )
fi

# --- Network (Standard User/SLIRP) ---

if [ "$NO_NET" == "0" ]; then
    # Default QEMU 'user' networking. 
    # Forwards host port 2222 -> guest port 22 for SSH convenience.
    QEMU_ARGS+=( "-netdev" "user,id=net0,hostfwd=tcp::2222-:22" )
    QEMU_ARGS+=( "-device" "virtio-net-pci,netdev=net0,romfile=" )
    info "Network enabled (User Mode). SSH mapped: localhost:2222 -> guest:22"
fi

# --- Console & Graphics ---

# Serial console (always attached for logs)
QEMU_ARGS+=( "-serial" "stdio" )

if [ "$CONSOLE" == "serial" ]; then
    QEMU_ARGS+=( "-nographic" )
else
    QEMU_ARGS+=( "-vga" "$CONSOLE" )
    if [ -n "$VNC_PORT" ]; then
        QEMU_ARGS+=( "-vnc" ":${VNC_PORT}" )
        info "VNC started on :${VNC_PORT}"
    fi
fi

# Monitor
QEMU_ARGS+=( "-monitor" "pty" )

# --- Kernel & Initrd ---

if [ -n "$KERNEL_FILE" ]; then
    QEMU_ARGS+=( "-kernel" "$KERNEL_FILE" )

    CMDLINE=""
    # Combine extracted params with necessary console params
    if [ -n "$KERNEL_PARAMS_STR" ]; then
        CMDLINE="${KERNEL_PARAMS_STR}"
    fi

    # Ensure console output is visible if user didn't specify it
    if [[ "$CMDLINE" != *"console="* ]]; then
        CMDLINE="$CMDLINE console=ttyS0"
    fi

    QEMU_ARGS+=( "-append" "$CMDLINE" )

    if [ -n "$INITRD_FILE" ]; then
        QEMU_ARGS+=( "-initrd" "$INITRD_FILE" )
    fi
fi

if [ "$FREEZE" == "1" ]; then
    QEMU_ARGS+=( "-S" )
    warn "VM starting in frozen state (-S)."
fi

# --- Execution ---

info "Starting QEMU (SEV-SNP) on ${CPU_TYPE}..."
echo "Mapping CTRL-C to CTRL-]"
stty intr ^]

# Run QEMU with the array of arguments
"${QEMU_ARGS[@]}"
