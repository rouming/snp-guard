#!/bin/bash
set -e

INITRD_IN=$1
INITRD_OUT=$2
CLIENT_BIN="./target/x86_64-unknown-linux-musl/release/snpguard-client"

if [ -z "$INITRD_IN" ] || [ -z "$INITRD_OUT" ]; then
    echo "Usage: $0 <in-img> <out-img>"
    exit 1
fi

if [ ! -f "$CLIENT_BIN" ]; then
    echo "Error: Client binary not found at $CLIENT_BIN"
    echo "Please build the client first: make build-client"
    exit 1
fi

WORKDIR=$(mktemp -d)
echo "Workdir: $WORKDIR"
mkdir -p "$WORKDIR/initrd"

echo "Unpacking initrd..."
# Try unmkinitramfs first (initramfs-tools)
if command -v unmkinitramfs &> /dev/null; then
    unmkinitramfs "$INITRD_IN" "$WORKDIR/initrd" 2>/dev/null || {
        # Fallback to cpio/gzip extraction
        echo "unmkinitramfs failed, trying manual extraction..."
        cd "$WORKDIR"
        zcat "$INITRD_IN" 2>/dev/null | cpio -idm 2>/dev/null || {
            echo "Failed to extract initrd"
            rm -rf "$WORKDIR"
            exit 1
        }
        cd - > /dev/null
    }
else
    # Manual extraction for dracut or other formats
    echo "Using manual extraction (dracut/other format)..."
    cd "$WORKDIR"
    zcat "$INITRD_IN" 2>/dev/null | cpio -idm 2>/dev/null || {
        echo "Failed to extract initrd"
        rm -rf "$WORKDIR"
        exit 1
    }
    cd - > /dev/null
fi

echo "Installing snpguard-client..."
mkdir -p "$WORKDIR/initrd/bin"
cp "$CLIENT_BIN" "$WORKDIR/initrd/bin/snpguard-client"
chmod +x "$WORKDIR/initrd/bin/snpguard-client"

echo "Installing attestation hook..."
# For initramfs-tools
if [ -d "$WORKDIR/initrd/scripts" ]; then
    mkdir -p "$WORKDIR/initrd/scripts/local-top"
    cat <<'HOOK' > "$WORKDIR/initrd/scripts/local-top/snpguard_attest"
#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case $1 in prereqs) prereqs; exit 0 ;; esac

# Parse kernel cmdline for attestation URL
ATTEST_URL=""
for x in $(cat /proc/cmdline); do
    case $x in
        rd.attest.url=*)
            ATTEST_URL=${x#rd.attest.url=}
            ;;
    esac
done

if [ -n "$ATTEST_URL" ]; then
    echo "SnpGuard: Starting attestation with $ATTEST_URL..."
    
    # Ensure network is up (wait a bit if needed)
    sleep 2
    
    # Run attestation and capture secret
    if /bin/snpguard-client --url "$ATTEST_URL" > /tmp/disk-secret 2>/tmp/attest-err; then
        echo "SnpGuard: Attestation successful"
        # The secret is now in /tmp/disk-secret
        # This can be used by cryptsetup or other tools
        # Example: cryptsetup luksOpen /dev/sda2 root_crypt --key-file=/tmp/disk-secret
    else
        echo "SnpGuard: Attestation failed!"
        cat /tmp/attest-err >&2
        exit 1
    fi
fi
HOOK
    chmod +x "$WORKDIR/initrd/scripts/local-top/snpguard_attest"
fi

# For dracut
if [ -d "$WORKDIR/initrd/usr/lib/dracut/hooks" ] || [ -d "$WORKDIR/initrd/lib/dracut/hooks" ]; then
    DRACUT_HOOK_DIR="$WORKDIR/initrd/lib/dracut/hooks"
    [ ! -d "$DRACUT_HOOK_DIR" ] && DRACUT_HOOK_DIR="$WORKDIR/initrd/usr/lib/dracut/hooks"
    mkdir -p "$DRACUT_HOOK_DIR/pre-mount"
    cat <<'HOOK' > "$DRACUT_HOOK_DIR/pre-mount/99-snpguard.sh"
#!/bin/bash
# SnpGuard attestation hook for dracut

ATTEST_URL=""
for x in $(cat /proc/cmdline); do
    case $x in
        rd.attest.url=*)
            ATTEST_URL=${x#rd.attest.url=}
            ;;
    esac
done

if [ -n "$ATTEST_URL" ]; then
    echo "SnpGuard: Starting attestation..."
    if /bin/snpguard-client --url "$ATTEST_URL" > /tmp/disk-secret 2>/tmp/attest-err; then
        echo "SnpGuard: Attestation successful"
    else
        echo "SnpGuard: Attestation failed!"
        cat /tmp/attest-err >&2
        exit 1
    fi
fi
HOOK
    chmod +x "$DRACUT_HOOK_DIR/pre-mount/99-snpguard.sh"
fi

echo "Repacking initrd..."
cd "$WORKDIR/initrd"
find . | cpio -o -H newc | gzip > "$INITRD_OUT"
cd - > /dev/null

echo "Done: $INITRD_OUT"
rm -rf "$WORKDIR"
