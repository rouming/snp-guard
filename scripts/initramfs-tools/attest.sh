#!/bin/sh
PREREQ="udev network"

prereqs() { echo "$PREREQ"; }

case "$1" in
    prereqs) prereqs; exit 0 ;;
esac

. /scripts/functions

panic() {
    echo
    echo "PANIC:"
    echo "PANIC: $*" >&2
    echo "PANIC:"
    echo
    exec sh
}

# Ensure udev settled
udevadm settle

# Bring up network
configure_networking || panic "Networking failed"

# Determine root
if [ -z "$ROOT" ]; then
    ROOT="$(sed -n 's/.*\broot=\([^ ]*\).*/\1/p' /proc/cmdline)"
fi

[ -n "$ROOT" ] || panic "No root= specified"

REAL_ROOT="$(resolve_device "$ROOT")" || panic "Cannot resolve root device"

# Attestation
VMK="$(/usr/bin/snpguard-client attest \
    --url "$(cat /etc/snpguard/attest.url)" \
    --ca-cert /etc/snpguard/ca.pem \
    --sealed-blob /etc/snpguard/vmk.sealed)" || panic "Attestation failed"

# Unlock root
echo -n "$VMK" | cryptsetup luksOpen "$REAL_ROOT" root_crypt --key-file=- \
    || panic "cryptsetup failed"

unset VMK

# Ensure the ROOT variable is overridden
echo "ROOT=/dev/mapper/root_crypt" >> /conf/param.conf
