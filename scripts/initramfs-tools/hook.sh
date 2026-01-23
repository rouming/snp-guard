#!/bin/sh
set -e

PREREQ=""
prereqs() { echo "$PREREQ"; }

case "$1" in
    prereqs) prereqs; exit 0 ;;
esac

# Required by initramfs-tools
. /usr/share/initramfs-tools/hook-functions

# Deploy crypt modules, dependencies of the SEV-SNP driver
manual_add_modules \
    crypto \
    cryptd \
    aes \
    aesni_intel \
    cbc \
    xts \
    sha256 \
    sha512 \
    dm_crypt

# SEV-SNP guest driver
force_load sev-guest

# SnpGuard client
copy_exec /usr/bin/snpguard-client /usr/bin

# Deliver ip, see the attest.sh for details
copy_exec /usr/sbin/ip /usr/sbin

# Config files
copy_file config /etc/snpguard/attest.url
copy_file config /etc/snpguard/ca.pem
copy_file config /etc/snpguard/vmk.sealed
