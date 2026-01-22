#!/bin/sh
PREREQ=""

prereqs() { echo "$PREREQ"; }

case "$1" in
    prereqs) prereqs; exit 0 ;;
esac

# Copy your binary from the rootfs into initramfs
mkdir -p "$DESTDIR/usr/bin"
cp -a /usr/bin/snpguard-client "$DESTDIR/usr/bin/"

# Copy configs
mkdir -p "$DESTDIR/etc/snpguard"
cp -a /etc/snpguard/*.pem "$DESTDIR/etc/snpguard/"
cp -a /etc/snpguard/attest.url "$DESTDIR/etc/snpguard/"
cp -a /etc/snpguard/vmk.sealed "$DESTDIR/etc/snpguard/"
