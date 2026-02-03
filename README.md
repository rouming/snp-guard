# SnpGuard - SEV-SNP Attestation Service

**Zero-friction bootstrapping for AMD SEV-SNP Confidential VMs.**

SnpGuard is a toolchain and attestation service designed to turn
standard cloud images into Confidential VMs (CVMs) without complex
manual configuration. It automates the lifecycle of measuring boot
artifacts, encrypting disks, and securely releasing keys during the
pre-boot phase.

## Motivation

While libraries for SNP exist (thanks to
[VirTEE](https://virtee.io/)), the ecosystem lacks an end-to-end
toolchain for bootstrapping and attestating confidential
VMs. Currently, operators must stitch together image builders,
measurement calculators, and key brokers manually. `snp-guard` unifies
this into a binding workflow: `convert` -> `register` -> `boot`. It
is designed specifically to fill the IaaS/VM bootstrapping gap that
heavier container-focused solutions overlook.

## The Problem

Deploying AMD SEV-SNP VMs requires solving three technical challenges:

1. **The Measurement Problem:** To verify a CVM, you must calculate
   the precise launch digest of its firmware, kernel, initrd, and
   kernel command line. Any update to these artifacts changes the
   measurement, breaking trust. Calculating this manually is
   error-prone and brittle.

2. **The Secret Delivery Problem:** The VM needs its volume master
   key (VMK) before it can mount the root filesystem. However, you cannot
   bake the key into the image (it would be visible in the host
   storage) or send it over the network without verifying the receiver
   first.

3. **The Bootstrapping Problem:** You need a trusted agent inside the
   guest's early boot environment (initrd) to perform the
   cryptographic handshake with the attestation server before the OS
   creates users or networking configurations.

## The Solution

SnpGuard solves these problems by injecting a lightweight Rust-based
agent into the VM's initrd and providing a centralized server to
manage measurements.

* **Image Conversion:** The `snpguard-image` tool takes a stock
  QCOW2 (e.g., Debian, Ubuntu), encrypts the root partition (LUKS),
  injects the `snpguard-client` and a dedicated hook into the initrd
  and extracts the exact kernel/initrd/cmdline that will be used for
  booting.

* **Registration & Measurement:** The extracted artifacts are
  registered with the SnpGuard Server. The server records the
  measurements and returns a `launch-artifacts.tar.gz` bundle
  containing the kernel, initrd, and the cryptographic ID Block and
  Authentication Block required to launch the VM.  The SnpGuard Server
  leverages launch artifacts measurement to the [`sev` Rust
  library](https://github.com/virtee/sev) and [`snpguest`
  tool](https://github.com/virtee/snpguest) from the VirTEE community.

* **Visual Management (Web UI):** A built-in dashboard allows
  administrators to view and register images, launch artifacts, and
  manage API tokens.

* **Remote Attestation:** On boot, the client (running in the initrd)
  generates an AMD SEV-SNP attestation report. The SnpGuard Server
  verifies this report against the registered measurements and
  securely releases the volume master key (VMK) by encrypting it with
  a user's ephemeral session key.

## Quick Start

If you're cloning the repository for the first time, initialize the
git submodules:

```bash
git submodule update --init --recursive
```

This is required because `snpguest` is included as a git submodule.

### 1. Attestation Server & Web Dashboard

Generate TLS certificates:

```bash
./scripts/generate-tls-certs.sh --output data/tls --ip ${IP}
```

If a hostname should be used instead of `${IP}`, please provide the
`--dns <HOSTNAME>` option instead of the `--ip` option. Multiple `--ip
<IP>` or `--dns <HOSTNAME>` entries can be provided one after another.

Start the server. The server provides both the Attestation API and the
Management Web UI.

```bash
make run-server
```

On first start, the server generates a master password and prints it
to stdout. Copy it, then:

* Navigate to the Web Dashboard at https://${HOSTNAME_OR_IP}:3000
* Log in with the master password
* Go to `Tokens` to create an API token for your CLI client

### 2. Attestation Client

Configure the client to connect to the attestation server:

```bash
cargo run --bin snpguard-client config login \
  --url https://${HOSTNAME_OR_IP}:3000 \
  --token ${TOKEN}
```

### 3. Image Conversion

Download a standard cloud image and convert it to a confidential-ready
image. This process uses **qemu-img** and **libguestfs** to perform
surgical, offline manipulation of the QCOW2 image, including root
filesystem encryption (LUKS), partition management, and injecting the
attestation agent into the initrd.

```bash
# Download latest Debian trixie
wget https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2

# Convert standard Debian to a confidential-ready Debian
cargo run --bin snpguard-image convert \
  --in-image ./debian-13-genericcloud-amd64.qcow2 \
  --out-image confidential.qcow2 \
  --out-staging ./staging \
  --firmware ./OVMF.AMDSEV.fd
```

**Note 1**: To use AMD SEV-SNP technology, SEV-SNP must be enabled in
guest kernels, which is verified by the image tool. For example,
default Debian cloud images support SEV-SNP starting from the Trixie
distribution (Debian 13). Ubuntu introduced SEV-SNP support starting
from Ubuntu Noble (Ubuntu 24.04).

**Note 2**: The image tool requires `qemu-img` and `libguestfs` to be
installed on the system for the `convert` subcommand to inspecet and
modify the QCOW2 image.

**Note 3:** The image tool lists the available kernels and initrd
images with their kernel parameters. The user is prompted to choose
one to be the trusted boot target.

**Note 4:** The OVMF firmware binary must include `SNP_KERNEL_HASHES`,
which is achieved by the special AmdSevX64 build. Refer to [this
guide](https://rouming.github.io/2025/04/01/coco-with-amd-sev.html#guest-ovmf-firmware)
to build OVMF with `SNP_KERNEL_HASHES` enabled.

### 4. Register Attestation Record

Register the new image with the server. This uploads the measurements
and the encrypted key, and returns the signed launch artifacts.

```bash
cargo run --bin snpguard-client manage register \
  --os-name Debian13-CoCo \
  --vcpus 4 --vcpu-type EPYC-Milan \
  --allowed-smt \
  --min-tcb-bootloader 0 --min-tcb-tee 0 --min-tcb-snp 0 --min-tcb-microcode 0 \
  --staging-dir ./staging \
  --out-bundle ./launch-artifacts.tar.gz
```

You can now view this registered image and its measurements in the Web
Dashboard.

### 5. Run CoCo VM

Launch the confidential VM on the platform using the secured disk and
the signed artifacts:

```bash
sudo ./scripts/launch-qemu-snp.sh \
  --hda confidential.qcow2 \
  --artifacts launch-artifacts.tar.gz
```

Upon boot, the VM will verify itself against the server, receive the
key, unlock the disk, and boot the OS.

## Architecture Components

* **snpguard-server:** The core service provides a REST API and a web
  UI for management, validates hardware reports against AMD's
  certificate chain, and securely releases the volume master key.

* **snpguard-image:** CLI tool that leverages **libguestfs** for
  offline image manipulation. It automates the encryption of the
  rootfs and the injection of the attestation agent into the initrd.

* **snpguard-client:** A dual-purpose Rust binary:
  * **Host**: Used by developers to register images and download
    launch bundles.
  * **Guest**: A lightweight, static binary (built against the `musl`
    C standard library for a smaller footprint, and built as static to
    avoid any external dependencies) embedded in the VM's initrd that
    performs the hardware attestation handshake and unlocks the
    rootfs.

## Docker

Build and run the container:

```bash
# Build the image
docker build -t snp-guard .

# Run the container
docker run -d \
  --name snp-guard \
  -p 3000:3000 \
  -v "$(pwd)/data:/data" \
  -e DATA_DIR=/data \
  --restart unless-stopped \
  snp-guard

# Get master password from stdout if started for the first time
docker container logs snp-guard
```

## Documentation

- [API Documentation](docs/api.md)
- [Architecture](docs/architecture.md)
- [User Guide](docs/user_guide.md)
- [Initrd Support](docs/initrd_support.md)

## License

Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
