# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 IONOS SE
# Author: Roman Penyaev <r.peniaev@gmail.com>

# Build stage: compiles all three binaries from source
FROM rust:latest AS builder

WORKDIR /usr/src/snp-guard

RUN apt-get update && apt-get install -y \
    build-essential \
    protobuf-compiler \
    pkg-config \
    libssl-dev \
    musl-tools \
    musl-dev \
    libguestfs-dev \
    libguestfs-tools \
    linux-image-amd64 \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

COPY . .

RUN cargo update

RUN cargo build --release --bin snpguard-client --target x86_64-unknown-linux-musl
RUN cargo build --release --bin snpguard-image
RUN cargo build --release --bin snpguard-server

# Build snpguest (static, MUSL) required by the server to generate measurements
RUN cargo install --git https://github.com/rouming/snpguest.git \
    --rev 206f776e2407bac8dbce70836da9df0e883dc55f \
    --root /usr/local \
    snpguest


# Tools runtime stage: snpguard-client + snpguard-image with libguestfs
FROM debian:testing-slim AS tools

RUN apt-get update && apt-get install -y \
    libguestfs0t64 \
    libguestfs-tools \
    linux-image-amd64 \
    supermin \
    qemu-system-x86 \
    qemu-utils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder \
    /usr/src/snp-guard/target/x86_64-unknown-linux-musl/release/snpguard-client \
    /usr/local/bin/snpguard-client

COPY --from=builder \
    /usr/src/snp-guard/target/release/snpguard-image \
    /usr/local/bin/snpguard-image

ENV LIBGUESTFS_BACKEND=direct

WORKDIR /work

ENTRYPOINT []
CMD ["/bin/bash"]


# Server runtime stage: snpguard-server + snpguest
FROM debian:testing-slim AS server

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/snp-guard/target/release/snpguard-server /usr/local/bin/
COPY --from=builder /usr/local/bin/snpguest /usr/local/bin/
COPY --from=builder /usr/src/snp-guard/src/server/templates /app/templates

WORKDIR /app

ENV RUST_LOG=info
ENV DATA_DIR=/data
# Set NO_TLS=1 (default) for containerized deployments where TLS is terminated
# by the platform. Override with NO_TLS= (empty) to enable TLS inside the container.
ENV NO_TLS=1

RUN mkdir -p /data

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:3000/v1/health || exit 1

ENTRYPOINT ["/bin/sh", "-c", "mkdir -p ${DATA_DIR:-/data}/db && DATA_DIR=${DATA_DIR:-/data} /usr/local/bin/snpguard-server ${NO_TLS:+--no-tls}"]
