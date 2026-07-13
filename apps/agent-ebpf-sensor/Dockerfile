# syntax=docker/dockerfile:1

# ------------------------------------------------------------------------------
# builder — fast-fail CI validation target
#   docker build --target builder -f apps/agent-ebpf-sensor/Dockerfile .
# Proves bookworm/glibc toolchain + libcurl headers required by rdkafka cmake-build.
# ------------------------------------------------------------------------------
FROM rust:1-bookworm AS builder

ARG RDKAFKA_CRATE_VERSION=0.36

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        g++ \
        cmake \
        pkg-config \
        libssl-dev \
        libcurl4-openssl-dev \
        libsasl2-dev \
        zlib1g-dev \
        clang \
        llvm \
    && rm -rf /var/lib/apt/lists/*

RUN pkg-config --exists libcurl \
    && pkg-config --exists openssl \
    && echo '#include <curl/curl.h>\nint main(void){curl_version();return 0;}' \
       | gcc -x c - -o /tmp/curl-probe $(pkg-config --cflags --libs libcurl) \
    && /tmp/curl-probe \
    && rm /tmp/curl-probe

WORKDIR /tmp/rdkafka-probe
RUN cargo init --name rdkafka-probe --bin \
    && cargo add "rdkafka@${RDKAFKA_CRATE_VERSION}" --features cmake-build \
    && cargo build --release

# ------------------------------------------------------------------------------
# ebpf-builder — Rust nightly BPF enforcement object
# ------------------------------------------------------------------------------
FROM rust:1-bookworm AS ebpf-builder

RUN rustup toolchain install nightly --component rust-src \
    && cargo install bpf-linker --locked

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY packages packages
COPY tests tests
COPY apps/agent-ebpf-sensor/ebpf apps/agent-ebpf-sensor/ebpf

WORKDIR /build/apps/agent-ebpf-sensor/ebpf
ENV CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER=bpf-linker
RUN cargo +nightly build --package agent-ebpf-sensor-ebpf \
    --target bpfel-unknown-none -Z build-std=core --release

# ------------------------------------------------------------------------------
# agent-builder — orchestrator (deps cached via BuildKit; inherits builder toolchain)
# ------------------------------------------------------------------------------
FROM builder AS agent-builder

WORKDIR /build

# Manifest layer: invalidates only when dependency graph changes.
COPY Cargo.toml Cargo.lock ./
COPY packages packages
COPY tests tests

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo fetch --locked

COPY apps/agent-ebpf-sensor apps/agent-ebpf-sensor
COPY --from=ebpf-builder \
    /build/apps/agent-ebpf-sensor/ebpf/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf \
    /build/apps/agent-ebpf-sensor/ebpf/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --locked -p agent-ebpf-sensor --features orchestrator --release

# ------------------------------------------------------------------------------
# runtime — debian:bookworm-slim matches builder glibc (2.36)
# ------------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends libelf1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=agent-builder \
    /build/target/release/agent-ebpf-sensor \
    /usr/local/bin/agent-ebpf-sensor

ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/agent-ebpf-sensor"]
