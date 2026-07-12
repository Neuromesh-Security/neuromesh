# syntax=docker/dockerfile:1

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

FROM rust:1-bookworm AS agent-builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY packages packages
COPY tests tests
COPY apps/agent-ebpf-sensor apps/agent-ebpf-sensor
COPY --from=ebpf-builder \
    /build/apps/agent-ebpf-sensor/ebpf/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf \
    /build/apps/agent-ebpf-sensor/ebpf/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf

RUN cargo build -p agent-ebpf-sensor --features orchestrator --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends libelf1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=agent-builder \
    /build/target/release/agent-ebpf-sensor \
    /usr/local/bin/agent-ebpf-sensor

ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/agent-ebpf-sensor"]
