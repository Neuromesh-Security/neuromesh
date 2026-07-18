# syntax=docker/dockerfile:1

# ------------------------------------------------------------------------------
# toolchain — common build deps (kept lightweight; no Rust builds)
# ------------------------------------------------------------------------------
FROM rust:1-bookworm AS toolchain

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

# ------------------------------------------------------------------------------
# rdkafka-probe — optional fast-fail validation target (heavy; C++ build)
#   docker build --target rdkafka-probe -f apps/agent-ebpf-sensor/Dockerfile .
# Proves bookworm/glibc toolchain + libcurl headers required by rdkafka cmake-build.
# ------------------------------------------------------------------------------
FROM toolchain AS rdkafka-probe
WORKDIR /tmp/rdkafka-probe
RUN cargo init --name rdkafka-probe --bin \
    && cargo add "rdkafka@${RDKAFKA_CRATE_VERSION}" --features cmake-build \
    && cargo build --release

# ------------------------------------------------------------------------------
# ebpf-builder — Rust nightly BPF enforcement object
# ------------------------------------------------------------------------------
FROM rust:1-bookworm AS ebpf-builder

# Pinned to the Issue #53 baseline (see ebpf/rust-toolchain.toml). Floating
# `nightly` + unpinned bpf-linker previously made the enforcement object
# non-reproducible across CI runs.
RUN rustup toolchain install nightly-2026-07-17 --component rust-src \
    && cargo install bpf-linker --version 0.10.4 --locked

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY packages packages
COPY tests tests
COPY apps/agent-ebpf-sensor/ebpf apps/agent-ebpf-sensor/ebpf

WORKDIR /build/apps/agent-ebpf-sensor/ebpf
ENV CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER=bpf-linker
RUN cargo +nightly-2026-07-17 build --package agent-ebpf-sensor-ebpf \
    --target bpfel-unknown-none -Z build-std=core --release

# ------------------------------------------------------------------------------
# agent-builder — orchestrator (deps cached via BuildKit; inherits builder toolchain)
# ------------------------------------------------------------------------------
FROM toolchain AS agent-builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY packages packages
COPY tests tests
COPY apps/agent-ebpf-sensor apps/agent-ebpf-sensor
COPY --from=ebpf-builder \
    /build/apps/agent-ebpf-sensor/ebpf/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf \
    /build/apps/agent-ebpf-sensor/ebpf/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --locked -p agent-ebpf-sensor --features orchestrator --release

# ------------------------------------------------------------------------------
# attestation — digest the exact include_bytes! inputs from this build, then
# Cosign sign-blob with the SAME static key used for image signing (PR #47).
# Manifest+sig are baked into the image (same build trust boundary as the
# binary). CI also Cosign-signs the image digest; admission-time webhook
# enforcement of that signature is a separate deploy dependency (not shipped
# under deploy/ today — see tracked security issue). The public key is NOT
# baked — it is mounted at runtime (Secret), same env-var pattern as the
# webhook.
# ------------------------------------------------------------------------------
FROM agent-builder AS attestation

# Pin Cosign for reproducible sign-blob encoding (ECDSA P-256 / SHA-256).
ARG COSIGN_VERSION=2.4.3
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -fsSL "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" \
         -o /usr/local/bin/cosign \
    && chmod +x /usr/local/bin/cosign \
    && cosign version \
    && rm -rf /var/lib/apt/lists/*

ARG GIT_SHA=unknown
ARG BUILD_TIMESTAMP=unknown
# When true (CI publish on main), a missing/failed sign-blob MUST fail the
# image build — never ship an agent image without bytecode-manifest.sig.
ARG REQUIRE_BYTECODE_SIGNATURE=false

COPY scripts/ci/generate_bytecode_manifest.sh /tmp/generate_bytecode_manifest.sh

RUN mkdir -p /attestation \
    && bash /tmp/generate_bytecode_manifest.sh \
         --sys-exec /build/apps/agent-ebpf-sensor/target/bpf/sys_exec.bpf.o \
         --network-filter /build/apps/agent-ebpf-sensor/target/bpf/network_filter.bpf.o \
         --enforcement /build/apps/agent-ebpf-sensor/ebpf/target/bpfel-unknown-none/release/agent-ebpf-sensor-ebpf \
         --git-sha "${GIT_SHA}" \
         --build-timestamp "${BUILD_TIMESTAMP}" \
         --out /attestation/bytecode-manifest.json

# required=false: fork/PR builds without COSIGN_PRIVATE_KEY omit the signature.
# The agent then fail-closes at startup (no unverified operation).
#
# IMPORTANT: Cosign PEM keys are multiline. CI must inject them via
# `secret-envs` (or `secret-files`), NOT via build-push-action's line-oriented
# `secrets: key=${{ secrets.PEM }}` form — that truncates/corrupts the PEM
# ("invalid pem block") and previously allowed a successful image build with
# no .sig because this shell lacked `set -e`.
RUN --mount=type=secret,id=cosign_private_key,required=false \
    --mount=type=secret,id=cosign_password,required=false \
    set -eu; \
    if [ -f /run/secrets/cosign_private_key ] && [ -s /run/secrets/cosign_private_key ]; then \
      export COSIGN_PASSWORD="$(cat /run/secrets/cosign_password 2>/dev/null || true)"; \
      cosign sign-blob \
        --key /run/secrets/cosign_private_key \
        --yes \
        --tlog-upload=false \
        --output-signature /attestation/bytecode-manifest.sig \
        /attestation/bytecode-manifest.json; \
      test -s /attestation/bytecode-manifest.sig; \
      echo "signed bytecode-manifest.json ($(wc -c < /attestation/bytecode-manifest.sig) bytes sig)"; \
    else \
      echo "WARNING: cosign_private_key BuildKit secret not provided or empty — \
bytecode-manifest.sig omitted; agent will fail-closed at startup"; \
    fi; \
    if [ "${REQUIRE_BYTECODE_SIGNATURE}" = "true" ]; then \
      test -s /attestation/bytecode-manifest.sig || { \
        echo "ERROR: REQUIRE_BYTECODE_SIGNATURE=true but /attestation/bytecode-manifest.sig is missing or empty"; \
        exit 1; \
      }; \
    fi

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

# Baked manifest (+ signature when CI provided the Cosign static key).
COPY --from=attestation /attestation/ /etc/neuromesh/

# Public key is mounted at runtime (see deploy/kubernetes/neuromesh-agent.yaml).
ENV RUST_LOG=info \
    NEUROMESH_BYTECODE_MANIFEST_PATH=/etc/neuromesh/bytecode-manifest.json \
    NEUROMESH_BYTECODE_MANIFEST_SIG_PATH=/etc/neuromesh/bytecode-manifest.sig \
    NEUROMESH_COSIGN_PUBLIC_KEY_PATH=/etc/neuromesh/cosign/cosign.pub

ENTRYPOINT ["/usr/local/bin/agent-ebpf-sensor"]

LABEL org.opencontainers.image.source=https://github.com/Neuromesh-Security/neuromesh
