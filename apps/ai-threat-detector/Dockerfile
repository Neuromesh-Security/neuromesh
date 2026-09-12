# syntax=docker/dockerfile:1

FROM python:3.12-slim-bookworm AS builder

# Base image currently ships pip 25.0.1 (5 known CVEs). Upgrade before any
# package install so build-time and copied tooling are patched (>=26.1.2).
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends gcc librdkafka-dev \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade "pip>=26.1.2"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim-bookworm

# Runtime stage also inherits vulnerable pip from the base image; upgrade in
# place so the final image does not ship pip 25.0.1 even if /usr/local/bin
# copy order changes later.
#
# Trivy #146/#147/#148 (msgpack / setuptools under target "Python"): these are
# packages vendored inside pip itself (pip/_vendor/vendor.txt), NOT app deps
# from requirements.txt. Same residual class as agent PCRE2 — not independently
# bumpable until a pip release vendors patched trees. See Issue #201.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends librdkafka1 \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade "pip>=26.1.2"

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY . .

ENV PYTHONUNBUFFERED=1 \
    NEUROMESH_KAFKA_BROKERS=kafka:9094 \
    NEUROMESH_KAFKA_TOPIC=neuromesh.telemetry.v1 \
    NEUROMESH_KAFKA_GROUP_ID=ai-threat-detector

CMD ["python", "main.py"]

LABEL org.opencontainers.image.source=https://github.com/Neuromesh-Security/neuromesh
