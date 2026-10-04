# syntax=docker/dockerfile:1

FROM python:3.12-slim-bookworm AS builder

# Base image currently ships pip 25.0.1 (5 known CVEs). Upgrade before any
# package install so build-time tooling is patched (>=26.1.2).
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends gcc librdkafka-dev \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade "pip>=26.1.2"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim-bookworm

# Runtime does not need pip. Historical Trivy findings under target "Python"
# (#146/#147/#148 msgpack/setuptools; #157/#158/#159 urllib3 — CVE-2026-97687/
# 97688/97689) resolve to packages listed in pip's own
# pip/_vendor/vendor.txt, NOT apps/ai-threat-detector/requirements.txt
# (confluent-kafka + networkx only). Removing pip (and ensurepip bundled
# wheels) from the FINAL stage eliminates that residual class; see Issue #201.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends librdkafka1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY . .

# Strip pip / packaging tooling after COPY so builder pip is not retained.
# Also drop ensurepip (stdlib bootstrap + bundled wheels) from the base image.
RUN set -eux; \
    rm -rf \
      /usr/local/lib/python3.12/site-packages/pip \
      /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
      /usr/local/lib/python3.12/site-packages/setuptools \
      /usr/local/lib/python3.12/site-packages/setuptools-*.dist-info \
      /usr/local/lib/python3.12/site-packages/wheel \
      /usr/local/lib/python3.12/site-packages/wheel-*.dist-info \
      /usr/local/lib/python3.12/site-packages/pkg_resources \
      /usr/local/lib/python3.12/site-packages/_distutils_hack \
      /usr/local/lib/python3.12/ensurepip; \
    rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.*; \
    find /usr/local/bin -maxdepth 1 -type f \( -name 'wheel' -o -name 'wheel3*' -o -name 'easy_install*' \) -delete

ENV PYTHONUNBUFFERED=1 \
    NEUROMESH_KAFKA_BROKERS=kafka:9094 \
    NEUROMESH_KAFKA_TOPIC=neuromesh.telemetry.v1 \
    NEUROMESH_KAFKA_GROUP_ID=ai-threat-detector

CMD ["python", "main.py"]

LABEL org.opencontainers.image.source=https://github.com/Neuromesh-Security/neuromesh
