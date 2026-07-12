# syntax=docker/dockerfile:1

FROM python:3.12-slim-bookworm AS builder

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends gcc librdkafka-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends librdkafka1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY . .

ENV PYTHONUNBUFFERED=1 \
    NEUROMESH_KAFKA_BROKERS=kafka:9092 \
    NEUROMESH_KAFKA_TOPIC=neuromesh.telemetry.v1 \
    NEUROMESH_KAFKA_GROUP_ID=ai-threat-detector

CMD ["python", "main.py"]
