# syntax=docker/dockerfile:1

FROM golang:1.23-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /zt-policy-engine ./cmd/server

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /zt-policy-engine /usr/local/bin/zt-policy-engine

ENV ZT_POLICY_ENGINE_PORT=8080
EXPOSE 8080

USER nobody:nogroup
ENTRYPOINT ["/usr/local/bin/zt-policy-engine"]
