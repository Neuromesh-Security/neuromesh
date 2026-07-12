# syntax=docker/dockerfile:1

FROM golang:1.25-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /zt-policy-engine ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /zt-policy-engine /zt-policy-engine

ENV ZT_POLICY_ENGINE_PORT=8080
EXPOSE 8080

USER nonroot:nonroot
ENTRYPOINT ["/zt-policy-engine"]
