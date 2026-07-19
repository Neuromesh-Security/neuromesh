# syntax=docker/dockerfile:1

FROM golang:1.25-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /k8s-admission-webhook ./src

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /k8s-admission-webhook /k8s-admission-webhook

# TLS termination only (ListenAndServeTLS). Certs and Cosign pubkey are
# mounted at runtime via Secrets — never baked into the image.
EXPOSE 8443

USER nonroot:nonroot
ENTRYPOINT ["/k8s-admission-webhook"]

LABEL org.opencontainers.image.source=https://github.com/Neuromesh-Security/neuromesh
LABEL org.opencontainers.image.title=neuromesh-k8s-admission-webhook
