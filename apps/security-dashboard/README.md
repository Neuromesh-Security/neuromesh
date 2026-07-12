# Neuromesh Security Dashboard

Enterprise Edition command center for Zero Trust and eBPF runtime security.

## Stack

- Next.js 16 (App Router, Turbopack)
- React 19
- Tailwind CSS v4
- `@neuromesh/shared-ui-kit` for high-throughput telemetry surfaces

## Development

```bash
npm install
npm run dev --workspace @neuromesh/security-dashboard
```

## Architecture

- **Fast Path (Stream A):** WebSocket + gRPC-web subscriber for deterministic eBPF blocks
- **Slow Path (Stream B):** Async fetcher for GNN lateral-movement insights from `ai-threat-detector`
- **RBAC:** OIDC/SAML session gate enforced in `src/middleware.ts`
