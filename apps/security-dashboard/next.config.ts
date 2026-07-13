import type { NextConfig } from "next";

const policyProxyTarget =
  process.env.NEUROMESH_POLICY_ENGINE_PROXY_URL ?? "http://127.0.0.1:8080";

const aiProxyTarget = process.env.NEUROMESH_AI_API_PROXY_URL ?? "http://127.0.0.1:8090";

const k8sWebhookProxyTarget =
  process.env.NEUROMESH_K8S_WEBHOOK_PROXY_URL ?? "https://127.0.0.1:8443";

const nextConfig: NextConfig = {
  transpilePackages: ["@neuromesh/shared-ui-kit"],
  reactStrictMode: true,
  poweredByHeader: false,
  async rewrites() {
    return [
      {
        source: "/api/policy/:path*",
        destination: `${policyProxyTarget}/:path*`,
      },
      {
        source: "/api/ai/:path*",
        destination: `${aiProxyTarget}/:path*`,
      },
      {
        source: "/api/k8s-webhook/:path*",
        destination: `${k8sWebhookProxyTarget}/:path*`,
      },
    ];
  },
};

export default nextConfig;
