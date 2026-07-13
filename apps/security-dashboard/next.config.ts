import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: ["@neuromesh/shared-ui-kit"],
  reactStrictMode: true,
  poweredByHeader: false,
};

export default nextConfig;
