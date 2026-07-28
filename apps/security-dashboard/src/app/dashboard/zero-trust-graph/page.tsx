"use client";

import dynamic from "next/dynamic";

const ZeroTrustGraphPanel = dynamic(
  () =>
    import("@/features/zero-trust-graph").then((mod) => mod.ZeroTrustGraphPanel),
  { ssr: false, loading: () => <p>Loading Zero Trust Graph...</p> },
);

export default function ZeroTrustGraphPage() {
  return <ZeroTrustGraphPanel />;
}
