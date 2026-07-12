"use client";

import { ThreatMap } from "@neuromesh/shared-ui-kit";

import { useTelemetry } from "@/providers";

export function ZeroTrustGraphPanel() {
  const { slowPathInsights } = useTelemetry();
  const primaryInsight = slowPathInsights[0];

  const nodes =
    primaryInsight?.nodes.map((node) => ({
      id: node.id,
      label: node.label,
      riskScore: node.riskScore,
      x: node.x,
      y: node.y,
      clusterId: node.clusterId,
    })) ?? [];

  const edges =
    primaryInsight?.edges.map((edge) => ({
      id: edge.id,
      sourceId: edge.sourceId,
      targetId: edge.targetId,
      weight: edge.weight,
      alertType: edge.alertType,
    })) ?? [];

  return (
    <section className="feature-panel">
      <header>
        <h2>Zero Trust Graph</h2>
        <p>SPIFFE-attested workload relationships and policy posture.</p>
      </header>
      <ThreatMap nodes={nodes} edges={edges} />
    </section>
  );
}
