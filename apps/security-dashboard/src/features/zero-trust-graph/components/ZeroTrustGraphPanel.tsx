"use client";

import { ZeroTrustTopologyGraph } from "@neuromesh/shared-ui-kit";

import { useZeroTrustGraph } from "../hooks";

export function ZeroTrustGraphPanel() {
  const {
    nodes,
    edges,
    revision,
    fastPathStatus,
    baselineInsightId,
    connectionEventCount,
    refreshBaseline,
  } = useZeroTrustGraph();

  const topologyNodes = nodes.map((node) => ({
    id: node.id,
    label: node.label,
    riskScore: node.riskScore,
    spiffeId: node.spiffeId,
    clusterId: node.clusterId,
  }));

  const topologyLinks = edges.map((edge) => ({
    id: edge.id,
    sourceId: edge.sourceId,
    targetId: edge.targetId,
    state: edge.state,
    weight: edge.weight,
    alertType: edge.alertType,
  }));

  return (
    <section className="feature-panel">
      <header className="feature-panel-header">
        <div>
          <h2>Zero Trust Graph</h2>
          <p>SPIFFE-attested workload relationships and policy posture.</p>
        </div>
        <div className="feature-panel-meta">
          <span data-status={fastPathStatus}>Fast Path: {fastPathStatus}</span>
          <span>Baseline: {baselineInsightId ?? "pending"}</span>
          <span>Live edges: {connectionEventCount}</span>
          <button type="button" onClick={() => void refreshBaseline()}>
            Refresh GNN Baseline
          </button>
        </div>
      </header>
      <ZeroTrustTopologyGraph
        nodes={topologyNodes}
        links={topologyLinks}
        revision={revision}
      />
    </section>
  );
}
