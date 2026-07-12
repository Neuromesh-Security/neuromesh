"use client";

import { useTelemetry } from "@/providers";

export function K8sCompliancePanel() {
  const { slowPathInsights, refreshSlowPath } = useTelemetry();

  return (
    <section className="feature-panel">
      <header>
        <h2>Kubernetes Compliance</h2>
        <p>Slow Path GNN insights mapped to admission and runtime controls.</p>
        <button type="button" onClick={() => void refreshSlowPath()}>
          Refresh insights
        </button>
      </header>
      <ul className="compliance-list">
        {slowPathInsights.map((insight) => (
          <li key={insight.insightId}>
            <strong>{insight.summary}</strong>
            <span>confidence {(insight.confidence * 100).toFixed(1)}%</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
