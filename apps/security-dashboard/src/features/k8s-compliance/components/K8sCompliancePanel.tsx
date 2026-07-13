"use client";

import { useCallback } from "react";

import { useIsMounted } from "@/hooks/useIsMounted";

import { useK8sCompliance } from "../hooks/useK8sCompliance";
import type { AdmissionPolicyViolation } from "../types";

export function K8sCompliancePanel() {
  const isMounted = useIsMounted();
  const { violations, webhookHealth, isRefreshing, insightCount, refresh } =
    useK8sCompliance();

  const policyViolations: readonly AdmissionPolicyViolation[] = violations;
  const hasPolicyViolations = policyViolations.length > 0;
  const hasTelemetryInsights = insightCount > 0;

  const controlPlaneStatus =
    hasPolicyViolations || hasTelemetryInsights ? "ok" : webhookHealth.status;

  const handleRefresh = useCallback(() => {
    void refresh();
  }, [refresh]);

  if (!isMounted) {
    return (
      <section className="feature-panel k8s-compliance-panel" aria-busy="true">
        <header className="feature-panel-header">
          <div>
            <h2>Kubernetes Compliance</h2>
            <p>Loading control plane posture…</p>
          </div>
        </header>
      </section>
    );
  }

  return (
    <section className="feature-panel k8s-compliance-panel">
      <header className="feature-panel-header">
        <div>
          <h2>Kubernetes Compliance</h2>
          <p>
            Zero-Trust control plane posture and GNN lateral-movement signals mapped to
            admission policy violations. Telemetry from zt-policy-engine takes precedence
            over admission webhook availability.
          </p>
        </div>
        <div className="feature-panel-meta">
          <span data-status={controlPlaneStatus}>
            Control Plane: {controlPlaneStatus}
          </span>
          <span data-status="deferred">Admission Webhook: deferred</span>
          <span>Service: {webhookHealth.service}</span>
          <span>GNN insights: {insightCount}</span>
          <button type="button" disabled={isRefreshing} onClick={handleRefresh}>
            {isRefreshing ? "Refreshing…" : "Refresh posture"}
          </button>
        </div>
      </header>

      <div className="k8s-compliance-grid">
        <article className="k8s-compliance-card">
          <h3>Control Plane</h3>
          <dl>
            <div>
              <dt>Health</dt>
              <dd>/healthz</dd>
            </div>
            <div>
              <dt>Telemetry Query</dt>
              <dd>SearchTelemetry</dd>
            </div>
            <div>
              <dt>Admission Sync</dt>
              <dd>k8s-admission-webhook (deferred)</dd>
            </div>
            <div>
              <dt>Last check</dt>
              <dd>{webhookHealth.checkedAt || "pending"}</dd>
            </div>
          </dl>
        </article>

        <article className="k8s-compliance-card">
          <h3>Policy Violations</h3>
          {hasPolicyViolations ? (
            <ul className="compliance-list">
              {policyViolations.map((violation) => (
                <li key={violation.id} data-decision={violation.decision}>
                  <div className="k8s-violation-summary">
                    <strong>
                      {violation.resourceKind}/{violation.name}
                    </strong>
                    <span>
                      {violation.namespace} · {violation.endpoint} · {violation.decision}
                      {violation.gnnScore !== undefined
                        ? ` · GNN ${(violation.gnnScore * 100).toFixed(0)}%`
                        : ""}
                    </span>
                    <p>{violation.reason}</p>
                  </div>
                  <time dateTime={violation.detectedAt}>{violation.detectedAt}</time>
                </li>
              ))}
            </ul>
          ) : isRefreshing ? (
            <p className="k8s-compliance-empty">Fetching control plane telemetry…</p>
          ) : (
            <p className="k8s-compliance-empty">
              No high-risk admission violations derived from current control plane telemetry.
            </p>
          )}
        </article>
      </div>
    </section>
  );
}
