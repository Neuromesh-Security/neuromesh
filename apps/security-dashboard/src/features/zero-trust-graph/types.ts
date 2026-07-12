import type { FastPathConnectionState } from "@/api/fast-path";
import type { GnnInsightEdge, GnnInsightNode } from "@/api/slow-path";

export interface ZeroTrustGraphNode {
  id: string;
  spiffeId: string;
  label: string;
  riskScore: number;
  workload: string;
  trustScore: number;
  clusterId?: string;
}

export interface ZeroTrustGraphEdge {
  id: string;
  sourceId: string;
  targetId: string;
  state: FastPathConnectionState;
  weight: number;
  alertType?: GnnInsightEdge["alertType"];
  live: boolean;
}

export interface ZeroTrustGraphSnapshot {
  nodes: ZeroTrustGraphNode[];
  edges: ZeroTrustGraphEdge[];
  revision: number;
  baselineInsightId: string | null;
}

export function createNodeFromGnn(node: GnnInsightNode): ZeroTrustGraphNode {
  return {
    id: node.id,
    spiffeId: node.label.startsWith("spiffe://") ? node.label : `spiffe://local/${node.id}`,
    label: node.label,
    riskScore: clampRiskScore(node.riskScore),
    workload: node.label,
    trustScore: clampRiskScore(1 - node.riskScore),
    clusterId: node.clusterId,
  };
}

export function createEdgeFromGnn(edge: GnnInsightEdge): ZeroTrustGraphEdge {
  return {
    id: edge.id,
    sourceId: edge.sourceId,
    targetId: edge.targetId,
    state: "connected",
    weight: edge.weight,
    alertType: edge.alertType,
    live: false,
  };
}

export function createNodeFromSpiffe(
  spiffeId: string,
  nodeName?: string,
): ZeroTrustGraphNode {
  const id = spiffeIdToNodeId(spiffeId);
  return {
    id,
    spiffeId,
    label: nodeName ?? spiffeId,
    riskScore: 0.35,
    workload: nodeName ?? id,
    trustScore: 0.65,
  };
}

export function connectionEdgeId(sourceSpiffeId: string, targetSpiffeId: string): string {
  return `${spiffeIdToNodeId(sourceSpiffeId)}::${spiffeIdToNodeId(targetSpiffeId)}`;
}

export function spiffeIdToNodeId(spiffeId: string): string {
  return spiffeId.replace(/^spiffe:\/\//, "").replace(/[/:]/g, "_");
}

function clampRiskScore(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }

  return Math.min(1, Math.max(0, value));
}
