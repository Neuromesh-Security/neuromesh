export interface ZeroTrustNode {
  id: string;
  spiffeId: string;
  workload: string;
  trustScore: number;
}

export interface ZeroTrustEdge {
  sourceId: string;
  targetId: string;
  policyDecision: "allow" | "deny";
}
