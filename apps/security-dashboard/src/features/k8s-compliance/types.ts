export type AdmissionDecision = "allow" | "deny" | "mutate";
export type WebhookEndpoint = "validate" | "mutate";

export interface K8sWebhookHealth {
  status: "ok" | "degraded" | "unavailable";
  service: string;
  checkedAt: string;
}

export interface AdmissionPolicyViolation {
  id: string;
  resourceKind: string;
  namespace: string;
  name: string;
  endpoint: WebhookEndpoint;
  decision: AdmissionDecision;
  reason: string;
  insightId?: string;
  detectedAt: string;
  gnnScore?: number;
}
