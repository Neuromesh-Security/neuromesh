import {
  createQueryServiceFromEnv,
  type QueryService,
  type TelemetryQueryEvent,
} from "@/features/threat-hunting/api";
import { commandParser } from "@/features/threat-hunting/parser";
import { EMPTY_SNAPSHOT, asMutableSnapshot } from "@/lib/store/frozen-snapshots";
import { sanitizeTelemetryString } from "@/lib/security/sanitize";

import type { AdmissionPolicyViolation, K8sWebhookHealth } from "../types";

const DEFAULT_POLICY_BASE =
  process.env.NEXT_PUBLIC_NEUROMESH_POLICY_ENGINE_URL ?? "/api/policy";

const SERVER_VIOLATIONS = asMutableSnapshot<AdmissionPolicyViolation>(EMPTY_SNAPSHOT);
const AGENT_IDENTITY = "spiffe://neuromesh/agent";

const BASELINE_PROCESS_QUERY =
  `find process where identity=${AGENT_IDENTITY} limit 250 lookback 240m`;

const BASELINE_NETWORK_QUERY =
  `find network where identity=${AGENT_IDENTITY} limit 250 lookback 240m`;

const UNAVAILABLE_HEALTH: K8sWebhookHealth = Object.freeze({
  status: "unavailable",
  service: "zt-policy-engine",
  checkedAt: "",
});

export interface ClusterPostureSnapshot {
  health: K8sWebhookHealth;
  violations: AdmissionPolicyViolation[];
  insightCount: number;
  rawEvents: TelemetryQueryEvent[];
}

export const EMPTY_CLUSTER_POSTURE: ClusterPostureSnapshot = Object.freeze({
  health: UNAVAILABLE_HEALTH,
  violations: SERVER_VIOLATIONS,
  insightCount: 0,
  rawEvents: [],
});

function resolvePolicyUrl(baseUrl: string, path: string): string {
  if (baseUrl.startsWith("/")) {
    return `${baseUrl.replace(/\/$/, "")}${path}`;
  }

  return new URL(path, baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`).toString();
}

export async function fetchControlPlaneHealth(
  baseUrl: string = DEFAULT_POLICY_BASE,
): Promise<K8sWebhookHealth> {
  const checkedAt = new Date().toISOString();

  try {
    const response = await fetch(resolvePolicyUrl(baseUrl, "/healthz"), {
      method: "GET",
      cache: "no-store",
      signal: AbortSignal.timeout(4_000),
    });

    if (!response.ok) {
      return {
        ...UNAVAILABLE_HEALTH,
        status: "degraded",
        checkedAt,
      };
    }

    const payload = (await response.json()) as Record<string, unknown>;
    const status = sanitizeTelemetryString(payload.status, 16);
    const service = sanitizeTelemetryString(payload.service, 64);

    return {
      status: status === "ok" ? "ok" : "degraded",
      service: service || "zt-policy-engine",
      checkedAt,
    };
  } catch {
    return {
      ...UNAVAILABLE_HEALTH,
      checkedAt,
    };
  }
}

function resolveGnnScore(event: TelemetryQueryEvent): number {
  if (typeof event.gnnScore === "number" && Number.isFinite(event.gnnScore)) {
    return event.gnnScore;
  }

  return 0;
}

function isCriticalEvent(event: TelemetryQueryEvent, ruleId: string): boolean {
  return (
    event.eventId.includes("sim-t1204") ||
    event.eventId.includes("sim-t1071") ||
    event.eventId.includes("sim-t1059-burst") ||
    ruleId.includes("BLACKLIST") ||
    ruleId.includes("EGRESS") ||
    ruleId.includes("SPAWN-BURST")
  );
}

function mapEventToViolation(event: TelemetryQueryEvent): AdmissionPolicyViolation | null {
  const gnnScore = resolveGnnScore(event);
  const ruleId = event.ruleId ?? "";
  const verdict = event.verdict?.toLowerCase() ?? "";
  const binaryPath = event.binaryPath ?? "";
  const isBlocked = verdict === "block" || verdict === "deny";
  const isBurst = event.eventId.includes("sim-t1059-burst");
  const isCritical = isCriticalEvent(event, ruleId);

  if (!isBlocked && !isBurst && !isCritical && gnnScore < 0.5) {
    return null;
  }

  const effectiveScore =
    gnnScore > 0 ? gnnScore : isCritical && isBlocked ? 0.85 : gnnScore;

  const decision =
    effectiveScore >= 0.8 || isCritical ? ("deny" as const) : ("mutate" as const);

  let reason = "Policy engine telemetry flagged for admission review.";
  if (effectiveScore >= 0.8) {
    reason = `GNN lateral movement score ${effectiveScore.toFixed(2)} — rapid execution edge growth detected`;
  } else if (binaryPath.includes("/tmp/")) {
    reason = "T1204 user execution from ephemeral staging path (/tmp/)";
  } else if (binaryPath.includes("curl")) {
    reason = "T1071 outbound curl to unknown external endpoint";
  } else if (isBurst) {
    reason = "T1059 abnormal shell spawn burst from spiffe-attested workload";
  }

  return {
    id: event.eventId,
    resourceKind: event.resourceKind || "Pod",
    namespace: event.namespace || event.nodeName || "neuromesh-dev",
    name: binaryPath.split("/").pop() || event.nodeName || event.eventId,
    endpoint: isCritical ? "validate" : "mutate",
    decision,
    reason,
    insightId: ruleId || undefined,
    detectedAt: new Date(Math.floor(event.timestampNs / 1_000_000)).toISOString(),
    gnnScore: effectiveScore > 0 ? effectiveScore : undefined,
  };
}

function mergeTelemetryEvents(responses: readonly { events: TelemetryQueryEvent[] }[]): TelemetryQueryEvent[] {
  const merged = new Map<string, TelemetryQueryEvent>();
  for (const response of responses) {
    for (const event of response.events) {
      merged.set(event.eventId, event);
    }
  }
  return Array.from(merged.values());
}

export function mapEventsToViolations(events: readonly TelemetryQueryEvent[]): AdmissionPolicyViolation[] {
  const mapped = events
    .map(mapEventToViolation)
    .filter((violation): violation is AdmissionPolicyViolation => violation !== null);

  if (mapped.length === 0) {
    return SERVER_VIOLATIONS;
  }

  mapped.sort((left, right) => (right.gnnScore ?? 0) - (left.gnnScore ?? 0));
  return mapped;
}

function countGnnInsights(violations: readonly AdmissionPolicyViolation[]): number {
  if (violations.length === 0) {
    return 0;
  }

  return violations.filter(
    (violation) => (violation.gnnScore ?? 0) >= 0.5 || violation.decision === "deny",
  ).length;
}

async function searchBaselineQuery(
  queryService: QueryService,
  command: string,
): Promise<TelemetryQueryEvent[]> {
  const parsed = commandParser.parse(command);
  if (!parsed.ok) {
    console.error("[DEV] K8S PANEL QUERY PARSE ERROR:", parsed.error.message, command);
    return [];
  }

  const response = await queryService.searchTelemetry(parsed.query);
  return response.events;
}

export async function fetchClusterPosture(
  baseUrl: string = DEFAULT_POLICY_BASE,
): Promise<ClusterPostureSnapshot> {
  const queryService = createQueryServiceFromEnv();

  const health = await fetchControlPlaneHealth(baseUrl);

  const telemetryResponses: { events: TelemetryQueryEvent[] }[] = [];

  for (const command of [BASELINE_PROCESS_QUERY, BASELINE_NETWORK_QUERY]) {
    try {
      const events = await searchBaselineQuery(queryService, command);
      telemetryResponses.push({ events });
    } catch (error) {
      const message = error instanceof Error ? error.message : "unknown telemetry failure";
      console.error("[DEV] K8S PANEL TELEMETRY QUERY FAILED:", command, message);
    }
  }

  const events = mergeTelemetryEvents(telemetryResponses);
  const violations = mapEventsToViolations(events);
  const insightCount = countGnnInsights(violations);

  return {
    health,
    violations,
    insightCount,
    rawEvents: events,
  };
}
