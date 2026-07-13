import { EMPTY_SNAPSHOT, asMutableSnapshot } from "@/lib/store/frozen-snapshots";
import {
  sanitizeIdentifier,
  sanitizeTelemetryString,
} from "@/lib/security/sanitize";

export interface GnnInsightNode {
  id: string;
  label: string;
  riskScore: number;
  x: number;
  y: number;
  clusterId?: string;
}

export interface GnnInsightEdge {
  id: string;
  sourceId: string;
  targetId: string;
  weight: number;
  alertType: "lateral-movement" | "exfiltration" | "privilege-escalation";
}

export interface LateralMovementInsight {
  insightId: string;
  generatedAt: string;
  summary: string;
  confidence: number;
  nodes: GnnInsightNode[];
  edges: GnnInsightEdge[];
}

export interface SlowPathQueryParams {
  lookbackMinutes?: number;
  minConfidence?: number;
  nodeName?: string;
}

export interface SlowPathFetcherOptions {
  baseUrl: string;
  apiKey?: string;
  defaultLookbackMinutes?: number;
  healthCheckTimeoutMs?: number;
}

const EMPTY_INSIGHTS = asMutableSnapshot<LateralMovementInsight>(EMPTY_SNAPSHOT);

const DEFAULT_HEALTH_TIMEOUT_MS = 4_000;

/**
 * Stream B — Slow Path async fetcher for GNN-generated lateral movement insights.
 */
export class SlowPathFetcher {
  private readonly options: SlowPathFetcherOptions;

  constructor(options: SlowPathFetcherOptions) {
    this.options = options;
  }

  async checkHealth(): Promise<boolean> {
    try {
      const endpoint = buildInsightsEndpoint(this.options.baseUrl, {
        lookbackMinutes: 1,
        minConfidence: 0.99,
      });

      const response = await fetch(endpoint, {
        method: "GET",
        headers: this.buildHeaders(),
        cache: "no-store",
        signal: AbortSignal.timeout(
          this.options.healthCheckTimeoutMs ?? DEFAULT_HEALTH_TIMEOUT_MS,
        ),
      });

      return response.status < 500;
    } catch {
      return false;
    }
  }

  async fetchLateralMovementInsights(
    params: SlowPathQueryParams = {},
  ): Promise<LateralMovementInsight[]> {
    try {
      const endpoint = buildInsightsEndpoint(this.options.baseUrl, {
        lookbackMinutes:
          params.lookbackMinutes ?? this.options.defaultLookbackMinutes ?? 60,
        minConfidence: params.minConfidence ?? 0.55,
        nodeName: params.nodeName,
      });

      const response = await fetch(endpoint, {
        method: "GET",
        headers: this.buildHeaders(),
        cache: "no-store",
        signal: AbortSignal.timeout(12_000),
      });

      if (!response.ok) {
        console.warn(
          `[SlowPathFetcher] insights request failed with status ${response.status}`,
        );
        return EMPTY_INSIGHTS;
      }

      const payload = (await response.json()) as { insights?: unknown[] };
      const insights = (payload.insights ?? [])
        .map(sanitizeInsight)
        .filter((insight): insight is LateralMovementInsight => insight !== null);
      return insights.length === 0 ? EMPTY_INSIGHTS : insights;
    } catch (error) {
      const message = error instanceof Error ? error.message : "unknown error";
      console.warn(`[SlowPathFetcher] insights unavailable: ${message}`);
      return EMPTY_INSIGHTS;
    }
  }

  private buildHeaders(): HeadersInit {
    const headers: Record<string, string> = {
      accept: "application/json",
      "x-neuromesh-stream": "slow-path",
    };

    if (this.options.apiKey) {
      headers.authorization = `Bearer ${this.options.apiKey}`;
    }

    return headers;
  }
}

export function createSlowPathFetcherFromEnv(): SlowPathFetcher {
  const baseUrl = process.env.NEXT_PUBLIC_NEUROMESH_AI_API_URL ?? "/api/ai";

  return new SlowPathFetcher({
    baseUrl,
    apiKey: process.env.NEUROMESH_AI_API_KEY,
    defaultLookbackMinutes: 120,
  });
}

function buildInsightsEndpoint(
  baseUrl: string,
  params: Required<Pick<SlowPathQueryParams, "lookbackMinutes" | "minConfidence">> &
    Pick<SlowPathQueryParams, "nodeName">,
): string {
  const path = "/v1/insights/lateral-movement";
  const searchParams = new URLSearchParams({
    lookback_minutes: String(params.lookbackMinutes),
    min_confidence: String(params.minConfidence),
  });

  if (params.nodeName) {
    searchParams.set("node_name", params.nodeName);
  }

  if (baseUrl.startsWith("/")) {
    return `${baseUrl.replace(/\/$/, "")}${path}?${searchParams.toString()}`;
  }

  const root = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  return new URL(`${path}?${searchParams.toString()}`, root).toString();
}

function sanitizeInsight(value: unknown): LateralMovementInsight | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  const record = value as Record<string, unknown>;
  const insightId = sanitizeIdentifier(record.insightId ?? record.insight_id);
  if (!insightId) {
    return null;
  }

  const nodes = Array.isArray(record.nodes)
    ? record.nodes
        .map(sanitizeInsightNode)
        .filter((node): node is GnnInsightNode => node !== null)
    : [];

  const edges = Array.isArray(record.edges)
    ? record.edges
        .map(sanitizeInsightEdge)
        .filter((edge): edge is GnnInsightEdge => edge !== null)
    : [];

  const confidence =
    typeof record.confidence === "number" && Number.isFinite(record.confidence)
      ? record.confidence
      : 0;

  return {
    insightId,
    generatedAt: sanitizeTelemetryString(record.generatedAt ?? record.generated_at, 32),
    summary: sanitizeTelemetryString(record.summary, 512),
    confidence,
    nodes,
    edges,
  };
}

function sanitizeInsightNode(value: unknown): GnnInsightNode | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  const record = value as Record<string, unknown>;
  const id = sanitizeIdentifier(record.id);
  if (!id) {
    return null;
  }

  const riskScore =
    typeof record.riskScore === "number"
      ? record.riskScore
      : typeof record.risk_score === "number"
        ? record.risk_score
        : 0;

  const x = typeof record.x === "number" ? record.x : 0;
  const y = typeof record.y === "number" ? record.y : 0;

  return {
    id,
    label: sanitizeTelemetryString(record.label, 128),
    riskScore,
    x,
    y,
    clusterId: sanitizeTelemetryString(record.clusterId ?? record.cluster_id, 64) || undefined,
  };
}

function sanitizeInsightEdge(value: unknown): GnnInsightEdge | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  const record = value as Record<string, unknown>;
  const id = sanitizeIdentifier(record.id);
  const sourceId = sanitizeIdentifier(record.sourceId ?? record.source_id);
  const targetId = sanitizeIdentifier(record.targetId ?? record.target_id);

  if (!id || !sourceId || !targetId) {
    return null;
  }

  const alertType = sanitizeTelemetryString(record.alertType ?? record.alert_type, 32);
  const normalizedAlertType =
    alertType === "lateral-movement" ||
    alertType === "exfiltration" ||
    alertType === "privilege-escalation"
      ? alertType
      : "lateral-movement";

  return {
    id,
    sourceId,
    targetId,
    weight: typeof record.weight === "number" ? record.weight : 0,
    alertType: normalizedAlertType,
  };
}
