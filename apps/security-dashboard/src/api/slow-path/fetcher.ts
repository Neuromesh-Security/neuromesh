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
}

/**
 * Stream B — Slow Path async fetcher for GNN-generated lateral movement insights.
 */
export class SlowPathFetcher {
  private readonly options: SlowPathFetcherOptions;

  constructor(options: SlowPathFetcherOptions) {
    this.options = options;
  }

  async fetchLateralMovementInsights(
    params: SlowPathQueryParams = {},
  ): Promise<LateralMovementInsight[]> {
    const lookbackMinutes = params.lookbackMinutes ?? this.options.defaultLookbackMinutes ?? 60;
    const minConfidence = params.minConfidence ?? 0.55;

    const endpoint = new URL("/v1/insights/lateral-movement", this.options.baseUrl);
    endpoint.searchParams.set("lookback_minutes", String(lookbackMinutes));
    endpoint.searchParams.set("min_confidence", String(minConfidence));
    if (params.nodeName) {
      endpoint.searchParams.set("node_name", params.nodeName);
    }

    const response = await fetch(endpoint, {
      method: "GET",
      headers: this.buildHeaders(),
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error(`Slow Path query failed with status ${response.status}`);
    }

    const payload = (await response.json()) as { insights?: LateralMovementInsight[] };
    return payload.insights ?? [];
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
  const baseUrl =
    process.env.NEXT_PUBLIC_NEUROMESH_AI_API_URL ?? "http://localhost:8090";

  return new SlowPathFetcher({
    baseUrl,
    apiKey: process.env.NEUROMESH_AI_API_KEY,
    defaultLookbackMinutes: 120,
  });
}
