import {
  sanitizeIdentifier,
  sanitizeSpiffeId,
  sanitizeTelemetryString,
} from "@/lib/security/sanitize";

import type { ParsedThreatQuery } from "../parser";

export interface GrpcQueryRequest {
  resource: ParsedThreatQuery["resource"];
  filters: Array<{
    field: string;
    operator: "eq";
    value: string;
  }>;
  limit: number;
  lookback_minutes: number;
}

export interface TelemetryQueryEvent {
  eventId: string;
  timestampNs: number;
  nodeName: string;
  identity?: string;
  syscall?: string;
  binaryPath?: string;
  verdict?: string;
  sourceIp?: string;
  destinationIp?: string;
}

export interface TelemetryQueryResponse {
  events: TelemetryQueryEvent[];
  total: number;
  truncated: boolean;
}

export interface QueryServiceOptions {
  baseUrl: string;
  apiKey?: string;
}

/**
 * gRPC-web client for zt-policy-engine telemetry queries.
 */
export class QueryService {
  private readonly options: QueryServiceOptions;

  constructor(options: QueryServiceOptions) {
    this.options = options;
  }

  async searchTelemetry(query: ParsedThreatQuery): Promise<TelemetryQueryResponse> {
    const endpoint = new URL(
      "/neuromesh.policy.v1.QueryService/SearchTelemetry",
      this.options.baseUrl,
    );

    const body: GrpcQueryRequest = {
      resource: query.resource,
      filters: query.filters.map((filter) => ({
        field: filter.field,
        operator: filter.operator,
        value: filter.value,
      })),
      limit: query.limit,
      lookback_minutes: query.lookbackMinutes,
    };

    const response = await fetch(endpoint, {
      method: "POST",
      headers: this.buildHeaders(),
      body: JSON.stringify(body),
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error(`QueryService request failed with status ${response.status}`);
    }

    const payload = (await response.json()) as {
      events?: unknown[];
      total?: number;
      truncated?: boolean;
    };

    return {
      events: (payload.events ?? []).map(sanitizeQueryEvent).filter(Boolean) as TelemetryQueryEvent[],
      total: typeof payload.total === "number" ? payload.total : 0,
      truncated: Boolean(payload.truncated),
    };
  }

  private buildHeaders(): HeadersInit {
    const headers: Record<string, string> = {
      accept: "application/json",
      "content-type": "application/json",
      "x-neuromesh-stream": "query",
    };

    if (this.options.apiKey) {
      headers.authorization = `Bearer ${this.options.apiKey}`;
    }

    return headers;
  }
}

function sanitizeQueryEvent(event: unknown): TelemetryQueryEvent | null {
  if (!event || typeof event !== "object") {
    return null;
  }

  const record = event as Record<string, unknown>;
  const eventId = sanitizeIdentifier(record.eventId ?? record.event_id);
  if (!eventId) {
    return null;
  }

  const timestampNs =
    typeof record.timestampNs === "number"
      ? record.timestampNs
      : typeof record.timestamp_ns === "number"
        ? record.timestamp_ns
        : Date.now() * 1_000_000;

  const identity = record.identity ? sanitizeSpiffeId(record.identity) : null;

  return {
    eventId,
    timestampNs,
    nodeName: sanitizeTelemetryString(record.nodeName ?? record.node_name, 128),
    identity: identity ?? undefined,
    syscall: sanitizeTelemetryString(record.syscall, 64) || undefined,
    binaryPath: sanitizeTelemetryString(record.binaryPath ?? record.binary_path, 256) || undefined,
    verdict: sanitizeTelemetryString(record.verdict, 16) || undefined,
    sourceIp: sanitizeTelemetryString(record.sourceIp ?? record.source_ip, 64) || undefined,
    destinationIp:
      sanitizeTelemetryString(record.destinationIp ?? record.destination_ip, 64) || undefined,
  };
}

export function createQueryServiceFromEnv(): QueryService {
  const baseUrl =
    process.env.NEXT_PUBLIC_NEUROMESH_POLICY_ENGINE_URL ?? "http://localhost:8080";

  return new QueryService({
    baseUrl,
    apiKey: process.env.NEUROMESH_POLICY_ENGINE_API_KEY,
  });
}
