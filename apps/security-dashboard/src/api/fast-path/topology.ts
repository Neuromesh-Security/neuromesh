import {
  sanitizeIdentifier,
  sanitizeSpiffeId,
  sanitizeTelemetryString,
} from "@/lib/security/sanitize";

export type FastPathConnectionState = "connected" | "disconnected" | "denied";

export interface FastPathConnectionEvent {
  eventId: string;
  timestampNs: number;
  sourceSpiffeId: string;
  targetSpiffeId: string;
  state: FastPathConnectionState;
  nodeName?: string;
}

type FastPathEnvelope =
  | { stream: "block" }
  | { stream: "topology" }
  | { stream: "connection" };

export function parseFastPathConnectionMessage(
  data: unknown,
): FastPathConnectionEvent | null {
  if (typeof data !== "string") {
    return null;
  }

  try {
    const parsed = JSON.parse(data) as Record<string, unknown>;
    const envelope = resolveEnvelope(parsed);
    if (envelope !== "topology" && envelope !== "connection") {
      return null;
    }

    const eventId = sanitizeIdentifier(parsed.eventId);
    const sourceSpiffeId = sanitizeSpiffeId(parsed.sourceSpiffeId ?? parsed.source);
    const targetSpiffeId = sanitizeSpiffeId(parsed.targetSpiffeId ?? parsed.target);
    const state = sanitizeConnectionState(parsed.state);

    if (!eventId || !sourceSpiffeId || !targetSpiffeId || !state) {
      return null;
    }

    const timestampNs =
      typeof parsed.timestampNs === "number" && Number.isFinite(parsed.timestampNs)
        ? parsed.timestampNs
        : Date.now() * 1_000_000;

    const nodeName = parsed.nodeName
      ? sanitizeTelemetryString(parsed.nodeName, 128)
      : undefined;

    return {
      eventId,
      timestampNs,
      sourceSpiffeId,
      targetSpiffeId,
      state,
      nodeName: nodeName || undefined,
    };
  } catch {
    return null;
  }
}

function resolveEnvelope(payload: Record<string, unknown>): FastPathEnvelope["stream"] | null {
  const stream = sanitizeTelemetryString(payload.stream ?? payload.messageType, 32).toLowerCase();

  if (stream === "topology" || stream === "connection") {
    return stream;
  }

  if (
    sanitizeSpiffeId(payload.sourceSpiffeId ?? payload.source) &&
    sanitizeSpiffeId(payload.targetSpiffeId ?? payload.target)
  ) {
    return "connection";
  }

  return null;
}

function sanitizeConnectionState(value: unknown): FastPathConnectionState | null {
  const normalized = sanitizeTelemetryString(value, 16).toLowerCase();
  if (normalized === "connected" || normalized === "disconnected" || normalized === "denied") {
    return normalized;
  }

  return null;
}
