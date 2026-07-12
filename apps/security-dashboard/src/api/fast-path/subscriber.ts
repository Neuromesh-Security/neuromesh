export interface FastPathBlockEvent {
  eventId: string;
  timestampNs: number;
  nodeName: string;
  syscall: string;
  binaryPath: string;
  pid: number;
  ppid: number;
  verdict: "block" | "allow";
  spiffeId?: string;
}

export type FastPathSubscriberStatus =
  | "idle"
  | "connecting"
  | "connected"
  | "reconnecting"
  | "disconnected"
  | "error";

export interface FastPathSubscriberOptions {
  websocketUrl: string;
  grpcWebBaseUrl: string;
  onBlock: (event: FastPathBlockEvent) => void;
  onStatusChange?: (status: FastPathSubscriberStatus) => void;
  reconnectDelayMs?: number;
}

/**
 * Stream A — Fast Path subscriber for deterministic eBPF enforcement events.
 * WebSocket carries live blocks; gRPC-web supplements historical replay.
 */
export class FastPathSubscriber {
  private socket: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly options: FastPathSubscriberOptions;

  constructor(options: FastPathSubscriberOptions) {
    this.options = options;
  }

  connect(): void {
    this.clearReconnectTimer();
    this.options.onStatusChange?.("connecting");

    this.socket = new WebSocket(this.options.websocketUrl);
    this.socket.addEventListener("open", () => {
      this.options.onStatusChange?.("connected");
    });

    this.socket.addEventListener("message", (message) => {
      const event = parseFastPathMessage(message.data);
      if (event) {
        this.options.onBlock(event);
      }
    });

    this.socket.addEventListener("close", () => {
      this.options.onStatusChange?.("disconnected");
      this.scheduleReconnect();
    });

    this.socket.addEventListener("error", () => {
      this.options.onStatusChange?.("error");
      this.socket?.close();
    });
  }

  disconnect(): void {
    this.clearReconnectTimer();
    this.socket?.close();
    this.socket = null;
    this.options.onStatusChange?.("idle");
  }

  async replayRecentBlocks(limit = 250): Promise<FastPathBlockEvent[]> {
    const endpoint = new URL("/neuromesh.telemetry.v1.TelemetryService/ReplayBlocks", this.options.grpcWebBaseUrl);
    endpoint.searchParams.set("limit", String(limit));

    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-neuromesh-stream": "fast-path",
      },
      body: JSON.stringify({ limit }),
    });

    if (!response.ok) {
      throw new Error(`Fast Path replay failed with status ${response.status}`);
    }

    const payload = (await response.json()) as { events?: FastPathBlockEvent[] };
    return payload.events ?? [];
  }

  private scheduleReconnect(): void {
    const delay = this.options.reconnectDelayMs ?? 3_000;
    this.options.onStatusChange?.("reconnecting");
    this.reconnectTimer = setTimeout(() => this.connect(), delay);
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }
}

function parseFastPathMessage(data: unknown): FastPathBlockEvent | null {
  if (typeof data !== "string") {
    return null;
  }

  try {
    const parsed = JSON.parse(data) as FastPathBlockEvent;
    if (!parsed.eventId || !parsed.syscall) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}
