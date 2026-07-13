import { EMPTY_SNAPSHOT, asMutableSnapshot } from "@/lib/store/frozen-snapshots";
import { sanitizeTelemetryString } from "@/lib/security/sanitize";

import type { QueryHistoryEntry } from "./useQueryHistory";

const STORAGE_KEY = "neuromesh:threat-hunting:history";
const MAX_HISTORY_ENTRIES = 500;

const SERVER_SNAPSHOT = asMutableSnapshot<QueryHistoryEntry>(EMPTY_SNAPSHOT);

type Listener = () => void;

class QueryHistoryExternalStore {
  private readonly listeners = new Set<Listener>();
  private serialized = "";
  private snapshot: QueryHistoryEntry[] = SERVER_SNAPSHOT;

  subscribe = (listener: Listener): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getServerSnapshot = (): QueryHistoryEntry[] => {
    return SERVER_SNAPSHOT;
  };

  getSnapshot = (): QueryHistoryEntry[] => {
    if (typeof window === "undefined") {
      return SERVER_SNAPSHOT;
    }

    const raw = window.sessionStorage.getItem(STORAGE_KEY) ?? "";
    if (raw === this.serialized) {
      return this.snapshot;
    }

    this.serialized = raw;
    this.snapshot = this.parseSerialized(raw);
    return this.snapshot;
  };

  readSnapshot = (): QueryHistoryEntry[] => {
    return this.getSnapshot();
  };

  write(entries: QueryHistoryEntry[]): void {
    if (typeof window === "undefined") {
      return;
    }

    const payload = entries.slice(0, MAX_HISTORY_ENTRIES);
    const serialized = JSON.stringify(payload);

    window.sessionStorage.setItem(STORAGE_KEY, serialized);
    this.serialized = serialized;
    this.snapshot =
      payload.length === 0 ? SERVER_SNAPSHOT : payload;
    this.emit();
  }

  private emit(): void {
    for (const listener of this.listeners) {
      listener();
    }
  }

  private parseSerialized(raw: string): QueryHistoryEntry[] {
    if (!raw) {
      return SERVER_SNAPSHOT;
    }

    try {
      const parsed = JSON.parse(raw) as QueryHistoryEntry[];
      if (!Array.isArray(parsed) || parsed.length === 0) {
        return SERVER_SNAPSHOT;
      }

      const sanitized = parsed
        .map(sanitizeHistoryEntry)
        .filter((entry): entry is QueryHistoryEntry => entry !== null)
        .slice(0, MAX_HISTORY_ENTRIES);

      return sanitized.length === 0 ? SERVER_SNAPSHOT : sanitized;
    } catch {
      return SERVER_SNAPSHOT;
    }
  }
}

function sanitizeHistoryEntry(entry: QueryHistoryEntry): QueryHistoryEntry | null {
  const query = sanitizeTelemetryString(entry.query, 512);
  if (!query) {
    return null;
  }

  const sanitizedId = sanitizeTelemetryString(entry.id, 64);
  return {
    id: sanitizedId || entry.id,
    query,
    executedAt: sanitizeTelemetryString(entry.executedAt, 32),
    resultCount:
      typeof entry.resultCount === "number" && Number.isFinite(entry.resultCount)
        ? entry.resultCount
        : 0,
    status: entry.status === "error" ? "error" : "success",
    errorMessage: entry.errorMessage
      ? sanitizeTelemetryString(entry.errorMessage, 256)
      : undefined,
  };
}

export const queryHistoryStore = new QueryHistoryExternalStore();

export function subscribeQueryHistoryHydration(_listener: Listener): () => void {
  return () => undefined;
}

export function getQueryHistoryHydratedSnapshot(): boolean {
  return true;
}

export function getQueryHistoryHydratedServerSnapshot(): boolean {
  return false;
}
