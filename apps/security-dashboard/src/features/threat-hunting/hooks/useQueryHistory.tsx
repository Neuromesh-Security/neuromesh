"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { sanitizeTelemetryString } from "@/lib/security/sanitize";

export interface QueryHistoryEntry {
  id: string;
  query: string;
  executedAt: string;
  resultCount: number;
  status: "success" | "error";
  errorMessage?: string;
}

interface QueryHistoryContextValue {
  entries: QueryHistoryEntry[];
  totalCount: number;
  searchTerm: string;
  setSearchTerm: (value: string) => void;
  addEntry: (
    entry: Omit<QueryHistoryEntry, "id" | "executedAt" | "query"> & { query: string },
  ) => void;
  clearHistory: () => void;
}

const STORAGE_KEY = "neuromesh:threat-hunting:history";
const MAX_HISTORY_ENTRIES = 500;

const QueryHistoryContext = createContext<QueryHistoryContextValue | null>(null);

function readHistory(): QueryHistoryEntry[] {
  if (typeof window === "undefined") {
    return [];
  }

  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return [];
    }

    const parsed = JSON.parse(raw) as QueryHistoryEntry[];
    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed
      .map(sanitizeHistoryEntry)
      .filter((entry): entry is QueryHistoryEntry => entry !== null)
      .slice(0, MAX_HISTORY_ENTRIES);
  } catch {
    return [];
  }
}

function writeHistory(entries: QueryHistoryEntry[]): void {
  if (typeof window === "undefined") {
    return;
  }

  window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(entries.slice(0, MAX_HISTORY_ENTRIES)));
}

function sanitizeHistoryEntry(entry: QueryHistoryEntry): QueryHistoryEntry | null {
  const query = sanitizeTelemetryString(entry.query, 512);
  if (!query) {
    return null;
  }

  return {
    id: sanitizeTelemetryString(entry.id, 64) || crypto.randomUUID(),
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

export function QueryHistoryProvider({ children }: { children: ReactNode }) {
  const [entries, setEntries] = useState<QueryHistoryEntry[]>(() => readHistory());
  const [searchTerm, setSearchTerm] = useState("");

  const persist = useCallback((next: QueryHistoryEntry[]) => {
    setEntries(next);
    writeHistory(next);
  }, []);

  const addEntry = useCallback(
    (
      entry: Omit<QueryHistoryEntry, "id" | "executedAt" | "query"> & { query: string },
    ) => {
      const nextEntry: QueryHistoryEntry = {
        id: crypto.randomUUID(),
        executedAt: new Date().toISOString(),
        query: sanitizeTelemetryString(entry.query, 512),
        resultCount: entry.resultCount,
        status: entry.status,
        errorMessage: entry.errorMessage
          ? sanitizeTelemetryString(entry.errorMessage, 256)
          : undefined,
      };

      persist([nextEntry, ...readHistory()]);
    },
    [persist],
  );

  const clearHistory = useCallback(() => {
    persist([]);
  }, [persist]);

  const filteredEntries = useMemo(() => {
    const normalized = searchTerm.trim().toLowerCase();
    if (!normalized) {
      return entries;
    }

    return entries.filter((entry) => {
      const haystack = `${entry.query} ${entry.errorMessage ?? ""}`.toLowerCase();
      return haystack.includes(normalized);
    });
  }, [entries, searchTerm]);

  const value = useMemo(
    (): QueryHistoryContextValue => ({
      entries: filteredEntries,
      totalCount: entries.length,
      searchTerm,
      setSearchTerm,
      addEntry,
      clearHistory,
    }),
    [addEntry, clearHistory, entries.length, filteredEntries, searchTerm],
  );

  return (
    <QueryHistoryContext.Provider value={value}>{children}</QueryHistoryContext.Provider>
  );
}

export function useQueryHistory(): QueryHistoryContextValue {
  const context = useContext(QueryHistoryContext);
  if (!context) {
    throw new Error("useQueryHistory must be used within QueryHistoryProvider");
  }
  return context;
}
