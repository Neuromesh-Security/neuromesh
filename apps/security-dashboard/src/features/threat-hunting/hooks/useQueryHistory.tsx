"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from "react";

import { sanitizeTelemetryString } from "@/lib/security/sanitize";

import {
  getQueryHistoryHydratedServerSnapshot,
  getQueryHistoryHydratedSnapshot,
  queryHistoryStore,
  subscribeQueryHistoryHydration,
} from "./queryHistoryStore";

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
  isHydrated: boolean;
  searchTerm: string;
  setSearchTerm: (value: string) => void;
  addEntry: (
    entry: Omit<QueryHistoryEntry, "id" | "executedAt" | "query"> & { query: string },
  ) => void;
  clearHistory: () => void;
}

const QueryHistoryContext = createContext<QueryHistoryContextValue | null>(null);

export function QueryHistoryProvider({ children }: { children: ReactNode }) {
  const entries = useSyncExternalStore(
    queryHistoryStore.subscribe,
    queryHistoryStore.getSnapshot,
    queryHistoryStore.getServerSnapshot,
  );
  const isHydrated = useSyncExternalStore(
    subscribeQueryHistoryHydration,
    getQueryHistoryHydratedSnapshot,
    getQueryHistoryHydratedServerSnapshot,
  );
  const [searchTerm, setSearchTerm] = useState("");

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

      const current = queryHistoryStore.readSnapshot();
      const next =
        current === queryHistoryStore.getServerSnapshot()
          ? [nextEntry]
          : [nextEntry, ...current];
      queryHistoryStore.write(next);
    },
    [],
  );

  const clearHistory = useCallback(() => {
    queryHistoryStore.write([]);
  }, []);

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
      isHydrated,
      searchTerm,
      setSearchTerm,
      addEntry,
      clearHistory,
    }),
    [addEntry, clearHistory, entries.length, filteredEntries, isHydrated, searchTerm],
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
