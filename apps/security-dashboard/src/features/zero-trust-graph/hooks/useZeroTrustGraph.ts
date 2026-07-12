"use client";

import { useEffect, useMemo, useReducer, useRef } from "react";

import type { FastPathSubscriberStatus } from "@/api/fast-path";
import { useTelemetry } from "@/providers";

import {
  createEmptyGraphStore,
  graphReducer,
  toGraphSnapshot,
} from "./graphReducer";
import type { ZeroTrustGraphSnapshot } from "../types";

export interface UseZeroTrustGraphResult extends ZeroTrustGraphSnapshot {
  fastPathStatus: FastPathSubscriberStatus;
  connectionEventCount: number;
  refreshBaseline: () => Promise<void>;
}

export function useZeroTrustGraph(): UseZeroTrustGraphResult {
  const {
    slowPathInsights,
    fastPathConnectionEvents,
    fastPathStatus,
    refreshSlowPath,
  } = useTelemetry();

  const [store, dispatch] = useReducer(graphReducer, undefined, createEmptyGraphStore);
  const processedConnectionCountRef = useRef(0);
  const baselineInsightId = slowPathInsights[0]?.insightId ?? null;

  useEffect(() => {
    dispatch({
      type: "set_baseline",
      insight: slowPathInsights[0] ?? null,
    });
  }, [baselineInsightId, slowPathInsights]);

  useEffect(() => {
    const pending = fastPathConnectionEvents.slice(processedConnectionCountRef.current);
    if (pending.length === 0) {
      return;
    }

    for (const event of pending) {
      dispatch({ type: "connection_delta", event });
    }

    processedConnectionCountRef.current = fastPathConnectionEvents.length;
  }, [fastPathConnectionEvents]);

  const snapshot = useMemo(() => toGraphSnapshot(store), [store]);

  return {
    ...snapshot,
    fastPathStatus,
    connectionEventCount: fastPathConnectionEvents.length,
    refreshBaseline: refreshSlowPath,
  };
}
