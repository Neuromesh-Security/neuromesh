"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import {
  FastPathSubscriber,
  type FastPathBlockEvent,
  type FastPathConnectionEvent,
  type FastPathSubscriberStatus,
} from "@/api/fast-path";
import {
  SlowPathFetcher,
  type LateralMovementInsight,
} from "@/api/slow-path";
import { EMPTY_SNAPSHOT, asMutableSnapshot } from "@/lib/store/frozen-snapshots";

export type SlowPathStatus = "idle" | "checking" | "ready" | "unavailable";

const EMPTY_BLOCK_EVENTS = asMutableSnapshot<FastPathBlockEvent>(EMPTY_SNAPSHOT);
const EMPTY_CONNECTION_EVENTS = asMutableSnapshot<FastPathConnectionEvent>(EMPTY_SNAPSHOT);
const EMPTY_INSIGHTS = asMutableSnapshot<LateralMovementInsight>(EMPTY_SNAPSHOT);

interface TelemetryContextValue {
  fastPathStatus: FastPathSubscriberStatus;
  fastPathEvents: FastPathBlockEvent[];
  fastPathConnectionEvents: FastPathConnectionEvent[];
  slowPathInsights: LateralMovementInsight[];
  slowPathStatus: SlowPathStatus;
  refreshSlowPath: () => Promise<void>;
}

const TelemetryContext = createContext<TelemetryContextValue | null>(null);

export interface TelemetryProviderProps {
  children: ReactNode;
  websocketUrl?: string;
  grpcWebBaseUrl?: string;
  aiApiBaseUrl?: string;
}

export function TelemetryProvider({
  children,
  websocketUrl = process.env.NEXT_PUBLIC_NEUROMESH_FAST_PATH_WS_URL ??
    "ws://localhost:8081/v1/fast-path",
  grpcWebBaseUrl = process.env.NEXT_PUBLIC_NEUROMESH_GRPC_WEB_URL ??
    "http://localhost:8081",
  aiApiBaseUrl = process.env.NEXT_PUBLIC_NEUROMESH_AI_API_URL ?? "/api/ai",
}: TelemetryProviderProps) {
  const [fastPathStatus, setFastPathStatus] =
    useState<FastPathSubscriberStatus>("idle");
  const [fastPathEvents, setFastPathEvents] =
    useState<FastPathBlockEvent[]>(EMPTY_BLOCK_EVENTS);
  const [fastPathConnectionEvents, setFastPathConnectionEvents] = useState<
    FastPathConnectionEvent[]
  >(EMPTY_CONNECTION_EVENTS);
  const [slowPathInsights, setSlowPathInsights] =
    useState<LateralMovementInsight[]>(EMPTY_INSIGHTS);
  const [slowPathStatus, setSlowPathStatus] = useState<SlowPathStatus>("idle");

  const slowPathFetcher = useMemo(
    () => new SlowPathFetcher({ baseUrl: aiApiBaseUrl }),
    [aiApiBaseUrl],
  );

  useEffect(() => {
    const subscriber = new FastPathSubscriber({
      websocketUrl,
      grpcWebBaseUrl,
      onBlock: (event) => {
        setFastPathEvents((current) => [event, ...current].slice(0, 5_000));
      },
      onConnectionChange: (event) => {
        setFastPathConnectionEvents((current) => [event, ...current].slice(0, 10_000));
      },
      onStatusChange: setFastPathStatus,
    });

    subscriber.connect();
    return () => subscriber.disconnect();
  }, [grpcWebBaseUrl, websocketUrl]);

  const refreshSlowPath = useCallback(async (): Promise<void> => {
    setSlowPathStatus("checking");
    const healthy = await slowPathFetcher.checkHealth();
    if (!healthy) {
      setSlowPathInsights(EMPTY_INSIGHTS);
      setSlowPathStatus("unavailable");
      return;
    }

    const insights = await slowPathFetcher.fetchLateralMovementInsights();
    setSlowPathInsights(
      insights.length === 0 ? EMPTY_INSIGHTS : insights,
    );
    setSlowPathStatus("ready");
  }, [slowPathFetcher]);

  useEffect(() => {
    let cancelled = false;

    const initializeSlowPath = async (): Promise<void> => {
      setSlowPathStatus("checking");
      const healthy = await slowPathFetcher.checkHealth();
      if (cancelled) {
        return;
      }

      if (!healthy) {
        setSlowPathInsights(EMPTY_INSIGHTS);
        setSlowPathStatus("unavailable");
        return;
      }

      const insights = await slowPathFetcher.fetchLateralMovementInsights();
      if (!cancelled) {
        setSlowPathInsights(
          insights.length === 0 ? EMPTY_INSIGHTS : insights,
        );
        setSlowPathStatus("ready");
      }
    };

    void initializeSlowPath();

    return () => {
      cancelled = true;
    };
  }, [slowPathFetcher]);

  const value = useMemo(
    (): TelemetryContextValue => ({
      fastPathStatus,
      fastPathEvents,
      fastPathConnectionEvents,
      slowPathInsights,
      slowPathStatus,
      refreshSlowPath,
    }),
    [
      fastPathConnectionEvents,
      fastPathEvents,
      fastPathStatus,
      refreshSlowPath,
      slowPathInsights,
      slowPathStatus,
    ],
  );

  return (
    <TelemetryContext.Provider value={value}>{children}</TelemetryContext.Provider>
  );
}

export function useTelemetry(): TelemetryContextValue {
  const context = useContext(TelemetryContext);
  if (!context) {
    throw new Error("useTelemetry must be used within TelemetryProvider");
  }
  return context;
}
