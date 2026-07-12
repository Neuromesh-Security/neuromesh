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
  type FastPathSubscriberStatus,
} from "@/api/fast-path";
import {
  SlowPathFetcher,
  type LateralMovementInsight,
} from "@/api/slow-path";

interface TelemetryContextValue {
  fastPathStatus: FastPathSubscriberStatus;
  fastPathEvents: FastPathBlockEvent[];
  slowPathInsights: LateralMovementInsight[];
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
  aiApiBaseUrl = process.env.NEXT_PUBLIC_NEUROMESH_AI_API_URL ?? "http://localhost:8090",
}: TelemetryProviderProps) {
  const [fastPathStatus, setFastPathStatus] =
    useState<FastPathSubscriberStatus>("idle");
  const [fastPathEvents, setFastPathEvents] = useState<FastPathBlockEvent[]>([]);
  const [slowPathInsights, setSlowPathInsights] = useState<LateralMovementInsight[]>(
    [],
  );

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
      onStatusChange: setFastPathStatus,
    });

    subscriber.connect();
    return () => subscriber.disconnect();
  }, [grpcWebBaseUrl, websocketUrl]);

  const refreshSlowPath = useCallback(async (): Promise<void> => {
    const insights = await slowPathFetcher.fetchLateralMovementInsights();
    setSlowPathInsights(insights);
  }, [slowPathFetcher]);

  useEffect(() => {
    let cancelled = false;

    slowPathFetcher.fetchLateralMovementInsights().then((insights) => {
      if (!cancelled) {
        setSlowPathInsights(insights);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [slowPathFetcher]);

  const value: TelemetryContextValue = {
    fastPathStatus,
    fastPathEvents,
    slowPathInsights,
    refreshSlowPath,
  };

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
