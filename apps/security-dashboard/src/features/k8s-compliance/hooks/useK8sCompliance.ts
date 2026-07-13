"use client";

import { useCallback, useEffect, useSyncExternalStore } from "react";

import { fetchClusterPosture } from "../api/ControlPlaneClient";
import { k8sAdmissionStore } from "../store/k8sAdmissionStore";
import type { AdmissionPolicyViolation, K8sWebhookHealth } from "../types";

export interface UseK8sComplianceResult {
  violations: AdmissionPolicyViolation[];
  webhookHealth: K8sWebhookHealth;
  isRefreshing: boolean;
  insightCount: number;
  refresh: () => Promise<void>;
}

async function hydrateFromControlPlane(): Promise<void> {
  const posture = await fetchClusterPosture();

  console.log("[DEV] K8S PANEL FETCHED DATA:", {
    eventCount: posture.rawEvents.length,
    violationCount: posture.violations.length,
    insightCount: posture.insightCount,
    health: posture.health,
    events: posture.rawEvents,
    violations: posture.violations,
  });

  k8sAdmissionStore.setPosture(
    posture.health,
    posture.violations,
    posture.insightCount,
  );
}

export function useK8sCompliance(): UseK8sComplianceResult {
  const violations = useSyncExternalStore(
    k8sAdmissionStore.subscribe,
    k8sAdmissionStore.getSnapshot,
    k8sAdmissionStore.getServerSnapshot,
  );
  const webhookHealth = useSyncExternalStore(
    k8sAdmissionStore.subscribe,
    k8sAdmissionStore.getHealthSnapshot,
    k8sAdmissionStore.getHealthServerSnapshot,
  );
  const isRefreshing = useSyncExternalStore(
    k8sAdmissionStore.subscribe,
    k8sAdmissionStore.getLoadingSnapshot,
    k8sAdmissionStore.getLoadingServerSnapshot,
  );
  const insightCount = useSyncExternalStore(
    k8sAdmissionStore.subscribe,
    k8sAdmissionStore.getInsightCountSnapshot,
    k8sAdmissionStore.getInsightCountServerSnapshot,
  );

  const refresh = useCallback(async () => {
    k8sAdmissionStore.setLoading(true);
    try {
      await hydrateFromControlPlane();
    } catch (error) {
      const message = error instanceof Error ? error.message : "unknown hydration failure";
      console.error("[DEV] K8S PANEL HYDRATION FAILED:", message);
    } finally {
      k8sAdmissionStore.setLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    const bootstrap = async (): Promise<void> => {
      k8sAdmissionStore.setLoading(true);
      try {
        await hydrateFromControlPlane();
      } catch (error) {
        const message = error instanceof Error ? error.message : "unknown bootstrap failure";
        console.error("[DEV] K8S PANEL BOOTSTRAP FAILED:", message);
      } finally {
        if (!cancelled) {
          k8sAdmissionStore.setLoading(false);
        }
      }
    };

    void bootstrap();

    return () => {
      cancelled = true;
    };
  }, []);

  return {
    violations,
    webhookHealth,
    isRefreshing,
    insightCount,
    refresh,
  };
}
