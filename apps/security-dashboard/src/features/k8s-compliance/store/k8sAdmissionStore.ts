import { EMPTY_SNAPSHOT, asMutableSnapshot } from "@/lib/store/frozen-snapshots";

import type { AdmissionPolicyViolation, K8sWebhookHealth } from "../types";

const SERVER_VIOLATIONS = asMutableSnapshot<AdmissionPolicyViolation>(EMPTY_SNAPSHOT);

const UNAVAILABLE_HEALTH: K8sWebhookHealth = Object.freeze({
  status: "unavailable",
  service: "zt-policy-engine",
  checkedAt: "",
});

type Listener = () => void;

class K8sAdmissionExternalStore {
  private readonly listeners = new Set<Listener>();
  private violations: AdmissionPolicyViolation[] = SERVER_VIOLATIONS;
  private health: K8sWebhookHealth = UNAVAILABLE_HEALTH;
  private loading = false;
  private insightCount = 0;

  subscribe = (listener: Listener): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getServerSnapshot = (): AdmissionPolicyViolation[] => {
    return SERVER_VIOLATIONS;
  };

  getSnapshot = (): AdmissionPolicyViolation[] => {
    return this.violations;
  };

  getHealthServerSnapshot = (): K8sWebhookHealth => {
    return UNAVAILABLE_HEALTH;
  };

  getHealthSnapshot = (): K8sWebhookHealth => {
    return this.health;
  };

  getLoadingServerSnapshot = (): boolean => {
    return false;
  };

  getLoadingSnapshot = (): boolean => {
    return this.loading;
  };

  getInsightCountServerSnapshot = (): number => {
    return 0;
  };

  getInsightCountSnapshot = (): number => {
    return this.insightCount;
  };

  setPosture(
    health: K8sWebhookHealth,
    violations: AdmissionPolicyViolation[],
    insightCount: number,
  ): void {
    this.health = health;
    this.violations =
      violations.length === 0 ? SERVER_VIOLATIONS : violations;
    this.insightCount = insightCount;
    this.emit();
  }

  setLoading(loading: boolean): void {
    if (this.loading === loading) {
      return;
    }
    this.loading = loading;
    this.emit();
  }

  private emit(): void {
    for (const listener of this.listeners) {
      listener();
    }
  }
}

export const k8sAdmissionStore = new K8sAdmissionExternalStore();

export function subscribeK8sAdmissionLoading(_listener: Listener): () => void {
  return () => undefined;
}

export function getK8sAdmissionLoadingSnapshot(): boolean {
  return k8sAdmissionStore.getLoadingSnapshot();
}

export function getK8sAdmissionLoadingServerSnapshot(): boolean {
  return k8sAdmissionStore.getLoadingServerSnapshot();
}
