import type { Metadata } from "next";

import { K8sCompliancePanel } from "@/features/k8s-compliance";

export const metadata: Metadata = {
  title: "Kubernetes Compliance | Neuromesh Security Dashboard",
  description:
    "Admission webhook posture and GNN-derived policy violations for Kubernetes workloads.",
};

export default function K8sCompliancePage() {
  return <K8sCompliancePanel />;
}
