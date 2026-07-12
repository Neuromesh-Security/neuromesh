import Link from "next/link";

import { TelemetryProvider } from "@/providers";

const NAV_ITEMS = [
  { href: "/dashboard/zero-trust-graph", label: "Zero Trust Graph" },
  { href: "/dashboard/threat-hunting", label: "Threat Hunting" },
  { href: "/dashboard/k8s-compliance", label: "K8s Compliance" },
] as const;

export default function DashboardLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <TelemetryProvider>
      <div className="dashboard-shell">
        <aside className="dashboard-nav">
          <h1>Neuromesh</h1>
          <p>Enterprise Command Center</p>
          <nav>
            {NAV_ITEMS.map((item) => (
              <Link key={item.href} href={item.href}>
                {item.label}
              </Link>
            ))}
          </nav>
        </aside>
        <main className="dashboard-main">{children}</main>
      </div>
    </TelemetryProvider>
  );
}
