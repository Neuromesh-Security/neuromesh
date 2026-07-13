import Link from "next/link";
import { cookies } from "next/headers";

import { SESSION_COOKIE_NAME, type DashboardRole } from "@/lib/auth/rbac";
import { verifySessionToken } from "@/lib/auth/session";
import { AuthProvider, TelemetryProvider } from "@/providers";

const NAV_ITEMS = [
  { href: "/dashboard/zero-trust-graph", label: "Zero Trust Graph" },
  { href: "/dashboard/threat-hunting", label: "Threat Hunting" },
  { href: "/dashboard/k8s-compliance", label: "K8s Compliance" },
] as const;

export default async function DashboardLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const sessionToken = (await cookies()).get(SESSION_COOKIE_NAME)?.value;
  const principal = sessionToken ? await verifySessionToken(sessionToken) : null;
  const devBypassAuth = process.env.NEUROMESH_DEV_BYPASS_AUTH === "true";

  const authValue = principal
    ? {
        subject: principal.subject,
        email: principal.email,
        roles: principal.roles,
      }
    : devBypassAuth
      ? {
          subject: "dev-analyst",
          email: "dev-analyst@neuromesh.local",
          roles: ["analyst"] as DashboardRole[],
        }
      : {
          subject: "anonymous",
          email: "",
          roles: [] as DashboardRole[],
        };

  return (
    <AuthProvider principal={authValue}>
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
    </AuthProvider>
  );
}
