import Link from "next/link";

export default function DashboardIndexPage() {
  return (
    <section>
      <h2>Security Operations Overview</h2>
      <p>Select a module from the navigation to begin investigation.</p>
      <ul>
        <li>
          <Link href="/dashboard/zero-trust-graph">Zero Trust Graph</Link>
        </li>
        <li>
          <Link href="/dashboard/threat-hunting">Threat Hunting</Link>
        </li>
        <li>
          <Link href="/dashboard/k8s-compliance">K8s Compliance</Link>
        </li>
      </ul>
    </section>
  );
}
