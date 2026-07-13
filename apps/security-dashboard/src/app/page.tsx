import Link from "next/link";

export default function HomePage() {
  return (
    <main className="dashboard-main">
      <h1>Neuromesh Security</h1>
      <p>Next-Generation Zero Trust and eBPF Runtime Security platform.</p>
      <Link href="/dashboard">Enter Enterprise Dashboard</Link>
    </main>
  );
}
