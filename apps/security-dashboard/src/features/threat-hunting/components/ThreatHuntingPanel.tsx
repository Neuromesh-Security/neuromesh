"use client";

import { VirtualizedLogGrid, type LogEntry } from "@neuromesh/shared-ui-kit";

import { useTelemetry } from "@/providers";

function toLogEntry(event: {
  eventId: string;
  timestampNs: number;
  nodeName: string;
  syscall: string;
  binaryPath: string;
  verdict: "block" | "allow";
}): LogEntry {
  return {
    id: event.eventId,
    timestampNs: event.timestampNs,
    severity: event.verdict === "block" ? "block" : "info",
    source: "fast-path",
    nodeName: event.nodeName,
    message: `${event.syscall} ${event.binaryPath}`,
  };
}

export function ThreatHuntingPanel() {
  const { fastPathEvents, fastPathStatus } = useTelemetry();
  const entries = fastPathEvents.map(toLogEntry);

  return (
    <section className="feature-panel">
      <header>
        <h2>Threat Hunting</h2>
        <p>Fast Path deterministic blocks from eBPF sensors ({fastPathStatus}).</p>
      </header>
      <div className="log-grid-shell">
        <VirtualizedLogGrid entries={entries} />
      </div>
    </section>
  );
}
