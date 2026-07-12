"use client";

import { useRef, type CSSProperties } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";

export interface LogEntry {
  id: string;
  timestampNs: number;
  severity: "info" | "warn" | "critical" | "block";
  source: "fast-path" | "slow-path";
  message: string;
  nodeName: string;
  metadata?: Record<string, string | number | boolean>;
}

export interface VirtualizedLogGridProps {
  entries: LogEntry[];
  rowHeight?: number;
  overscan?: number;
  className?: string;
  onRowClick?: (entry: LogEntry) => void;
}

const severityColor: Record<LogEntry["severity"], string> = {
  info: "var(--color-log-info, #38bdf8)",
  warn: "var(--color-log-warn, #fbbf24)",
  critical: "var(--color-log-critical, #f87171)",
  block: "var(--color-log-block, #ef4444)",
};

/**
 * High-throughput log surface for Fast/Slow Path telemetry (100k+ events/sec ingest).
 * Uses windowed virtualization to avoid main-thread layout thrashing.
 */
export function VirtualizedLogGrid({
  entries,
  rowHeight = 32,
  overscan = 24,
  className,
  onRowClick,
}: VirtualizedLogGridProps) {
  const parentRef = useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count: entries.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    overscan,
  });

  const containerStyle: CSSProperties = {
    height: "100%",
    overflow: "auto",
    contain: "strict",
  };

  const innerStyle: CSSProperties = {
    height: `${virtualizer.getTotalSize()}px`,
    width: "100%",
    position: "relative",
  };

  return (
    <div
      ref={parentRef}
      className={className}
      style={containerStyle}
      role="log"
      aria-live="polite"
      aria-label="Neuromesh telemetry log stream"
    >
      <div style={innerStyle}>
        {virtualizer.getVirtualItems().map((virtualRow) => {
          const entry = entries[virtualRow.index];
          if (!entry) {
            return null;
          }

          const rowStyle: CSSProperties = {
            position: "absolute",
            top: 0,
            left: 0,
            width: "100%",
            height: `${virtualRow.size}px`,
            transform: `translateY(${virtualRow.start}px)`,
          };

          return (
            <button
              key={entry.id}
              type="button"
              style={rowStyle}
              className="log-grid-row"
              onClick={() => onRowClick?.(entry)}
            >
              <span className="log-grid-ts">
                {new Date(entry.timestampNs / 1_000_000).toISOString()}
              </span>
              <span
                className="log-grid-severity"
                style={{ color: severityColor[entry.severity] }}
              >
                {entry.severity.toUpperCase()}
              </span>
              <span className="log-grid-source">{entry.source}</span>
              <span className="log-grid-node">{entry.nodeName}</span>
              <span className="log-grid-message">{entry.message}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
