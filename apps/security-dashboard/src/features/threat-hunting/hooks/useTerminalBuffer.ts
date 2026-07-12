"use client";

import { useCallback, useRef, useState } from "react";

export interface TerminalLine {
  id: string;
  text: string;
  stream: "stdout" | "stderr" | "system";
  timestamp: number;
}

export interface TerminalBufferSnapshot {
  lines: TerminalLine[];
  droppedCount: number;
  revision: number;
}

const DEFAULT_CAPACITY = 20_000;

export function useTerminalBuffer(capacity = DEFAULT_CAPACITY) {
  const linesRef = useRef<TerminalLine[]>([]);
  const droppedCountRef = useRef(0);
  const [revision, setRevision] = useState(0);

  const append = useCallback(
    (text: string, stream: TerminalLine["stream"] = "stdout"): TerminalBufferSnapshot => {
      const chunks = text.split(/\r?\n/).filter((line, index, array) => {
        if (index === array.length - 1 && text.endsWith("\n")) {
          return true;
        }
        return line.length > 0 || index < array.length - 1;
      });

      const timestamp = Date.now();
      for (const chunk of chunks) {
        linesRef.current.push({
          id: `${timestamp}-${linesRef.current.length}`,
          text: chunk,
          stream,
          timestamp,
        });
      }

      if (linesRef.current.length > capacity) {
        const overflow = linesRef.current.length - capacity;
        linesRef.current = linesRef.current.slice(overflow);
        droppedCountRef.current += overflow;
      }

      setRevision((current) => current + 1);
      return {
        lines: [...linesRef.current],
        droppedCount: droppedCountRef.current,
        revision: revision + 1,
      };
    },
    [capacity, revision],
  );

  const clear = useCallback((): TerminalBufferSnapshot => {
    linesRef.current = [];
    setRevision((current) => current + 1);
    return {
      lines: [],
      droppedCount: droppedCountRef.current,
      revision: revision + 1,
    };
  }, [revision]);

  return {
    append,
    clear,
    revision,
  };
}
