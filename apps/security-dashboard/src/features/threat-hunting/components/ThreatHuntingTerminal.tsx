"use client";

import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import { useEffect, useMemo, useRef } from "react";

import { createQueryServiceFromEnv } from "../api";
import { useThreatHuntingTerminal } from "../hooks";

import "@xterm/xterm/css/xterm.css";

const PROMPT = "neuromesh> ";

export interface ThreatHuntingTerminalProps {
  className?: string;
}

export function ThreatHuntingTerminal({ className }: ThreatHuntingTerminalProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const inputBufferRef = useRef("");
  const onCommandRef = useRef<(command: string) => Promise<void>>(async () => undefined);
  const canQueryRef = useRef(false);

  const queryService = useMemo(() => createQueryServiceFromEnv(), []);

  const writeToTerminal = useMemo(() => {
    return (text: string) => {
      terminalRef.current?.write(text);
    };
  }, []);

  const terminalApi = useThreatHuntingTerminal(writeToTerminal, queryService);

  useEffect(() => {
    onCommandRef.current = terminalApi.onCommand;
    canQueryRef.current = terminalApi.canQuery;
  }, [terminalApi.canQuery, terminalApi.onCommand]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) {
      return;
    }

    const terminal = new Terminal({
      cursorBlink: true,
      fontFamily: '"JetBrains Mono", "Cascadia Code", Consolas, monospace',
      fontSize: 13,
      theme: {
        background: "#020617",
        foreground: "#e2e8f0",
        cursor: "#38bdf8",
        selectionBackground: "rgba(56, 189, 248, 0.25)",
      },
      scrollback: 10_000,
      convertEol: true,
    });

    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(container);
    fitAddon.fit();

    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;

    terminal.writeln("Neuromesh Threat Hunting Terminal");
    terminal.writeln(
      canQueryRef.current
        ? "Type 'help' for query syntax. Analyst query access: ENABLED."
        : "Read-only session. Analyst or admin role required for queries.",
    );
    terminal.write(PROMPT);

    const onData = (data: string) => {
      if (!canQueryRef.current) {
        return;
      }

      if (data === "\r") {
        const command = inputBufferRef.current;
        inputBufferRef.current = "";
        terminal.write("\r\n");
        void onCommandRef.current(command);
        return;
      }

      if (data === "\u007f") {
        if (inputBufferRef.current.length === 0) {
          return;
        }
        inputBufferRef.current = inputBufferRef.current.slice(0, -1);
        terminal.write("\b \b");
        return;
      }

      if (data < " " && data !== "\t") {
        return;
      }

      inputBufferRef.current += data;
      terminal.write(data);
    };

    const disposable = terminal.onData(onData);

    const resizeObserver = new ResizeObserver(() => {
      fitAddon.fit();
    });
    resizeObserver.observe(container);

    return () => {
      disposable.dispose();
      resizeObserver.disconnect();
      terminal.dispose();
      terminalRef.current = null;
      fitAddonRef.current = null;
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className={className}
      data-can-query={terminalApi.canQuery}
      data-buffer-revision={terminalApi.bufferRevision}
      aria-label="Threat hunting terminal"
    />
  );
}
