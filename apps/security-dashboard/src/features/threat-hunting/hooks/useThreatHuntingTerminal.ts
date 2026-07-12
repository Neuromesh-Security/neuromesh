"use client";

import { useCallback, useEffect, useMemo, useRef } from "react";

import { canExecuteThreatHuntingQueries } from "@/lib/auth/rbac";
import { useAuth } from "@/providers";
import { useTelemetry } from "@/providers";

import type { QueryService } from "../api";
import { commandParser } from "../parser";
import { useTerminalBuffer } from "./useTerminalBuffer";
import { useQueryHistory } from "./useQueryHistory";

const PROMPT = "neuromesh> ";

const HELP_TEXT = [
  "Neuromesh Threat Hunting Terminal",
  "",
  "Syntax:",
  "  find <process|network|identity> where <field>=<value> [and <field>=<value> ...] [limit N] [lookback Nm]",
  "",
  "Examples:",
  '  find process where identity=spiffe://neuromesh/agent and syscall=execve',
  '  find network where source_ip=10.0.0.4 and dest_ip=10.0.0.12 limit 100',
  "",
  "Commands:",
  "  help    Show this message",
  "  clear   Clear terminal output",
  "  history Show persisted session history",
].join("\r\n");

export interface UseThreatHuntingTerminalResult {
  canQuery: boolean;
  searchTerm: string;
  setSearchTerm: (value: string) => void;
  historyEntries: ReturnType<typeof useQueryHistory>["entries"];
  historyCount: number;
  clearHistory: () => void;
  onCommand: (command: string) => Promise<void>;
  onFastPathLine: (line: string) => void;
  bufferRevision: number;
}

export function useThreatHuntingTerminal(
  write: (text: string) => void,
  queryService: QueryService,
): UseThreatHuntingTerminalResult {
  const { roles } = useAuth();
  const { fastPathEvents } = useTelemetry();
  const canQuery = canExecuteThreatHuntingQueries(roles);
  const { append, revision } = useTerminalBuffer();
  const {
    entries: historyEntries,
    totalCount: historyCount,
    searchTerm,
    setSearchTerm,
    addEntry,
    clearHistory,
  } = useQueryHistory();

  const processedFastPathCountRef = useRef(0);

  const print = useCallback(
    (text: string, stream: "stdout" | "stderr" | "system" = "stdout") => {
      append(text.endsWith("\r\n") ? text : `${text}\r\n`, stream);
      write(text.endsWith("\r\n") ? text : `${text}\r\n`);
    },
    [append, write],
  );

  const onCommand = useCallback(
    async (rawCommand: string) => {
      const command = rawCommand.trim();
      if (!command) {
        write(PROMPT);
        return;
      }

      if (!canQuery) {
        print("RBAC: query access requires analyst or admin role.", "stderr");
        write(PROMPT);
        return;
      }

      if (command.toLowerCase() === "clear") {
        print("Terminal cleared.", "system");
        write(PROMPT);
        return;
      }

      if (command.toLowerCase() === "help") {
        print(HELP_TEXT, "system");
        write(PROMPT);
        return;
      }

      if (command.toLowerCase() === "history") {
        if (historyCount === 0) {
          print("No queries recorded in this audit session.", "system");
        } else {
          for (const entry of historyEntries) {
            print(
              `[${entry.executedAt}] ${entry.status} (${entry.resultCount}) ${entry.query}`,
              "system",
            );
          }
        }
        write(PROMPT);
        return;
      }

      const parsed = commandParser.parse(command);
      if (!parsed.ok) {
        if (parsed.error.message === "HELP") {
          print(HELP_TEXT, "system");
        } else {
          print(`Parse error: ${parsed.error.message}`, "stderr");
          addEntry({
            query: command,
            resultCount: 0,
            status: "error",
            errorMessage: parsed.error.message,
          });
        }
        write(PROMPT);
        return;
      }

      print(`Executing gRPC query against zt-policy-engine...`, "system");

      try {
        const response = await queryService.searchTelemetry(parsed.query);
        if (response.events.length === 0) {
          print("No telemetry events matched the query.", "stdout");
        } else {
          for (const event of response.events) {
            print(
              [
                event.timestampNs,
                event.nodeName,
                event.identity ?? "-",
                event.syscall ?? "-",
                event.binaryPath ?? "-",
                event.verdict ?? "-",
              ].join(" | "),
            );
          }
        }

        if (response.truncated) {
          print(
            `Results truncated. total=${response.total}, returned=${response.events.length}`,
            "system",
          );
        } else {
          print(`Matched ${response.events.length} event(s).`, "system");
        }

        addEntry({
          query: command,
          resultCount: response.events.length,
          status: "success",
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : "Unknown query failure";
        print(`QueryService error: ${message}`, "stderr");
        addEntry({
          query: command,
          resultCount: 0,
          status: "error",
          errorMessage: message,
        });
      }

      write(PROMPT);
    },
    [
      addEntry,
      canQuery,
      historyCount,
      historyEntries,
      print,
      queryService,
      write,
    ],
  );

  const onFastPathLine = useCallback(
    (line: string) => {
      print(`[fast-path] ${line}`, "system");
    },
    [print],
  );

  useEffect(() => {
    const pending = fastPathEvents.slice(processedFastPathCountRef.current);
    if (pending.length === 0) {
      return;
    }

    const batch = pending
      .map(
        (event) =>
          `${event.timestampNs} ${event.nodeName} ${event.spiffeId ?? "-"} ${event.syscall} ${event.binaryPath} ${event.verdict}`,
      )
      .join("\r\n");

    onFastPathLine(batch);
    processedFastPathCountRef.current = fastPathEvents.length;
  }, [fastPathEvents, onFastPathLine]);

  return useMemo(
    () => ({
      canQuery,
      searchTerm,
      setSearchTerm,
      historyEntries,
      historyCount,
      clearHistory,
      onCommand,
      onFastPathLine,
      bufferRevision: revision,
    }),
    [
      canQuery,
      clearHistory,
      historyCount,
      historyEntries,
      onCommand,
      onFastPathLine,
      revision,
      searchTerm,
      setSearchTerm,
    ],
  );
}
