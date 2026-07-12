export type QueryResource = "process" | "network" | "identity";

export type QueryFilterField =
  | "identity"
  | "syscall"
  | "node"
  | "binary"
  | "verdict"
  | "pid"
  | "ppid"
  | "source_ip"
  | "dest_ip";

export interface QueryFilter {
  field: QueryFilterField;
  operator: "eq";
  value: string;
}

export interface ParsedThreatQuery {
  resource: QueryResource;
  filters: QueryFilter[];
  limit: number;
  lookbackMinutes: number;
}

export interface ParseError {
  message: string;
  position?: number;
}

export type ParseResult =
  | { ok: true; query: ParsedThreatQuery }
  | { ok: false; error: ParseError };

const FIND_PATTERN =
  /^find\s+(process|network|identity)\s*(?:where\s+(.+?))?(?:\s+limit\s+(\d+))?(?:\s+lookback\s+(\d+)m?)?$/i;

const CONDITION_PATTERN =
  /^(identity|syscall|node|binary|verdict|pid|ppid|source_ip|dest_ip)\s*=\s*(?:"([^"]+)"|([^\s]+))$/i;

const FIELD_ALIASES: Record<string, QueryFilterField> = {
  identity: "identity",
  syscall: "syscall",
  node: "node",
  binary: "binary",
  verdict: "verdict",
  pid: "pid",
  ppid: "ppid",
  source_ip: "source_ip",
  dest_ip: "dest_ip",
};

/**
 * Translates analyst-friendly query strings into structured gRPC request payloads.
 *
 * Example:
 *   find process where identity=spiffe://neuromesh/agent and syscall=execve
 */
export class CommandParser {
  parse(input: string): ParseResult {
    const normalized = input.trim().replace(/\s+/g, " ");
    if (!normalized) {
      return { ok: false, error: { message: "Query cannot be empty." } };
    }

    if (normalized.toLowerCase() === "help") {
      return { ok: false, error: { message: "HELP" } };
    }

    const match = FIND_PATTERN.exec(normalized);
    if (!match) {
      return {
        ok: false,
        error: {
          message:
            'Invalid syntax. Use: find <process|network|identity> where <field>=<value> [and ...] [limit N] [lookback Nm]',
        },
      };
    }

    const resource = match[1].toLowerCase() as QueryResource;
    const whereClause = match[2]?.trim();
    const limit = match[3] ? Number.parseInt(match[3], 10) : 250;
    const lookbackMinutes = match[4] ? Number.parseInt(match[4], 10) : 60;

    if (!Number.isFinite(limit) || limit < 1 || limit > 5_000) {
      return { ok: false, error: { message: "limit must be between 1 and 5000." } };
    }

    if (!Number.isFinite(lookbackMinutes) || lookbackMinutes < 1 || lookbackMinutes > 1_440) {
      return {
        ok: false,
        error: { message: "lookback must be between 1 and 1440 minutes." },
      };
    }

    const filters: QueryFilter[] = [];
    if (whereClause) {
      const clauses = whereClause.split(/\s+and\s+/i);
      for (const clause of clauses) {
        const parsed = this.parseCondition(clause.trim());
        if (!parsed.ok) {
          return parsed;
        }
        filters.push(parsed.filter);
      }
    }

    return {
      ok: true,
      query: {
        resource,
        filters,
        limit,
        lookbackMinutes,
      },
    };
  }

  private parseCondition(
    clause: string,
  ): { ok: true; filter: QueryFilter } | { ok: false; error: ParseError } {
    const match = CONDITION_PATTERN.exec(clause);
    if (!match) {
      return {
        ok: false,
        error: { message: `Invalid condition: "${clause}". Expected field=value.` },
      };
    }

    const fieldKey = match[1].toLowerCase();
    const field = FIELD_ALIASES[fieldKey];
    if (!field) {
      return { ok: false, error: { message: `Unsupported field: ${fieldKey}` } };
    }

    const value = (match[2] ?? match[3] ?? "").trim();
    if (!value) {
      return { ok: false, error: { message: `Missing value for field ${field}.` } };
    }

    if (field === "identity" && !value.startsWith("spiffe://")) {
      return {
        ok: false,
        error: { message: "identity must be a SPIFFE URI (spiffe://...)." },
      };
    }

    return {
      ok: true,
      filter: { field, operator: "eq", value },
    };
  }
}

export const commandParser = new CommandParser();
