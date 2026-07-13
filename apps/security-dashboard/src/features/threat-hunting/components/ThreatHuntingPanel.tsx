"use client";

import { QueryHistoryProvider, useQueryHistory } from "../hooks";
import { ThreatHuntingTerminal } from "./ThreatHuntingTerminal";

function QueryHistoryPanel() {
  const { entries, totalCount, searchTerm, setSearchTerm, clearHistory } = useQueryHistory();

  return (
    <aside className="threat-history-panel">
      <header>
        <h3>Query History</h3>
        <span>{totalCount} session entries</span>
      </header>
      <label className="threat-history-search">
        <span>Search &amp; Filter</span>
        <input
          type="search"
          value={searchTerm}
          placeholder="Filter by query or error"
          onChange={(event) => setSearchTerm(event.target.value)}
        />
      </label>
      <ul>
        {entries.length === 0 ? (
          <li className="threat-history-empty">No queries in this audit session.</li>
        ) : (
          entries.map((entry) => (
            <li key={entry.id} data-status={entry.status}>
              <code>{entry.query}</code>
              <span>
                {entry.status} · {entry.resultCount} results · {entry.executedAt}
              </span>
              {entry.errorMessage ? <em>{entry.errorMessage}</em> : null}
            </li>
          ))
        )}
      </ul>
      <button type="button" onClick={clearHistory}>
        Clear Session History
      </button>
    </aside>
  );
}

export function ThreatHuntingPanel() {
  return (
    <QueryHistoryProvider>
      <section className="feature-panel threat-hunting-panel">
        <header className="feature-panel-header">
          <div>
            <h2>Threat Hunting</h2>
            <p>
              Interactive terminal for analyst queries against aggregated telemetry via
              zt-policy-engine.
            </p>
          </div>
        </header>
        <div className="threat-hunting-layout">
          <ThreatHuntingTerminal className="threat-hunting-terminal" />
          <QueryHistoryPanel />
        </div>
      </section>
    </QueryHistoryProvider>
  );
}
