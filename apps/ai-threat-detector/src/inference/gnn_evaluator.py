"""Graph-based anomaly scoring for behavioral telemetry."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Final

import networkx as nx

from src.streaming.kafka_consumer import TelemetryEnvelope

logger = logging.getLogger(__name__)

DEFAULT_EDGE_GROWTH_THRESHOLD: Final[int] = 5
DEFAULT_GROWTH_WINDOW_SEC: Final[float] = 10.0


@dataclass(frozen=True, slots=True)
class AnomalyScore:
    """Mock GNN inference output for a flagged graph node."""

    node_id: str
    score: float
    edge_growth: int
    window_secs: float
    reason: str


class GNNEvaluator:
    """Scaffold GNN state using NetworkX process execution graphs.

    Nodes represent hosts/processes; directed edges represent parent→child
    execution relationships observed in BEHAVIOR_ALERT telemetry.
    """

    def __init__(
        self,
        *,
        edge_growth_threshold: int = DEFAULT_EDGE_GROWTH_THRESHOLD,
        growth_window_secs: float = DEFAULT_GROWTH_WINDOW_SEC,
    ) -> None:
        self.graph = nx.DiGraph()
        self.edge_growth_threshold = edge_growth_threshold
        self.growth_window_secs = growth_window_secs
        self._edge_events: dict[str, list[float]] = defaultdict(list)

    def ingest_behavior_alert(self, envelope: TelemetryEnvelope) -> AnomalyScore | None:
        """Add execution edges from a behavior alert and score lateral movement."""
        payload = envelope.payload
        ppid = int(payload.get("ppid", 0))
        last_pid = int(payload.get("last_pid", 0))
        last_comm = str(payload.get("last_comm", "unknown"))
        binary_path = str(payload.get("last_binary_path", ""))

        parent_id = self._process_node(envelope.node_name, ppid, "parent")
        child_id = self._process_node(
            envelope.node_name, last_pid, last_comm, binary_path
        )

        self.graph.add_node(
            parent_id,
            kind="process",
            node_name=envelope.node_name,
            pid=ppid,
        )
        self.graph.add_node(
            child_id,
            kind="process",
            node_name=envelope.node_name,
            pid=last_pid,
            comm=last_comm,
            binary_path=binary_path,
        )
        self.graph.add_edge(
            parent_id,
            child_id,
            event_id=envelope.event_id,
            timestamp_ns=envelope.timestamp_ns,
            spawn_count=int(payload.get("spawn_count", 1)),
        )

        return self._score_node(parent_id)

    def _process_node(
        self,
        host: str,
        pid: int,
        label: str,
        binary_path: str = "",
    ) -> str:
        suffix = f":{binary_path}" if binary_path else ""
        return f"proc:{host}:{pid}:{label}{suffix}"

    def _score_node(self, node_id: str) -> AnomalyScore | None:
        """Mock anomaly function: flag rapid out-edge growth (lateral movement)."""
        now = time.monotonic()
        window_start = now - self.growth_window_secs

        out_edges = list(self.graph.out_edges(node_id, data=True))
        self._edge_events[node_id].append(now)
        self._edge_events[node_id] = [
            ts for ts in self._edge_events[node_id] if ts >= window_start
        ]

        edge_growth = len(self._edge_events[node_id])
        if edge_growth < self.edge_growth_threshold:
            return None

        # Normalized mock score — higher growth yields higher anomaly confidence.
        score = min(1.0, edge_growth / (self.edge_growth_threshold * 2))
        reason = (
            f"rapid execution edge growth detected ({edge_growth} spawns in "
            f"{self.growth_window_secs:.0f}s) — possible lateral movement"
        )

        logger.warning(
            "GNN anomaly flagged | node=%s score=%.2f edges=%d",
            node_id,
            score,
            edge_growth,
        )

        return AnomalyScore(
            node_id=node_id,
            score=score,
            edge_growth=edge_growth,
            window_secs=self.growth_window_secs,
            reason=reason,
        )

    @property
    def node_count(self) -> int:
        return self.graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self.graph.number_of_edges()
