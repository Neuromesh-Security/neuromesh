import type { FastPathConnectionEvent } from "@/api/fast-path";
import type { LateralMovementInsight } from "@/api/slow-path";

import {
  connectionEdgeId,
  createEdgeFromGnn,
  createNodeFromGnn,
  createNodeFromSpiffe,
  spiffeIdToNodeId,
  type ZeroTrustGraphEdge,
  type ZeroTrustGraphNode,
  type ZeroTrustGraphSnapshot,
} from "../types";

type GraphStore = {
  nodes: Map<string, ZeroTrustGraphNode>;
  edges: Map<string, ZeroTrustGraphEdge>;
  baselineInsightId: string | null;
  revision: number;
};

export type GraphReducerAction =
  | { type: "set_baseline"; insight: LateralMovementInsight | null }
  | { type: "connection_delta"; event: FastPathConnectionEvent };

export function createEmptyGraphStore(): GraphStore {
  return {
    nodes: new Map(),
    edges: new Map(),
    baselineInsightId: null,
    revision: 0,
  };
}

export function graphReducer(state: GraphStore, action: GraphReducerAction): GraphStore {
  switch (action.type) {
    case "set_baseline":
      return applyBaseline(state, action.insight);
    case "connection_delta":
      return applyConnectionDelta(state, action.event);
    default:
      return state;
  }
}

export function toGraphSnapshot(store: GraphStore): ZeroTrustGraphSnapshot {
  return {
    nodes: Array.from(store.nodes.values()),
    edges: Array.from(store.edges.values()),
    revision: store.revision,
    baselineInsightId: store.baselineInsightId,
  };
}

function applyBaseline(
  state: GraphStore,
  insight: LateralMovementInsight | null,
): GraphStore {
  if (!insight) {
    if (state.baselineInsightId === null && state.nodes.size === 0) {
      return state;
    }

    return {
      nodes: new Map(),
      edges: new Map(),
      baselineInsightId: null,
      revision: state.revision + 1,
    };
  }

  if (state.baselineInsightId === insight.insightId) {
    return state;
  }

  const nodes = new Map<string, ZeroTrustGraphNode>();
  const edges = new Map<string, ZeroTrustGraphEdge>();

  for (const node of insight.nodes) {
    nodes.set(node.id, createNodeFromGnn(node));
  }

  for (const edge of insight.edges) {
    edges.set(edge.id, createEdgeFromGnn(edge));
  }

  for (const liveEdge of state.edges.values()) {
    if (!liveEdge.live) {
      continue;
    }

    const existing = edges.get(liveEdge.id);
    if (!existing || liveEdge.state !== "connected") {
      edges.set(liveEdge.id, liveEdge);
    }
  }

  for (const [id, node] of state.nodes) {
    if (!nodes.has(id) && node.spiffeId.startsWith("spiffe://")) {
      nodes.set(id, node);
    }
  }

  return {
    nodes,
    edges,
    baselineInsightId: insight.insightId,
    revision: state.revision + 1,
  };
}

function applyConnectionDelta(
  state: GraphStore,
  event: FastPathConnectionEvent,
): GraphStore {
  const sourceId = spiffeIdToNodeId(event.sourceSpiffeId);
  const targetId = spiffeIdToNodeId(event.targetSpiffeId);
  const edgeId = connectionEdgeId(event.sourceSpiffeId, event.targetSpiffeId);
  const existingEdge = state.edges.get(edgeId);

  if (
    existingEdge &&
    existingEdge.state === event.state &&
    !event.nodeName
  ) {
    return state;
  }

  const nodes = new Map(state.nodes);
  const edges = new Map(state.edges);

  if (!nodes.has(sourceId)) {
    nodes.set(sourceId, createNodeFromSpiffe(event.sourceSpiffeId));
  }

  if (!nodes.has(targetId)) {
    nodes.set(targetId, createNodeFromSpiffe(event.targetSpiffeId, event.nodeName));
  }

  if (event.state === "disconnected") {
    if (!edges.has(edgeId)) {
      return state;
    }

    edges.delete(edgeId);
  } else {
    const baselineEdge = edges.get(edgeId);
    edges.set(edgeId, {
      id: edgeId,
      sourceId,
      targetId,
      state: event.state,
      weight: baselineEdge?.weight ?? (event.state === "denied" ? 0.9 : 0.55),
      alertType: baselineEdge?.alertType,
      live: true,
    });
  }

  return {
    nodes,
    edges,
    baselineInsightId: state.baselineInsightId,
    revision: state.revision + 1,
  };
}
