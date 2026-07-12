"use client";

import ForceGraph2D from "react-force-graph-2d";
import { memo, useCallback, useMemo } from "react";

export interface TopologyGraphNode {
  id: string;
  label: string;
  riskScore: number;
  spiffeId?: string;
  clusterId?: string;
}

export interface TopologyGraphLink {
  id: string;
  sourceId: string;
  targetId: string;
  state?: "connected" | "disconnected" | "denied";
  weight?: number;
  alertType?: "lateral-movement" | "exfiltration" | "privilege-escalation";
}

export interface ZeroTrustTopologyGraphProps {
  nodes: TopologyGraphNode[];
  links: TopologyGraphLink[];
  revision: number;
  width?: number;
  height?: number;
  className?: string;
}

interface ForceNode extends TopologyGraphNode {
  x?: number;
  y?: number;
}

interface ForceLink {
  id: string;
  source: string;
  target: string;
  state?: TopologyGraphLink["state"];
  weight?: number;
  alertType?: TopologyGraphLink["alertType"];
}

function riskScoreToColor(riskScore: number): string {
  if (riskScore >= 0.8) {
    return "#ef4444";
  }
  if (riskScore >= 0.55) {
    return "#f97316";
  }
  if (riskScore >= 0.35) {
    return "#eab308";
  }

  return "#38bdf8";
}

function ZeroTrustTopologyGraphComponent({
  nodes,
  links,
  revision,
  width = 960,
  height = 540,
  className,
}: ZeroTrustTopologyGraphProps) {
  const graphData = useMemo(
    () => ({
      nodes: nodes.map(
        (node): ForceNode => ({
          ...node,
        }),
      ),
      links: links.map(
        (link): ForceLink => ({
          id: link.id,
          source: link.sourceId,
          target: link.targetId,
          state: link.state,
          weight: link.weight,
          alertType: link.alertType,
        }),
      ),
    }),
    [nodes, links, revision],
  );

  const nodeCanvasObject = useCallback(
    (node: ForceNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const radius = 4 + node.riskScore * 8;
      const x = node.x ?? 0;
      const y = node.y ?? 0;

      ctx.beginPath();
      ctx.fillStyle = riskScoreToColor(node.riskScore);
      ctx.arc(x, y, radius, 0, 2 * Math.PI);
      ctx.fill();

      if (globalScale > 0.85) {
        ctx.font = `${10 / globalScale}px sans-serif`;
        ctx.fillStyle = "#e2e8f0";
        ctx.fillText(node.label, x + radius + 2, y + 3);
      }
    },
    [],
  );

  const linkColor = useCallback((link: ForceLink) => {
    if (link.state === "denied") {
      return "rgba(239, 68, 68, 0.85)";
    }
    if (link.alertType === "lateral-movement") {
      return "rgba(248, 113, 113, 0.75)";
    }

    const weight = link.weight ?? 0.4;
    return `rgba(56, 189, 248, ${Math.min(0.85, 0.25 + weight)})`;
  }, []);

  const linkWidth = useCallback((link: ForceLink) => 1 + (link.weight ?? 0.35) * 2, []);

  return (
    <div
      className={className}
      style={{
        width,
        height,
        borderRadius: 8,
        overflow: "hidden",
        border: "1px solid rgba(148, 163, 184, 0.2)",
        background: "#0b1220",
      }}
      data-renderer="force-graph-2d"
      data-revision={revision}
    >
      <ForceGraph2D
        width={width}
        height={height}
        graphData={graphData}
        nodeId="id"
        nodeCanvasObject={nodeCanvasObject}
        nodePointerAreaPaint={(node, color, ctx) => {
          const forceNode = node as ForceNode;
          const radius = 6 + forceNode.riskScore * 8;
          ctx.fillStyle = color;
          ctx.beginPath();
          ctx.arc(forceNode.x ?? 0, forceNode.y ?? 0, radius, 0, 2 * Math.PI);
          ctx.fill();
        }}
        linkColor={linkColor}
        linkWidth={linkWidth}
        backgroundColor="#0b1220"
        cooldownTicks={48}
        d3AlphaDecay={0.03}
        d3VelocityDecay={0.35}
      />
    </div>
  );
}

export const ZeroTrustTopologyGraph = memo(ZeroTrustTopologyGraphComponent);
