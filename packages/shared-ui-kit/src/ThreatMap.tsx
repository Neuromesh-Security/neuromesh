"use client";

import { useEffect, useRef, type CSSProperties } from "react";

export interface ThreatMapNode {
  id: string;
  label: string;
  riskScore: number;
  x: number;
  y: number;
  clusterId?: string;
}

export interface ThreatMapEdge {
  id: string;
  sourceId: string;
  targetId: string;
  weight: number;
  alertType?: "lateral-movement" | "exfiltration" | "privilege-escalation";
}

export interface ThreatMapProps {
  nodes: ThreatMapNode[];
  edges: ThreatMapEdge[];
  width?: number;
  height?: number;
  className?: string;
}

/**
 * WebGL-ready GNN telemetry canvas scaffold.
 * Renders a 2D projection layer today; swap the renderer for WebGL without changing props.
 */
export function ThreatMap({
  nodes,
  edges,
  width = 960,
  height = 540,
  className,
}: ThreatMapProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) {
      return;
    }

    const context = canvas.getContext("2d");
    if (!context) {
      return;
    }

    const devicePixelRatio = window.devicePixelRatio || 1;
    canvas.width = width * devicePixelRatio;
    canvas.height = height * devicePixelRatio;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    context.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);

    context.clearRect(0, 0, width, height);
    context.fillStyle = "#0b1220";
    context.fillRect(0, 0, width, height);

    const nodeById = new Map(nodes.map((node) => [node.id, node]));

    for (const edge of edges) {
      const source = nodeById.get(edge.sourceId);
      const target = nodeById.get(edge.targetId);
      if (!source || !target) {
        continue;
      }

      context.strokeStyle = `rgba(248, 113, 113, ${Math.min(edge.weight, 1)})`;
      context.lineWidth = 1 + edge.weight * 2;
      context.beginPath();
      context.moveTo(source.x * width, source.y * height);
      context.lineTo(target.x * width, target.y * height);
      context.stroke();
    }

    for (const node of nodes) {
      const radius = 4 + node.riskScore * 10;
      context.fillStyle = node.riskScore > 0.7 ? "#ef4444" : "#38bdf8";
      context.beginPath();
      context.arc(node.x * width, node.y * height, radius, 0, Math.PI * 2);
      context.fill();
    }
  }, [nodes, edges, width, height]);

  const wrapperStyle: CSSProperties = {
    width,
    height,
    borderRadius: 8,
    overflow: "hidden",
    border: "1px solid rgba(148, 163, 184, 0.2)",
  };

  return (
    <div className={className} style={wrapperStyle} data-renderer="canvas-webgl-ready">
      <canvas ref={canvasRef} aria-label="GNN threat topology map" role="img" />
    </div>
  );
}
