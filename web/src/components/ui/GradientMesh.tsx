import React from "react";
import "./GradientMesh.css";

interface GradientMeshProps {
 intensity?: "low" | "medium" | "high";
 className?: string;
 style?: React.CSSProperties;
}

const CONFIG = {
 low: { count: 2, speed: "20s", blur: 80 },
 medium: { count: 3, speed: "15s", blur: 70 },
 high: { count: 4, speed: "10s", blur: 60 },
};

const BLOBS = [
 { color: "rgba(234, 88, 12, 0.18)", size: 650, top: "-12%", left: "55%", delay: "0s" },
 { color: "rgba(56, 198, 244, 0.14)", size: 550, top: "45%", left: "-8%", delay: "-6s" },
 { color: "rgba(124, 58, 237, 0.10)", size: 500, top: "25%", left: "35%", delay: "-12s" },
 { color: "rgba(234, 88, 12, 0.12)", size: 600, top: "65%", left: "65%", delay: "-8s" },
];

export default function GradientMesh({
 intensity = "medium",
 className = "",
 style = {},
}: GradientMeshProps) {
 const cfg = CONFIG[intensity];

 return (
 <div
 className={`gradient-mesh gradient-mesh--${intensity} ${className}`}
 style={{ ...style, filter: `blur(${cfg.blur}px)` }}
 >
 {BLOBS.slice(0, cfg.count).map((blob, i) => (
 <div
 key={i}
 className="gradient-mesh__blob"
 style={{
 width: blob.size,
 height: blob.size,
 background: `radial-gradient(circle, ${blob.color} 0%, transparent 70%)`,
 top: blob.top,
 left: blob.left,
 animationDuration: cfg.speed,
 animationDelay: blob.delay,
 }}
 />
 ))}
 </div>
 );
}
