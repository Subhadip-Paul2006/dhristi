import { type ReactNode } from "react";
import "./GlassCard.css";

interface GlassCardProps {
 children: ReactNode;
 accent?: string;
 icon?: ReactNode;
 hoverable?: boolean;
 className?: string;
 style?: React.CSSProperties;
}

export default function GlassCard({
 children,
 accent = "#ea580c",
 icon,
 hoverable = true,
 className = "",
 style = {},
}: GlassCardProps) {
 return (
 <div
 className={`glass-card ${hoverable ? "glass-card--hoverable" : ""} ${className}`}
 style={{"--glass-accent": accent, ...style} as any}
 >
 {icon && <div className="glass-card__icon" style={{ color: accent }}>{icon}</div>}
 {children}
 </div>
 );
}
