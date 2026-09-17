// Drishti v0.1 — custom React Flow graph node | 11-Jul-2026
import clsx from "clsx";
import {
 Database,
 Globe,
 HardDrive,
 Laptop,
 Monitor,
 Router,
 Server,
 ShieldAlert,
 ShieldCheck,
 Smartphone,
 Cpu,
} from "lucide-react";
import { memo } from "react";
import { Handle, Position } from "reactflow";
import type { GraphNodeData } from "../../api/types";
import { RISK_HEX, money, riskBucket } from "../../lib/format";

const ICONS: Record<string, typeof Server> = {
 database: Database,
 webapp: Globe,
 server: Server,
 workstation: Monitor,
 firewall: ShieldCheck,
 router: Router,
 iot: Cpu,
 cloud: HardDrive,
};

const SEV_HEX: Record<string, string> = {
 critical: RISK_HEX.critical,
 high: RISK_HEX.high,
 medium: RISK_HEX.medium,
 low: RISK_HEX.safe,
};

const THREAT_LABEL: Record<string, string> = {
 arp_spoof: "ARP SPOOF",
 rogue_device: "ROGUE",
 risky_service: "EXPOSED",
 malicious_domain: "C2",
};

export interface RfNodeData extends GraphNodeData {
 selected: boolean;
 inBlast: boolean;
 dimmed: boolean;
 onSelect: (id: string) => void;
 nodeId: string;
}

function ThreatBadge({ data }: { data: RfNodeData }) {
  if (!data.threat) return null;
  const hex = SEV_HEX[data.threat_severity ?? "medium"] ?? RISK_HEX.medium;
  return (
    <span
      title={`${data.threat_title ?? ""}${data.mitre ? " · " + data.mitre : ""}`}
      className="absolute -right-1 -top-2.5 z-10 rounded border px-1.5 py-0.5 font-mono text-[8px] font-bold uppercase tracking-wider shadow-md animate-pulse"
      style={{ background: "#050706", color: hex, borderColor: hex, boxShadow: `0 0 8px ${hex}88` }}
    >
      [{THREAT_LABEL[data.threat_kind ?? ""] ?? "THREAT"}]
    </span>
  );
}

export const GraphNode = memo(function GraphNode({ data }: { data: RfNodeData }) {
  if (data.asset_type === "cloud" && (data.label === "INTERNET" || data.label.startsWith("GATEWAY") || data.label.startsWith("UPLINK"))) {
    return <InternetNode data={data} />;
  }
  if (data.is_device) return <DeviceNode data={data} />;

  const Icon = ICONS[data.asset_type] ?? Server;
  const hex = data.threat ? SEV_HEX[data.threat_severity ?? "medium"] : RISK_HEX[riskBucket(data.risk_score)];

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => data.onSelect(data.nodeId)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          data.onSelect(data.nodeId);
        }
      }}
      className={clsx(
        "relative w-[184px] cursor-pointer rounded border bg-surface-1/90 px-3 py-2.5 backdrop-blur-md transition-all duration-200 shadow-[0_4px_16px_rgba(0,0,0,0.6)]",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-500",
        data.selected && "border-accent-500 shadow-[0_0_20px_rgba(0,255,102,0.3)] ring-1 ring-accent-500",
        data.threat && "animate-pulse border-risk-critical shadow-[0_0_20px_rgba(239,68,68,0.3)]",
        data.inBlast && !data.selected && "animate-blast-pulse border-risk-critical",
        data.dimmed ? "opacity-[0.25]" : "opacity-100",
        !data.threat && !data.inBlast && !data.selected && data.open_findings === 0 && "border-hairline hover:border-accent-500/50",
        !data.threat && !data.inBlast && !data.selected && data.open_findings > 0 && "border-risk-high/70 shadow-[0_0_12px_rgba(249,115,22,0.2)]",
      )}
      style={{
        borderLeft: `3px solid ${data.inBlast && !data.selected ? RISK_HEX.critical : hex}`,
      }}
    >
      <ThreatBadge data={data} />
      <Handle type="target" position={Position.Left} className="!bg-accent-500 !border-0 !w-1.5 !h-1.5 shadow-[0_0_6px_#00ff66]" />
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4 shrink-0" style={{ color: hex }} />
        <div className="min-w-0 flex-1">
          <div className="truncate font-mono text-[11px] font-bold text-ink-primary">
            {data.label}
          </div>
          {data.ip && (
            <div className="truncate font-mono text-[9px] text-ink-muted">
              {data.ip}
            </div>
          )}
        </div>
        {data.is_crown_jewel && (
          <span
            title="Crown jewel"
            className="h-2.5 w-2.5 shrink-0 rounded-full ring-2 ring-risk-critical animate-pulse"
            style={{ background: RISK_HEX.critical, boxShadow: "0 0 10px #ef4444" }}
          />
        )}
      </div>
      <div className="mt-1.5 flex items-center justify-between font-mono text-[10px] text-ink-muted border-t border-hairline/60 pt-1">
        <span>{money(data.business_value)}</span>
        <span className="flex items-center gap-1.5">
          {data.open_findings > 0 && (
            <span className="inline-flex items-center gap-1 text-risk-high font-bold">
              <span className="h-1.5 w-1.5 rounded-full bg-risk-high animate-ping" />
              {data.open_findings}
            </span>
          )}
          <span style={{ color: hex }} className="font-bold">R:{data.risk_score.toFixed(0)}</span>
        </span>
      </div>
      {data.internet_facing && (
        <span className="absolute -right-1 -top-2 rounded border border-accent-500 bg-accent-500/20 px-1 font-mono text-[8px] font-bold uppercase text-accent-400">
          WAN
        </span>
      )}
      <Handle type="source" position={Position.Right} className="!bg-accent-500 !border-0 !w-1.5 !h-1.5 shadow-[0_0_6px_#00ff66]" />
    </div>
  );
});

function DeviceNode({ data }: { data: RfNodeData }) {
  const Icon = data.is_gateway ? Router : data.asset_type === "workstation" ? Laptop : Smartphone;
  const threatHex = data.threat ? SEV_HEX[data.threat_severity ?? "medium"] : null;
  const border = threatHex ?? (data.is_gateway ? RISK_HEX.medium : "#5b6b86");
  const isGateway = data.is_gateway;
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => data.onSelect(data.nodeId)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          data.onSelect(data.nodeId);
        }
      }}
      className={clsx(
        "relative w-[184px] cursor-pointer rounded border bg-surface-1/90 px-3 py-2.5 backdrop-blur-md transition-all duration-200 shadow-[0_4px_16px_rgba(0,0,0,0.6)]",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-500",
        data.selected && "border-accent-500 shadow-[0_0_20px_rgba(0,255,102,0.3)] ring-1 ring-accent-500",
        data.threat && "animate-pulse shadow-[0_0_20px_rgba(239,68,68,0.3)]",
        data.inBlast && !data.selected && "animate-blast-pulse border-risk-critical",
        data.dimmed ? "opacity-[0.25]" : "opacity-100",
        isGateway && "shadow-[0_0_20px_rgba(245,158,66,0.25)]",
      )}
      style={{ borderColor: border, borderLeft: `3px solid ${border}` }}
    >
      <ThreatBadge data={data} />
      <Handle type="target" position={Position.Left} className="!bg-accent-500 !border-0 !w-1.5 !h-1.5 shadow-[0_0_6px_#00ff66]" />
      <div className="flex items-center gap-2">
        {data.threat ? (
          <ShieldAlert className="h-4 w-4 shrink-0" style={{ color: border }} />
        ) : (
          <Icon className="h-4 w-4 shrink-0" style={{ color: border }} />
        )}
        <div className="min-w-0 flex-1">
          <div className="truncate font-mono text-[11px] font-bold text-ink-primary">
            {data.ip || data.label}
          </div>
          {data.ip && data.label !== data.ip && (
            <div className="truncate font-mono text-[9px] text-ink-muted">
              {data.label}
            </div>
          )}
        </div>
        {isGateway && (
          <span
            title="Default gateway — Mother WiFi router"
            className="shrink-0 rounded px-1.5 py-0.5 font-mono text-[8px] font-bold uppercase tracking-wider"
            style={{ background: `${RISK_HEX.medium}22`, color: RISK_HEX.medium, border: `1px solid ${RISK_HEX.medium}66` }}
          >
            GW
          </span>
        )}
        <span
          className={clsx("h-2 w-2 shrink-0 rounded-full", data.online ? "bg-accent-500 shadow-[0_0_6px_#00ff66]" : "bg-ink-muted")}
          title={data.online ? "online" : "offline"}
        />
      </div>
      <div className="mt-1.5 flex items-center justify-between font-mono text-[10px] text-ink-muted border-t border-hairline/60 pt-1">
        <span className="flex items-center gap-1.5">
          {isGateway && (
            <span className="rounded px-1 py-0.5 text-[8px] font-bold"
                  style={{ background: `${RISK_HEX.medium}15`, color: RISK_HEX.medium }}>
              MOTHER_AP
            </span>
          )}
          {!isGateway && <span className="uppercase text-[9px]">{data.is_gateway ? "GW" : "HOST"}</span>}
        </span>
        {data.mac && (
          <span className="truncate max-w-[85px] text-[9px] font-mono" title={data.mac}>{data.mac.slice(0, 8)}</span>
        )}
      </div>
      {isGateway && data.mac && (
        <div className="mt-1.5 rounded border border-hairline bg-surface-2/80 px-2 py-0.5 font-mono text-[9px] text-ink-muted">
          MAC: {data.mac}
        </div>
      )}
      <Handle type="source" position={Position.Right} className="!bg-accent-500 !border-0 !w-1.5 !h-1.5 shadow-[0_0_6px_#00ff66]" />
    </div>
  );
}

function InternetNode({ data }: { data: RfNodeData }) {
  const displayIp = data.ip;
  const isGateway = Boolean(displayIp || data.is_gateway);
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => data.onSelect(data.nodeId)}
      className={clsx(
        "relative flex flex-col gap-1 rounded border bg-surface-1/90 px-3 py-2.5 backdrop-blur-md transition-all duration-200 cursor-pointer min-w-[165px] shadow-[0_4px_16px_rgba(0,0,0,0.6)]",
        data.dimmed ? "opacity-30" : "opacity-100",
        data.selected && "border-accent-500 shadow-[0_0_20px_rgba(0,255,102,0.3)] ring-1 ring-accent-500",
        "border-accent-500/60 shadow-[0_0_15px_rgba(0,255,102,0.15)]"
      )}
      style={{ borderLeft: `3px solid ${RISK_HEX.medium}` }}
    >
      <div className="flex items-center gap-2">
        {isGateway ? (
          <Router className="h-4 w-4 text-accent-400 shrink-0" />
        ) : (
          <Globe className="h-4 w-4 text-accent-400 shrink-0" />
        )}
        <div className="min-w-0 flex-1">
          <div className="truncate font-mono text-[11px] font-bold text-ink-primary">
            {displayIp || (data.label.startsWith("GATEWAY") ? data.label : "GATEWAY // UPLINK")}
          </div>
        </div>
        <span
          className="shrink-0 rounded px-1.5 py-0.5 font-mono text-[8px] font-bold uppercase tracking-wider"
          style={{ background: `${RISK_HEX.medium}22`, color: RISK_HEX.medium, border: `1px solid ${RISK_HEX.medium}66` }}
        >
          {displayIp ? "MOTHER_GW" : "UPLINK"}
        </span>
      </div>
      <div className="flex items-center justify-between font-mono text-[10px] text-ink-muted border-t border-hairline/60 pt-1">
        <span>{displayIp ? "Mother Router" : "Internet Entry"}</span>
        {data.mac ? (
          <span className="text-[9px] text-ink-muted font-mono">{data.mac.slice(0, 8)}</span>
        ) : (
          <span className="text-[9px] font-bold text-accent-400">WAN HOP</span>
        )}
      </div>
      <Handle type="source" position={Position.Right} className="!bg-accent-500 !border-0 !w-1.5 !h-1.5 shadow-[0_0_6px_#00ff66]" />
    </div>
  );
}
