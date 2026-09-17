import React, { useState, useEffect, useRef } from "react";
import { Link, Navigate } from "react-router-dom";
import {
  motion,
  AnimatePresence,
  useScroll,
  useSpring,
  useTransform,
} from "framer-motion";
import {
  Shield,
  Activity,
  ArrowRight,
  ChevronDown,
  Lock,
  Layers,
  CheckCircle2,
  DollarSign,
  Network,
  Eye,
  Terminal,
  Cpu,
  Server,
  Zap,
} from "lucide-react";
import { useAuth } from "../../auth";
import "./landing.css";
import "./landing-cinema.css";
import heroBg from "../../assets/hero-bg.jpg";
import { EntryAnimation } from "./EntryAnimation";

/* ============================================================
   PIPELINE STAGES DATA
   ============================================================ */
const PIPELINE_STAGES = [
  {
    stage: "STAGE 01",
    label: "DISCOVERY",
    icon: <Zap size={14} />,
    title: "LAN & Perimeter Ingestion",
    desc: "Edge agent performs non-intrusive ARP polling, passive DNS observation, and live LAN device detection across subnet ranges.",
    accent: "#ea580c",
    gradient: "linear-gradient(90deg, #ea580c, #f97316)",
    meta: "RFC1918 Private Gate",
    visual: (
      <div className="hml-card-visual-box">
        <div className="hml-visual-header">
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#4ade80", boxShadow: "0 0 8px #4ade80" }} />
            <span style={{ color: "#fb923c", fontWeight: 700, letterSpacing: "0.05em" }}>SUBNET 192.168.1.0/24</span>
          </div>
          <span className="hml-pulse-tag">● 14 LIVE HOSTS</span>
        </div>
        <div className="hml-visual-list">
          <div className="hml-visual-row">
            <span style={{ display: "flex", alignItems: "center", gap: "6px", color: "#e2e8f0" }}>
              <Server size={12} color="#38c6f4" />
              <span>192.168.1.1 (Gateway)</span>
            </span>
            <span className="hml-tag-cyan">PORT 22, 443</span>
          </div>
          <div className="hml-visual-row">
            <span style={{ display: "flex", alignItems: "center", gap: "6px", color: "#e2e8f0" }}>
              <Server size={12} color="#fb7185" />
              <span>192.168.1.10 (Nginx DMZ)</span>
            </span>
            <span className="hml-tag-rose">CVE-2024-4321</span>
          </div>
        </div>
      </div>
    ),
  },
  {
    stage: "STAGE 02",
    label: "TOPOLOGY",
    icon: <Network size={14} />,
    title: "Directed Graph Construction",
    desc: "Translates isolated host scans into a unified mathematical attack topology with weighted edge traversal difficulties.",
    accent: "#38c6f4",
    gradient: "linear-gradient(90deg, #38c6f4, #0284c7)",
    meta: "NetworkX DiGraph",
    visual: (
      <div className="hml-card-visual-box" style={{ background: "#0c0f14" }}>
        <div className="hml-graph-pipeline">
          <div className="hml-node-pill" style={{ borderColor: "rgba(244,63,94,0.3)", background: "rgba(244,63,94,0.1)" }}>
            <div style={{ fontSize: 9, color: "#fb7185", fontFamily: "var(--font-family-mono)", fontWeight: 700 }}>SOURCE</div>
            <span style={{ color: "#ffffff", fontSize: 11, fontWeight: 700, fontFamily: "var(--font-family-mono)" }}>INTERNET</span>
          </div>
          <div className="hml-node-arrow">
            <div className="hml-arrow-line" />
            <span className="hml-arrow-label">HTTPS 443</span>
          </div>
          <div className="hml-node-pill" style={{ borderColor: "rgba(56,198,244,0.3)", background: "rgba(56,198,244,0.1)" }}>
            <div style={{ fontSize: 9, color: "#38c6f4", fontFamily: "var(--font-family-mono)", fontWeight: 700 }}>DMZ NODE</div>
            <span style={{ color: "#ffffff", fontSize: 11, fontWeight: 700, fontFamily: "var(--font-family-mono)" }}>web-lb-01</span>
          </div>
          <div className="hml-node-arrow">
            <div className="hml-arrow-line" />
            <span className="hml-arrow-label">PORT 5432</span>
          </div>
          <div className="hml-node-pill" style={{ borderColor: "rgba(234,88,12,0.5)", background: "rgba(234,88,12,0.15)", boxShadow: "0 0 12px rgba(234,88,12,0.3)" }}>
            <div style={{ fontSize: 9, color: "#fb923c", fontFamily: "var(--font-family-mono)", fontWeight: 700 }}>👑 CROWN</div>
            <span style={{ color: "#fed7aa", fontSize: 11, fontWeight: 700, fontFamily: "var(--font-family-mono)" }}>db-prod-01</span>
          </div>
        </div>
      </div>
    ),
  },
  {
    stage: "STAGE 03",
    label: "SOLVER",
    icon: <Cpu size={14} />,
    title: "Bounded Yen's Path Solver",
    desc: "Enumerates the top 5 shortest attack routes per crown jewel (bounded at max 6 hops), avoiding exponential traversal explosion.",
    accent: "#d97706",
    gradient: "linear-gradient(90deg, #d97706, #f59e0b)",
    meta: "Bounded Yen's K-Shortest",
    visual: (
      <div className="hml-card-visual-box">
        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 11, fontFamily: "var(--font-family-mono)", marginBottom: 4 }}>
              <span style={{ color: "#fb7185", fontWeight: 700, display: "flex", alignItems: "center", gap: 4 }}>
                <Shield size={11} /> #1 Primary Path (88.0%)
              </span>
              <span style={{ color: "#94a3b8" }}>3 Hops · CVSS 9.8</span>
            </div>
            <div style={{ height: 6, width: "100%", background: "#1e293b", borderRadius: 999, overflow: "hidden" }}>
              <div style={{ height: "100%", width: "88%", background: "linear-gradient(90deg, #fb7185, #f97316)", borderRadius: 999 }} />
            </div>
          </div>
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 11, fontFamily: "var(--font-family-mono)", marginBottom: 4 }}>
              <span style={{ color: "#fb923c", fontWeight: 700, display: "flex", alignItems: "center", gap: 4 }}>
                <Activity size={11} /> #2 Lateral Path (41.0%)
              </span>
              <span style={{ color: "#94a3b8" }}>4 Hops · CVSS 7.5</span>
            </div>
            <div style={{ height: 6, width: "100%", background: "#1e293b", borderRadius: 999, overflow: "hidden" }}>
              <div style={{ height: "100%", width: "41%", background: "linear-gradient(90deg, #f97316, #fbbf24)", borderRadius: 999 }} />
            </div>
          </div>
        </div>
      </div>
    ),
  },
  {
    stage: "STAGE 04",
    label: "VALUATION",
    icon: <DollarSign size={14} />,
    title: "Deterministic $ Valuation",
    desc: "Applies mathematical risk pricing: Likelihood × Asset Value × Multiplier + Base Cost. Zero fabricated numbers.",
    accent: "#15803d",
    gradient: "linear-gradient(90deg, #15803d, #22c55e)",
    meta: "Deterministic ($ USD)",
    visual: (
      <div className="hml-card-visual-box" style={{ background: "rgba(225, 29, 72, 0.06)", borderColor: "rgba(225, 29, 72, 0.2)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <div style={{ fontSize: 10, fontFamily: "var(--font-family-mono)", color: "#f43f5e", fontWeight: 700, letterSpacing: "0.08em" }}>CALCULATED EXPOSURE</div>
            <div style={{ fontSize: 24, fontWeight: 800, color: "#f43f5e", fontFamily: "var(--font-family-mono)", lineHeight: 1.2 }}>$902,900</div>
          </div>
          <div style={{ textAlign: "right", fontSize: 11, fontFamily: "var(--font-family-mono)", color: "#94a3b8", borderLeft: "1px solid rgba(255,255,255,0.1)", paddingLeft: 12 }}>
            <div style={{ color: "#e2e8f0", fontWeight: 600 }}>0.88 × $500K DB</div>
            <div style={{ color: "#64748b" }}>+ $462.9K Blast</div>
          </div>
        </div>
      </div>
    ),
  },
  {
    stage: "STAGE 05",
    label: "REMEDIATION",
    icon: <Terminal size={14} />,
    title: "Defensive Playbook Synthesis",
    desc: "Synthesizes contextual Ansible, Shell, and AWS CLI remediations with strict output-side offensive marker screening.",
    accent: "#7c3aed",
    gradient: "linear-gradient(90deg, #7c3aed, #a855f7)",
    meta: "NVIDIA NIM Guardrails",
    visual: (
      <div className="hml-card-visual-box">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid rgba(255,255,255,0.08)", paddingBottom: 6, marginBottom: 8 }}>
          <span style={{ display: "flex", alignItems: "center", gap: 6, color: "#4ade80", fontWeight: 700, fontSize: 11, fontFamily: "var(--font-family-mono)" }}>
            <CheckCircle2 size={12} /> PLAYBOOK VERIFIED
          </span>
          <span style={{ fontSize: 10, fontFamily: "var(--font-family-mono)", color: "#94a3b8" }}>ansible-playbook</span>
        </div>
        <div style={{ fontFamily: "var(--font-family-mono)", fontSize: 11, color: "#cbd5e1", lineHeight: 1.5 }}>
          <span style={{ color: "#c084fc" }}>- name:</span> Patch CVE & Harden DMZ<br />
          <span style={{ color: "#38bdf8" }}>  ansible.builtin.iptables:</span> drop
        </div>
      </div>
    ),
  },
];

/* ============================================================
   MAIN LANDING PAGE
   ============================================================ */
export default function Landing() {
  const { user } = useAuth();
  const [replayKey, setReplayKey] = useState(0);
  const { scrollYProgress } = useScroll();
  const scaleX = useSpring(scrollYProgress, {
    stiffness: 120,
    damping: 24,
    restDelta: 0.001,
  });

  if (user) return <Navigate to="/app" replace />;

  return (
    <EntryAnimation key={replayKey} forcePlay={replayKey > 0}>
      <div className="hml">
        {/* Scroll Progress Bar */}
        <motion.div className="hml-scroll-progress-bar" style={{ scaleX }} />

        {/* Master Full-Bleed Dark Hero Section */}
        <div className="hml-hero-master-wrap">
          <HeroBackdrop scrollYProgress={scrollYProgress} />
          <TopStatusStrip onReplay={() => setReplayKey((k) => k + 1)} />
          <Navbar />
          <HeroContent />
        </div>

        <main>
          {/* Interactive Multi-Hop Attack Path Simulator */}
          <InteractivePathSection />

          {/* Scroll-Driven Horizontal Threat Pipeline */}
          <ScrollDrivenHorizontalPipeline />

          {/* Six Architectural Pillars */}
          <PillarsSection />

          {/* Competitive Benchmark Comparison */}
          <ComparisonSection />

          {/* Defensive Playbook Terminal Showcase */}
          <PlaybookTerminalSection />

          {/* Frequently Asked Questions */}
          <FaqSection />

          {/* Final Call to Action */}
          <CtaBandSection />
        </main>

        <FooterSection />
      </div>
    </EntryAnimation>
  );
}

/* ------------------------------------------------------------- Top Status Strip */
function TopStatusStrip({ onReplay }: { onReplay?: () => void }) {
  const [time, setTime] = useState(() =>
    new Date().toLocaleTimeString("en-IN", {
      timeZone: "Asia/Kolkata",
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    })
  );

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(
        new Date().toLocaleTimeString("en-IN", {
          timeZone: "Asia/Kolkata",
          hour12: false,
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        })
      );
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="hml-strip">
      <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
        <span>
          DRISHTI <em>//</em> DEFENSIVE GRAPH INTELLIGENCE
        </span>
        <span style={{ opacity: 0.35 }}>|</span>
        <span>ENGINE: NETWORKX 3.3 (BOUNDED YEN&apos;S K-SHORTEST)</span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "1.25rem" }}>
        {onReplay && (
          <button
            onClick={onReplay}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
              padding: "2px 8px",
              fontSize: "11px",
              fontFamily: "var(--font-family-mono)",
              fontWeight: 700,
              color: "var(--color-accent)",
              background: "rgba(234, 88, 12, 0.12)",
              border: "1px solid rgba(234, 88, 12, 0.3)",
              borderRadius: "4px",
              cursor: "pointer",
            }}
          >
            <Activity size={10} /> REPLAY SCAN
          </button>
        )}
        <span>
          STATUS:{" "}
          <span style={{ color: "#4ade80", fontWeight: 700 }}>OPERATIONAL</span>
        </span>
        <span className="mono">IST: {time} (KOLKATA)</span>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------- Navigation Bar */
function Navbar() {
  return (
    <header className="hml-nav">
      <div className="hml-nav-inner">
        <Link to="/" className="hml-brand">
          <motion.div
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            style={{
              width: 32,
              height: 32,
              borderRadius: 8,
              background: "var(--color-accent)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: "0 2px 14px rgba(234, 88, 12, 0.45)",
            }}
          >
            <Shield size={18} color="#ffffff" />
          </motion.div>
          <span>
            DR<em>I</em>SHTI
          </span>
        </Link>

        <nav>
          <ul className="hml-nav-links">
            <li>
              <a href="#topology" className="hml-nav-link">
                Attack Topology
              </a>
            </li>
            <li>
              <a href="#pipeline" className="hml-nav-link">
                Threat Pipeline
              </a>
            </li>
            <li>
              <a href="#pillars" className="hml-nav-link">
                Architecture
              </a>
            </li>
            <li>
              <a href="#comparison" className="hml-nav-link">
                Comparison
              </a>
            </li>
            <li>
              <a href="#playbooks" className="hml-nav-link">
                Playbooks
              </a>
            </li>
            <li>
              <a href="#faq" className="hml-nav-link">
                FAQ
              </a>
            </li>
          </ul>
        </nav>

        <div className="hml-nav-actions">
          <Link to="/login" className="hml-btn-ghost">
            Sign In
          </Link>
          <Link to="/signup" className="hml-btn-primary">
            Launch Console <ArrowRight size={14} />
          </Link>
        </div>
      </div>
    </header>
  );
}

/* ------------------------------------------------------------- Hero Backdrop */
function HeroBackdrop({ scrollYProgress }: { scrollYProgress: any }) {
  const heroBgY = useTransform(scrollYProgress, [0, 0.4], [0, 80]);

  return (
    <div className="hml-hero-bg-backdrop">
      <motion.img
        src={heroBg}
        alt="Drishti Intelligence Topology Backdrop"
        className="hml-hero-bg-img"
        style={{ y: heroBgY }}
      />
      <div className="hml-hero-bg-overlay" />
    </div>
  );
}

/* ------------------------------------------------------------- Hero Content */
function HeroContent() {
  return (
    <section className="hml-hero hml-wrap">
      <motion.div
        initial={{ opacity: 0, y: 15 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.1 }}
        className="hml-pill-tag"
      >
        <span className="hml-pill-dot" />
        <span>Defensive Attack-Path Intelligence</span>
        <span style={{ color: "rgba(255, 255, 255, 0.35)" }}>|</span>
        <span style={{ color: "var(--color-accent)", fontWeight: 700 }}>
          Zero-Hallucination Impact
        </span>
      </motion.div>

      <motion.h1
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.2 }}
        className="hml-hero-title text-white"
        style={{ color: "#ffffff" }}
      >
        See Your Network Through the Eyes of an Attacker.
      </motion.h1>

      <motion.p
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.3 }}
        className="hml-hero-desc text-slate-200"
        style={{ color: "#e2e8f0" }}
      >
        Drishti maps real routes from the internet to your crown-jewel assets,
        prices every path in <span style={{ color: "#fb923c", fontWeight: 700 }}>$ dollars</span>,
        and synthesizes human-reviewed Ansible playbooks. Never attacks.
      </motion.p>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.4 }}
        className="hml-hero-cta"
      >
        <motion.div whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
          <Link to="/signup" className="hml-btn-accent">
            Launch Interactive Console <ArrowRight size={16} />
          </Link>
        </motion.div>
        <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
          <a href="#pipeline" className="hml-btn-outline">
            Explore Threat Pipeline
          </a>
        </motion.div>
      </motion.div>
    </section>
  );
}

/* ------------------------------------------------------------- Interactive Path Simulator */
function InteractivePathSection() {
  const [selectedPath, setSelectedPath] = useState(1);
  const [remediated, setRemediated] = useState(false);

  const paths = [
    {
      id: 1,
      name: "Path #1",
      subtitle: "Foothold to Main DB",
      target: "PostgreSQL Database (10.0.0.5)",
      hops: [
        { label: "Entry Point", name: "INTERNET", ip: "0.0.0.0", type: "entry" },
        { label: "Hop 01", name: "Edge Firewall", ip: "192.168.1.1", type: "fw" },
        { label: "Hop 02", name: "Web Server", ip: "192.168.1.10", type: "srv" },
        { label: "Crown Jewel", name: "PostgreSQL DB", ip: "10.0.0.5", type: "target" },
      ],
      vuln: "CVE-2024-4321 (RCE on DMZ Web Node)",
      likelihood: remediated ? 0.04 : 0.88,
      exposure: remediated ? 50000 : 902900,
      riskScore: remediated ? 12.4 : 88.0,
    },
    {
      id: 2,
      name: "Path #2",
      subtitle: "Lateral Admin Pivot",
      target: "Domain Controller (10.0.0.2)",
      hops: [
        { label: "Entry Point", name: "INTERNET", ip: "0.0.0.0", type: "entry" },
        { label: "Hop 01", name: "VPN Gateway", ip: "192.168.1.5", type: "fw" },
        { label: "Hop 02", name: "Admin Workstation", ip: "192.168.1.45", type: "srv" },
        { label: "Crown Jewel", name: "Active Directory DC", ip: "10.0.0.2", type: "target" },
      ],
      vuln: "Weak VPN Credential Spraying + Kerberoasting",
      likelihood: remediated ? 0.02 : 0.41,
      exposure: remediated ? 30000 : 420000,
      riskScore: remediated ? 8.1 : 54.5,
    },
  ];

  const current = paths.find((p) => p.id === selectedPath) || paths[0];

  return (
    <section id="topology" className="hml-section hml-wrap">
      <div className="hml-section-header">
        <span className="hml-section-tag">Interactive Topology Intelligence</span>
        <h2 className="hml-section-title">Multi-Hop Attack Path Simulator</h2>
        <p className="hml-section-desc">
          Test Yen&apos;s K-shortest path algorithm live. Select a computed route, inspect intermediate hops, and simulate automated remediation.
        </p>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.6 }}
        style={{
          background: "var(--color-surface-raised)",
          border: "1px solid var(--color-border-default)",
          borderRadius: "var(--radius-card)",
          padding: "clamp(1.5rem, 3vw, 2.5rem)",
          boxShadow: "var(--shadow-lift)",
        }}
      >
        {/* Top Controls */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "1rem",
            marginBottom: "2rem",
            paddingBottom: "1.25rem",
            borderBottom: "1px solid var(--color-border-subtle)",
          }}
        >
          <div style={{ display: "flex", gap: "0.75rem" }}>
            {paths.map((p) => (
              <button
                key={p.id}
                onClick={() => {
                  setSelectedPath(p.id);
                  setRemediated(false);
                }}
                style={{
                  padding: "0.6rem 1.25rem",
                  borderRadius: "var(--radius-pill)",
                  border: `1px solid ${selectedPath === p.id ? "var(--color-accent)" : "var(--color-border-default)"}`,
                  background: selectedPath === p.id ? "var(--color-accent)" : "var(--color-surface-base)",
                  color: selectedPath === p.id ? "#ffffff" : "var(--color-text-primary)",
                  fontWeight: 700,
                  fontSize: "0.85rem",
                  cursor: "pointer",
                  transition: "all 0.2s ease",
                }}
              >
                {p.name}: {p.subtitle}
              </button>
            ))}
          </div>

          <button
            onClick={() => setRemediated(!remediated)}
            style={{
              padding: "0.6rem 1.25rem",
              borderRadius: "var(--radius-pill)",
              border: `1px solid ${remediated ? "#16a34a" : "var(--color-accent)"}`,
              background: remediated ? "#15803d" : "rgba(234, 88, 12, 0.1)",
              color: remediated ? "#ffffff" : "var(--color-accent)",
              fontWeight: 700,
              fontSize: "0.85rem",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
            }}
          >
            {remediated ? (
              <>
                <CheckCircle2 size={16} /> Patch Applied (-$200,000 Drop)
              </>
            ) : (
              <>
                <Shield size={16} /> Simulate Defensive Remediation
              </>
            )}
          </button>
        </div>

        {/* Hops Chain Visualization */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "1rem" }}>
          {current.hops.map((hop, index) => (
            <React.Fragment key={hop.name}>
              <motion.div
                whileHover={{ y: -4 }}
                style={{
                  display: "flex",
                  flexDirection: "column",
                  padding: "1rem 1.25rem",
                  background: hop.type === "entry" ? "#fff5f5" : hop.type === "target" ? "#fff8f5" : "#ffffff",
                  border: `1px solid ${hop.type === "entry" ? "rgba(225, 29, 72, 0.3)" : hop.type === "target" ? "rgba(234, 88, 12, 0.4)" : "rgba(23, 25, 22, 0.1)"}`,
                  borderRadius: "10px",
                  minWidth: "155px",
                  boxShadow: "0 2px 8px rgba(23, 25, 22, 0.04)",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.35rem" }}>
                  <span style={{ fontSize: "0.65rem", fontFamily: "var(--font-family-mono)", fontWeight: 700, textTransform: "uppercase", color: hop.type === "entry" ? "#e11d48" : hop.type === "target" ? "#ea580c" : "#555951" }}>
                    {hop.label}
                  </span>
                  <span style={{ fontSize: "0.65rem", fontFamily: "var(--font-family-mono)", color: "#8b8f87" }}>
                    {hop.ip}
                  </span>
                </div>
                <span style={{ fontSize: "0.95rem", fontWeight: 800, color: "#171916" }}>
                  {hop.name}
                </span>
              </motion.div>
              {index < current.hops.length - 1 && (
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", paddingInline: "0.25rem" }}>
                  <ArrowRight size={18} color="var(--color-accent)" />
                </div>
              )}
            </React.Fragment>
          ))}
        </div>

        {/* Metrics Grid */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "1.25rem", marginTop: "2rem", paddingTop: "1.5rem", borderTop: "1px solid var(--color-border-subtle)" }}>
          <div style={{ padding: "1rem", background: "var(--color-surface-base)", borderRadius: "8px", border: "1px solid rgba(23, 25, 22, 0.06)" }}>
            <div style={{ fontSize: "0.75rem", fontFamily: "var(--font-family-mono)", color: "#555951", textTransform: "uppercase", fontWeight: 700, marginBottom: "0.25rem" }}>
              Exploited Vulnerability
            </div>
            <div style={{ color: "#171916", fontWeight: 800, fontSize: "0.95rem" }}>{current.vuln}</div>
          </div>
          <div style={{ padding: "1rem", background: "var(--color-surface-base)", borderRadius: "8px", border: "1px solid rgba(23, 25, 22, 0.06)" }}>
            <div style={{ fontSize: "0.75rem", fontFamily: "var(--font-family-mono)", color: "#555951", textTransform: "uppercase", fontWeight: 700, marginBottom: "0.25rem" }}>
              Traversal Likelihood
            </div>
            <div style={{ color: remediated ? "#15803d" : "#ea580c", fontWeight: 800, fontSize: "1.35rem" }}>
              {(current.likelihood * 100).toFixed(1)}%
            </div>
          </div>
          <div style={{ padding: "1rem", background: "var(--color-surface-base)", borderRadius: "8px", border: "1px solid rgba(23, 25, 22, 0.06)" }}>
            <div style={{ fontSize: "0.75rem", fontFamily: "var(--font-family-mono)", color: "#555951", textTransform: "uppercase", fontWeight: 700, marginBottom: "0.25rem" }}>
              Total Financial Impact
            </div>
            <div style={{ color: remediated ? "#15803d" : "#e11d48", fontWeight: 800, fontSize: "1.35rem" }}>
              ${current.exposure.toLocaleString()}
            </div>
          </div>
          <div style={{ padding: "1rem", background: "var(--color-surface-base)", borderRadius: "8px", border: "1px solid rgba(23, 25, 22, 0.06)" }}>
            <div style={{ fontSize: "0.75rem", fontFamily: "var(--font-family-mono)", color: "#555951", textTransform: "uppercase", fontWeight: 700, marginBottom: "0.25rem" }}>
              Composite Path Risk
            </div>
            <div style={{ color: remediated ? "#15803d" : "#e11d48", fontWeight: 800, fontSize: "1.35rem" }}>
              {current.riskScore.toFixed(1)} / 100
            </div>
          </div>
        </div>
      </motion.div>
    </section>
  );
}

/* ------------------------------------------------------------- Scroll-Driven Horizontal Pipeline */
function ScrollDrivenHorizontalPipeline() {
  const containerRef = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ["start start", "end end"],
  });

  // Smooth horizontal scrub from 0% to -64%
  const x = useTransform(scrollYProgress, [0, 1], ["0%", "-64%"]);
  const progressPercent = useTransform(scrollYProgress, [0, 1], ["0%", "100%"]);

  return (
    <div id="pipeline" ref={containerRef} className="hml-horizontal-scroll-section">
      <div className="hml-horizontal-sticky">
        <div className="hml-wrap" style={{ marginBottom: "2rem", paddingTop: "0.5rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", flexWrap: "wrap", gap: "1.25rem" }}>
            <div>
              <div className="hml-section-tag" style={{ marginBottom: "0.4rem" }}>
                Continuous Defensive Engine
              </div>
              <h2 style={{ fontSize: "clamp(2rem, 3.2vw, 2.75rem)", fontWeight: 800, color: "#171916", margin: 0, letterSpacing: "-0.03em" }}>
                End-to-End Threat Pipeline
              </h2>
            </div>

            {/* Scroll-Linked Progress Pill */}
            <div style={{ display: "flex", alignItems: "center", gap: "0.85rem", background: "#ffffff", padding: "0.6rem 1.35rem", borderRadius: "var(--radius-pill)", border: "1px solid rgba(23, 25, 22, 0.12)", boxShadow: "0 4px 12px rgba(0, 0, 0, 0.05)" }}>
              <span style={{ fontSize: "0.75rem", fontFamily: "var(--font-family-primary)", color: "#555951", fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase" }}>
                Pipeline Progress
              </span>
              <div style={{ width: "90px", height: "6px", background: "#eae5dc", borderRadius: "999px", overflow: "hidden" }}>
                <motion.div style={{ width: progressPercent, height: "100%", background: "var(--color-accent)" }} />
              </div>
            </div>
          </div>
        </div>

        {/* Horizontally Scrubbed Track with Cards */}
        <motion.div style={{ x }} className="hml-horizontal-track">
          {PIPELINE_STAGES.map((stage) => (
            <motion.div
              key={stage.stage}
              whileHover={{ y: -8, scale: 1.01 }}
              transition={{ duration: 0.25 }}
              className="hml-pipeline-card"
            >
              <div className="hml-card-accent-line" style={{ background: stage.gradient }} />
              <div>
                <div className="hml-card-top-meta">
                  <span
                    className="hml-stage-chip"
                    style={{
                      color: stage.accent,
                      background: `${stage.accent}15`,
                      borderColor: `${stage.accent}35`,
                    }}
                  >
                    {stage.icon} {stage.stage} // {stage.label}
                  </span>
                  <span className="hml-meta-badge">{stage.meta}</span>
                </div>
                <h3 className="hml-card-heading">{stage.title}</h3>
                <p className="hml-card-body">{stage.desc}</p>
              </div>
              {stage.visual}
            </motion.div>
          ))}
        </motion.div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------- Six Architectural Pillars */
function PillarsSection() {
  const pillars = [
    {
      icon: <Network size={20} />,
      title: "Directed Graph Topology",
      body: "Constructs an in-memory NetworkX DiGraph capturing entry points, DMZs, firewalls, and internal trust relationships with weighted edge traversal models.",
      accent: "#38c6f4",
    },
    {
      icon: <Layers size={20} />,
      title: "Bounded Yen's Path Enumeration",
      body: "Enumerates up to 5 shortest paths per crown jewel (bounded at max 6 hops, top 25 globally), eliminating computational explosion.",
      accent: "#ea580c",
    },
    {
      icon: <DollarSign size={20} />,
      title: "Deterministic Impact ($ USD)",
      body: "Calculates real dollar risk using mathematical formulas based on asset value and breach base costs. AI never alters financial numbers.",
      accent: "#e11d48",
    },
    {
      icon: <Shield size={20} />,
      title: "Defensive-Only AI Guardrails",
      body: "Integrated with NVIDIA NIM (Llama 3.3 70B). Strict output-side marker scanning guarantees zero offensive exploit generation.",
      accent: "#7c3aed",
    },
    {
      icon: <Eye size={20} />,
      title: "Real-Time Telemetry Watch",
      body: "Edge agent detects LAN devices via ARP and flags MITRE ATT&CK threats (ARP spoofing, rogue hardware, risky ports).",
      accent: "#15803d",
    },
    {
      icon: <Lock size={20} />,
      title: "Zero-Latency Web Guard",
      body: "Manifest V3 Chrome extension enforces in-browser domain trust verdicts with a transparent two-part scoring algorithm.",
      accent: "#d97706",
    },
  ];

  return (
    <section id="pillars" className="hml-section hml-wrap">
      <div className="hml-section-header">
        <span className="hml-section-tag">System Architecture</span>
        <h2 className="hml-section-title">Six Pillars of Defensive Intelligence</h2>
        <p className="hml-section-desc">
          Built on mathematical rigor, graph theory, and cryptographically verified data boundaries.
        </p>
      </div>

      <div className="hml-grid-3">
        {pillars.map((p) => (
          <motion.div
            key={p.title}
            whileHover={{ y: -6 }}
            style={{
              padding: "2rem",
              background: "var(--color-surface-raised)",
              borderRadius: "var(--radius-card)",
              border: "1px solid var(--color-border-default)",
              boxShadow: "var(--shadow-sm)",
              display: "flex",
              flexDirection: "column",
            }}
          >
            <div
              style={{
                width: 44,
                height: 44,
                borderRadius: 10,
                background: `${p.accent}15`,
                border: `1px solid ${p.accent}35`,
                color: p.accent,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                marginBottom: "1.25rem",
              }}
            >
              {p.icon}
            </div>
            <h3 style={{ fontSize: "1.15rem", fontWeight: 800, color: "#171916", marginBottom: "0.5rem" }}>
              {p.title}
            </h3>
            <p style={{ fontSize: "0.9rem", color: "#555951", lineHeight: 1.6, margin: 0 }}>
              {p.body}
            </p>
          </motion.div>
        ))}
      </div>
    </section>
  );
}

/* ------------------------------------------------------------- Comparison Section */
function ComparisonSection() {
  const rows = [
    {
      dim: "Attack Surface Representation",
      legacy: "Flat, disconnected list of CVEs without topology context",
      drishti: "Directed topological graph with multi-hop lateral movement chains",
    },
    {
      dim: "Prioritization Logic",
      legacy: "Raw CVSS score (treats isolated servers and crown jewels equally)",
      drishti: "Graph centrality + reachable distance + deterministic crown jewel value",
    },
    {
      dim: "Risk Quantification",
      legacy: "Abstract high/medium/low severity badges without financial meaning",
      drishti: "Deterministic dollar exposure ($ USD) board-ready metric",
    },
    {
      dim: "AI Integration Safety",
      legacy: "Unconstrained prompts prone to hallucinations and unverified actions",
      drishti: "Output-side offensive marker scanning with defensive-only verification",
    },
    {
      dim: "Scan Scope & Compliance",
      legacy: "Blind automated port probing across arbitrary subnets",
      drishti: "Strict RFC1918 private scope gate with explicit consent validation",
    },
  ];

  return (
    <section id="comparison" className="hml-section hml-wrap">
      <div className="hml-section-header">
        <span className="hml-section-tag">Competitive Benchmark</span>
        <h2 className="hml-section-title">Legacy Scanners vs. Drishti</h2>
        <p className="hml-section-desc">
          Why traditional vulnerability assessment fails in modern enterprise topologies.
        </p>
      </div>

      <div
        style={{
          borderRadius: "var(--radius-card)",
          border: "1px solid var(--color-border-default)",
          background: "var(--color-surface-raised)",
          overflow: "hidden",
          boxShadow: "var(--shadow-lift)",
        }}
      >
        <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1.4fr 1.4fr", background: "var(--color-surface-base)", padding: "1.25rem 1.75rem", borderBottom: "1px solid var(--color-border-default)", fontWeight: 800, fontSize: "0.85rem", color: "#171916" }}>
          <div>DIMENSION</div>
          <div style={{ color: "#e11d48" }}>LEGACY SCANNER</div>
          <div style={{ color: "var(--color-accent)" }}>DRISHTI PLATFORM</div>
        </div>
        {rows.map((r, i) => (
          <div
            key={r.dim}
            style={{
              display: "grid",
              gridTemplateColumns: "1.2fr 1.4fr 1.4fr",
              padding: "1.25rem 1.75rem",
              borderBottom: i < rows.length - 1 ? "1px solid var(--color-border-subtle)" : "none",
              fontSize: "0.9rem",
              alignItems: "center",
              gap: "1rem",
            }}
          >
            <div style={{ fontWeight: 700, color: "#171916" }}>{r.dim}</div>
            <div style={{ color: "#8b8f87", lineHeight: 1.5 }}>&times; {r.legacy}</div>
            <div style={{ color: "#171916", fontWeight: 600, lineHeight: 1.5, display: "flex", alignItems: "flex-start", gap: "6px" }}>
              <span style={{ color: "#15803d", fontWeight: 800 }}>&check;</span>
              <span>{r.drishti}</span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

/* ------------------------------------------------------------- Playbook Terminal */
function PlaybookTerminalSection() {
  const [activeTab, setActiveTab] = useState<"ansible" | "shell" | "aws">("ansible");

  const playbooks = {
    ansible: `---
- name: Remediate Attack Vector (Hop 02 DMZ to Crown DB)
  hosts: dmz_web_servers
  become: true
  tasks:
    - name: Patch CVE-2024-4321 Vulnerable Dependency
      ansible.builtin.apt:
        name: libnginx-mod-http-auth
        state: latest
        update_cache: yes

    - name: Restrict PostgreSQL Egress to Explicit DB Subnet
      ansible.builtin.iptables:
        chain: OUTPUT
        destination: 10.0.0.5
        protocol: tcp
        destination_port: 5432
        jump: ACCEPT
        comment: "Drishti Defensive Guardrail Policy"

    - name: Drop All Other Lateral Pivoting Ports
      ansible.builtin.iptables:
        chain: OUTPUT
        destination: 10.0.0.0/24
        jump: DROP`,
    shell: `#!/usr/bin/env bash
# Drishti Automated Defensive Isolation Script
# Target: 192.168.1.10 (Compromised Web Node)

set -euo pipefail

echo "[*] Applying host firewall isolation rules..."
iptables -A OUTPUT -p tcp --dport 5432 -d 10.0.0.5 -j ACCEPT
iptables -A OUTPUT -d 10.0.0.0/24 -j DROP

echo "[*] Restarting hardened service daemon..."
systemctl restart nginx.service

echo "[+] Remediation verified. Path likelihood reduced to 0.04."`,
    aws: `# AWS Security Group Hardening Rule via AWS CLI
aws ec2 revoke-security-group-ingress \\
    --group-id sg-0123456789abcdef0 \\
    --protocol tcp \\
    --port 5432 \\
    --cidr 192.168.1.0/24

aws ec2 authorize-security-group-ingress \\
    --group-id sg-0123456789abcdef0 \\
    --protocol tcp \\
    --port 5432 \\
    --source-group sg-0fedcba9876543210 \\
    --description "Drishti Enforced Least-Privilege DB Access"`,
  };

  return (
    <section id="playbooks" className="hml-section hml-wrap">
      <div className="hml-section-header">
        <span className="hml-section-tag">Zero-Exploit Synthesis</span>
        <h2 className="hml-section-title">Automated Defensive Playbooks</h2>
        <p className="hml-section-desc">
          Generate hardened configuration scripts ready for deployment. Every playbook is scanned to ensure it contains only defensive remediation commands.
        </p>
      </div>

      <div
        style={{
          borderRadius: "var(--radius-card)",
          background: "#0f110e",
          border: "1px solid rgba(255, 255, 255, 0.12)",
          overflow: "hidden",
          boxShadow: "0 25px 60px -15px rgba(0, 0, 0, 0.5)",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "0.85rem 1.25rem",
            background: "rgba(255, 255, 255, 0.04)",
            borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
          }}
        >
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#ef4444" }} />
            <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#f59e0b" }} />
            <span style={{ width: 11, height: 11, borderRadius: "50%", background: "#22c55e" }} />
          </div>

          <div style={{ display: "flex", gap: "0.5rem" }}>
            {(["ansible", "shell", "aws"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                style={{
                  padding: "0.35rem 0.85rem",
                  borderRadius: "6px",
                  border: `1px solid ${activeTab === tab ? "var(--color-accent)" : "transparent"}`,
                  background: activeTab === tab ? "rgba(234, 88, 12, 0.15)" : "transparent",
                  color: activeTab === tab ? "#fb923c" : "#8b8f87",
                  fontFamily: "var(--font-family-mono)",
                  fontSize: "0.75rem",
                  fontWeight: 700,
                  cursor: "pointer",
                  textTransform: "uppercase",
                }}
              >
                {tab === "ansible" ? "Ansible YAML" : tab === "shell" ? "Bash Script" : "AWS CLI"}
              </button>
            ))}
          </div>

          <span style={{ fontSize: "0.75rem", color: "#4ade80", fontFamily: "var(--font-family-mono)", fontWeight: 700 }}>
            &bull; SCANNER: DEFENSIVE PASS
          </span>
        </div>

        <pre
          style={{
            margin: 0,
            padding: "1.5rem",
            color: "#f2efe7",
            fontFamily: "var(--font-family-mono)",
            fontSize: "0.85rem",
            lineHeight: 1.6,
            overflowX: "auto",
          }}
        >
          <code>{playbooks[activeTab]}</code>
        </pre>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------- Frequently Asked Questions */
function FaqSection() {
  const [openIdx, setOpenIdx] = useState<number | null>(0);

  const faqs = [
    {
      q: "How does Drishti avoid hallucinating breach impact numbers?",
      badge: "DETERMINISTIC FORMULAS",
      a: "Financial exposure is computed using fixed mathematical formulas: Likelihood × Asset Valuation × Multiplier + Base Cost. The AI model only generates human-readable descriptions and code remediations — it is never permitted to calculate or alter risk metrics.",
    },
    {
      q: "Does Drishti ever execute active offensive exploits?",
      badge: "DEFENSIVE ONLY",
      a: "Never. Drishti operates under a strict defensive posture. All synthesized code passes through an output-side scanner that blocks metasploit modules, reverse shells, and exploit payloads. Only defensive configurations and patches are produced.",
    },
    {
      q: "Can Drishti scan public internet IP addresses without authorization?",
      badge: "SCOPE ENFORCEMENT",
      a: "No. Drishti enforces strict RFC1918 private address validation and requires explicit tenant authorization. Scanning unauthorized public internet subnets is hard-blocked at the agent network layer.",
    },
    {
      q: "Which database backends are supported for graph state storage?",
      badge: "STORAGE ARCHITECTURE",
      a: "Drishti supports PostgreSQL with transactional advisory locks for enterprise multi-user deployments, as well as SQLite (AIOSQLite Async) for local edge testing. All graph entities use 36-character UUIDs for full portability.",
    },
  ];

  return (
    <section id="faq" className="hml-section hml-wrap">
      <div className="hml-section-header">
        <span className="hml-section-tag">Verification & Trust</span>
        <h2 className="hml-section-title">Frequently Asked Questions</h2>
        <p className="hml-section-desc">
          Everything you need to know about Drishti&apos;s mathematical models, safety guardrails, and architecture.
        </p>
      </div>

      <div style={{ maxWidth: "48rem", marginInline: "auto", display: "flex", flexDirection: "column", gap: "1rem" }}>
        {faqs.map((faq, i) => {
          const isOpen = openIdx === i;
          return (
            <div
              key={faq.q}
              style={{
                borderRadius: "var(--radius-card)",
                border: "1px solid var(--color-border-default)",
                background: "var(--color-surface-raised)",
                overflow: "hidden",
                boxShadow: "var(--shadow-sm)",
              }}
            >
              <button
                onClick={() => setOpenIdx(isOpen ? null : i)}
                style={{
                  width: "100%",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "1.25rem 1.5rem",
                  background: "transparent",
                  border: "none",
                  textAlign: "left",
                  cursor: "pointer",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                  <span style={{ fontSize: "0.7rem", fontFamily: "var(--font-family-mono)", color: "var(--color-accent)", fontWeight: 700, padding: "0.2rem 0.5rem", background: "rgba(234, 88, 12, 0.1)", borderRadius: "4px" }}>
                    {faq.badge}
                  </span>
                  <span style={{ fontSize: "1rem", fontWeight: 700, color: "#171916" }}>
                    {faq.q}
                  </span>
                </div>
                <motion.div animate={{ rotate: isOpen ? 180 : 0 }} transition={{ duration: 0.2 }}>
                  <ChevronDown size={18} color="#8b8f87" />
                </motion.div>
              </button>

              <AnimatePresence>
                {isOpen && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.25 }}
                  >
                    <div style={{ padding: "0 1.5rem 1.25rem", color: "#555951", fontSize: "0.92rem", lineHeight: 1.6, borderTop: "1px solid var(--color-border-subtle)", paddingTop: "0.85rem" }}>
                      {faq.a}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </div>
    </section>
  );
}

/* ------------------------------------------------------------- Call to Action Band */
function CtaBandSection() {
  return (
    <section style={{ padding: "clamp(4rem, 8vw, 6rem) 1.5rem", background: "var(--color-surface-dark)", textAlign: "center", position: "relative", overflow: "hidden" }}>
      <div style={{ maxWidth: "44rem", marginInline: "auto", position: "relative", zIndex: 2 }}>
        <h2 style={{ fontSize: "clamp(2rem, 3.5vw, 3rem)", fontWeight: 800, color: "#ffffff", letterSpacing: "-0.03em", marginBottom: "1rem" }}>
          Ready to Map Your Attack Surface?
        </h2>
        <p style={{ color: "#a1a59c", fontSize: "1.1rem", marginBottom: "2rem", lineHeight: 1.6 }}>
          Run your first graph-theoretic threat topology audit in under 60 seconds. Zero agent installations required for initial reconnaissance.
        </p>
        <div style={{ display: "flex", justifyContent: "center", gap: "1rem", flexWrap: "wrap" }}>
          <Link to="/signup" className="hml-btn-accent">
            Launch Interactive Console <ArrowRight size={16} />
          </Link>
          <a
            href="https://github.com/Subhadip-Paul2006/dhristi"
            target="_blank"
            rel="noreferrer"
            className="hml-btn-outline"
            style={{ borderColor: "rgba(255, 255, 255, 0.25)", color: "#ffffff" }}
          >
            Star on GitHub
          </a>
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------- Footer Section */
function FooterSection() {
  return (
    <footer style={{ padding: "2.5rem 1.5rem", background: "#0b0d0a", borderTop: "1px solid rgba(255, 255, 255, 0.08)", color: "#8b8f87", fontSize: "0.85rem", fontFamily: "var(--font-family-mono)" }}>
      <div className="hml-wrap" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <Shield size={16} color="var(--color-accent)" />
          <span style={{ fontWeight: 800, color: "#ffffff" }}>DRISHTI</span>
          <span>&copy; {new Date().getFullYear()} Innofusion. All rights reserved.</span>
        </div>
        <div style={{ display: "flex", gap: "1.5rem" }}>
          <a href="#topology" style={{ color: "#8b8f87", textDecoration: "none" }}>Topology</a>
          <a href="#pipeline" style={{ color: "#8b8f87", textDecoration: "none" }}>Pipeline</a>
          <a href="#playbooks" style={{ color: "#8b8f87", textDecoration: "none" }}>Playbooks</a>
          <a href="#faq" style={{ color: "#8b8f87", textDecoration: "none" }}>FAQ</a>
        </div>
      </div>
    </footer>
  );
}
