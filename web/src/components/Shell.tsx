// Drishti v0.1 — application shell with dark cyber SOC console nav | 11-Jul-2026
import clsx from "clsx";
import {
  Activity,
  LayoutDashboard,
  LinkIcon,
  LogOut,
  Menu,
  Network,
  Radio,
  Route,
  ScrollText,
  Settings,
  ShieldAlert,
  Server,
  Wrench,
  X,
  Terminal,
} from "lucide-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { AuroraBackground } from "./ui/AuroraBackground";
import { api, isDemoMode } from "../api/client";
import { useAuth } from "../auth";
import { useToast } from "../store/graphStore";
import { Button } from "./Button";

const NAV = [
  { to: "/app", label: "Dashboard", code: "01", icon: LayoutDashboard, end: true },
  { to: "/app/graph", label: "Attack Map", code: "02", icon: Network, end: false },
  { to: "/app/live", label: "Live Watch", code: "03", icon: Radio, end: false },
  { to: "/app/paths", label: "Paths", code: "04", icon: Route, end: false },
  { to: "/app/findings", label: "Findings", code: "05", icon: ShieldAlert, end: false },
  { to: "/app/assets", label: "Assets", code: "06", icon: Server, end: false },
  { to: "/app/report", label: "Report", code: "07", icon: ScrollText, end: false },
  { to: "/app/url-analyzer", label: "URL Analyzer", code: "08", icon: LinkIcon, end: false },
];

export function Shell({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);

  const recompute = useMutation({
    mutationFn: () => api.recompute(),
    onSuccess: () => {
      qc.invalidateQueries();
      toast.show("Risk model recomputed", "success");
    },
    onError: () => toast.show("Couldn't recompute — retry", "error"),
  });

  // Close mobile menu on route change
  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  const currentNav = NAV.find((item) =>
    item.end
      ? location.pathname === item.to
      : location.pathname.startsWith(item.to)
  );

  return (
    <div className="flex min-h-screen flex-col bg-canvas text-ink selection:bg-accent-500/25 selection:text-white">
      {/* Top Cyber Command Header */}
      <header className="relative z-30 flex h-14 shrink-0 items-center justify-between border-b border-hairline bg-surface-1/90 px-4 sm:px-6 backdrop-blur-md">
        <div className="flex items-center gap-3.5">
          {/* Mobile menu toggle */}
          <button
            type="button"
            onClick={() => setMobileOpen((o) => !o)}
            aria-label={mobileOpen ? "Close menu" : "Open menu"}
            aria-expanded={mobileOpen}
            className="flex h-8 w-8 items-center justify-center rounded border border-hairline bg-surface-2 text-ink-secondary transition-colors hover:border-accent-500/40 hover:text-accent-400 lg:hidden"
          >
            {mobileOpen ? (
              <X className="h-4 w-4 text-accent-400" />
            ) : (
              <Menu className="h-4 w-4" />
            )}
          </button>

          {/* Logo & Terminal Brand */}
          <NavLink to="/app" className="flex items-center gap-2.5 group">
            <div className="flex h-7 w-7 items-center justify-center rounded border border-accent-500/40 bg-accent-500/10 text-accent-400 shadow-[0_0_12px_rgba(0,255,102,0.25)] transition-all group-hover:shadow-[0_0_16px_rgba(0,255,102,0.4)]">
              <Activity className="h-4 w-4" />
            </div>
            <div className="flex items-baseline gap-2">
              <span className="font-display text-[18px] font-bold tracking-tight text-ink-primary">
                DRISHTI
              </span>
              <span className="hidden sm:inline font-mono text-[10px] tracking-wider uppercase text-accent-500/80">
                // SOC CONSOLE
              </span>
            </div>
          </NavLink>

          <span className="hidden text-hairline sm:inline">|</span>

          {/* Workspace org name */}
          <span className="hidden rounded border border-hairline bg-surface-2/60 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-ink-muted sm:inline">
            ORG: {user?.org_name || (isDemoMode() ? "ACME-RETAIL (DEMO)" : "LOCAL")}
          </span>

          {/* Breadcrumb current page tag */}
          {currentNav && (
            <div className="hidden items-center gap-1.5 pl-1 font-mono text-xs text-ink-muted md:flex">
              <span className="text-hairline">/</span>
              <span className="font-semibold text-accent-400">
                {currentNav.label}
              </span>
            </div>
          )}
        </div>

        {/* Top Header Telemetry + Quick Actions */}
        <div className="flex items-center gap-3">
          {/* Subtle demo badge compliant with requirements 8 & 20 */}
          {isDemoMode() && (
            <div className="flex items-center gap-1.5 rounded border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 font-mono text-[10px] font-semibold tracking-wider text-amber-400 shadow-[0_0_10px_rgba(245,158,11,0.15)]">
              <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" />
              <span>SIMULATED LAB // DEMO MODE</span>
            </div>
          )}

          {/* Real-time Telemetry Status Badges */}
          <div className="hidden xl:flex items-center gap-2 border border-hairline bg-surface-2/40 px-2.5 py-1 rounded font-mono text-[10px] text-ink-muted">
            <span className="flex items-center gap-1.5 text-accent-400">
              <span className="h-1.5 w-1.5 rounded-full bg-accent-400 animate-pulse" />
              SYS: {isDemoMode() ? "SIMULATED" : "ONLINE"}
            </span>
            <span className="text-hairline">·</span>
            <span>NET: {isDemoMode() ? "SYNTHETIC" : "MONITORED"}</span>
            <span className="text-hairline">·</span>
            <span className="text-ink-secondary">ENGINE: ACTIVE</span>
          </div>

          <Button
            variant="ghost"
            size="sm"
            loading={recompute.isPending}
            onClick={() => recompute.mutate()}
            className="hidden sm:inline-flex font-mono text-xs border-hairline hover:border-accent-500/40"
          >
            <Wrench className="h-3.5 w-3.5 text-accent-400" />
            <span>Recompute</span>
          </Button>

          <UserMenu />
        </div>
      </header>

      {/* Mobile Drawer Sheet */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="relative z-20 overflow-hidden border-b border-hairline bg-surface-1/95 px-4 py-3 backdrop-blur-lg lg:hidden"
          >
            <nav className="grid grid-cols-1 gap-1 sm:grid-cols-2">
              {NAV.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  onClick={() => setMobileOpen(false)}
                  className={({ isActive }) =>
                    clsx(
                      "flex items-center gap-3 rounded border px-3 py-2 text-xs font-mono transition-all",
                      isActive
                        ? "border-accent-500/50 bg-accent-500/10 text-accent-400 font-semibold"
                        : "border-transparent text-ink-secondary hover:bg-surface-2 hover:text-ink-primary"
                    )
                  }
                >
                  {({ isActive }) => (
                    <>
                      <item.icon
                        className={clsx(
                          "h-4 w-4 shrink-0",
                          isActive ? "text-accent-400" : "text-ink-muted"
                        )}
                      />
                      <span>{item.label}</span>
                      <span className="ml-auto text-[10px] text-ink-muted">{item.code}</span>
                    </>
                  )}
                </NavLink>
              ))}
            </nav>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="flex flex-1 overflow-hidden">
        {/* Desktop & Tablet Terminal Sidebar */}
        <nav className="hidden shrink-0 flex-col border-r border-hairline bg-surface-1/95 py-3 lg:flex lg:w-56">
          <div className="mb-2 px-3 flex items-center justify-between">
            <span className="font-mono text-[9px] font-bold uppercase tracking-[0.2em] text-ink-muted">
              // TELEMETRY CONSOLE
            </span>
            <span className="h-1.5 w-1.5 rounded-full bg-accent-500/60" />
          </div>

          <div className="flex flex-1 flex-col gap-1 px-2.5">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  clsx(
                    "group relative flex items-center gap-2.5 rounded border px-2.5 py-2 font-mono text-xs transition-all duration-150 active:translate-y-px",
                    isActive
                      ? "border-accent-500/40 bg-accent-500/10 text-accent-400 font-semibold shadow-[0_0_12px_rgba(0,255,102,0.12)]"
                      : "border-transparent text-ink-secondary hover:border-hairline hover:bg-surface-2/60 hover:text-ink-primary"
                  )
                }
                title={item.label}
              >
                {({ isActive }) => (
                  <>
                    {isActive && (
                      <span className="absolute left-0 top-1 bottom-1 w-0.5 rounded-r bg-accent-400 shadow-[0_0_8px_#00ff66]" />
                    )}
                    <item.icon
                      className={clsx(
                        "h-4 w-4 shrink-0 transition-colors",
                        isActive
                          ? "text-accent-400"
                          : "text-ink-muted group-hover:text-ink-primary"
                      )}
                    />
                    <span className="flex-1 truncate">{item.label}</span>
                    <span className={clsx("text-[9px] tabular-nums", isActive ? "text-accent-400/80" : "text-ink-muted")}>
                      {item.code}
                    </span>
                  </>
                )}
              </NavLink>
            ))}
          </div>

          {/* Bottom Sidebar Status Card */}
          <div className="mx-2.5 mt-auto border-t border-hairline pt-3 pb-1">
            <div className="rounded border border-hairline bg-surface-2/40 p-2 text-[10px] font-mono leading-relaxed text-ink-muted">
              <div className="flex items-center gap-1.5 text-accent-400 font-bold mb-1">
                <Terminal className="h-3 w-3" />
                <span>DEFENSE ENGINE</span>
              </div>
              <div>WATCHER: ACTIVE</div>
              <div className="text-[9px] text-ink-muted/80">REACHABILITY &gt; CVSS</div>
            </div>
          </div>
        </nav>

        {/* Main Content Area */}
        <AuroraBackground className="flex-1 overflow-y-auto scrollbar-thin overflow-x-hidden bg-canvas">
          <AnimatePresence mode="wait">
            <motion.div
              key={location.pathname}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.18, ease: "easeOut" }}
              className="h-full w-full"
            >
              {children}
            </motion.div>
          </AnimatePresence>
        </AuroraBackground>
      </div>
    </div>
  );
}

function UserMenu() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener("mousedown", onClick);
    return () => window.removeEventListener("mousedown", onClick);
  }, [open]);

  const initial = (user?.name || user?.email || "?").charAt(0).toUpperCase();

  const signOut = () => {
    setOpen(false);
    logout();
    navigate("/");
  };

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        aria-label="Account menu"
        className="flex h-7 w-7 items-center justify-center rounded border border-hairline bg-surface-2 font-mono text-xs text-accent-400 transition-colors hover:border-accent-500/40 hover:bg-accent-500/10"
      >
        {initial}
      </button>
      {open && (
        <div className="absolute right-0 top-9 z-30 w-56 rounded border border-hairline bg-surface-1 p-1.5 shadow-2xl backdrop-blur-xl">
          <div className="border-b border-hairline px-2.5 pb-2 pt-1">
            <div className="text-xs font-semibold text-ink-primary">{user?.name || "—"}</div>
            <div className="font-mono text-[10px] text-ink-muted">{user?.email}</div>
            <div className="mt-0.5 font-mono text-[9px] uppercase tracking-wider text-accent-500">
              ROLE: {user?.role || "OPERATOR"}
            </div>
          </div>
          <button
            onClick={() => {
              setOpen(false);
              navigate("/app/settings");
            }}
            className="mt-1 flex w-full items-center gap-2 rounded px-2.5 py-1.5 text-left font-mono text-xs text-ink-secondary hover:bg-surface-2 hover:text-ink-primary"
          >
            <Settings className="h-3.5 w-3.5 text-ink-muted" /> Settings
          </button>
          <button
            onClick={signOut}
            className="flex w-full items-center gap-2 rounded px-2.5 py-1.5 text-left font-mono text-xs text-ink-secondary hover:bg-surface-2 hover:text-risk-critical"
          >
            <LogOut className="h-3.5 w-3.5 text-risk-critical" /> Terminate Session
          </button>
        </div>
      )}
    </div>
  );
}
