// Drishti v0.1 — authenticated app shell and routes | 11-Jul-2026
/** The authed application shell + routes. Lazy-loaded from App.tsx so the
 * public landing page never downloads React Flow, Recharts, or feature code. */
import { Loader2 } from "lucide-react";
import type { ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useAuth } from "./auth";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Shell } from "./components/Shell";
import { AssetsPage } from "./features/assets/AssetsPage";
import { AssetDetailPage } from "./features/assets/AssetDetailPage";
import { FindingsPage } from "./features/findings/FindingsPage";
import { AttackMap } from "./features/graph/AttackMap";
import { LiveWatchPage } from "./features/live/LiveWatchPage";
import { AppHome } from "./features/onboarding/AppHome";
import { PathDetailPage } from "./features/paths/PathDetailPage";
import { PathsPage } from "./features/paths/PathsPage";
import { RemediationConsole } from "./features/remediation/RemediationConsole";
import { ReportPage } from "./features/report/ReportPage";
import { SettingsPage } from "./features/settings/SettingsPage";
import { UrlAnalyzerPage } from "./features/urltrust/UrlAnalyzerPage";

/** Route guard: any /app/* URL without a session redirects to /login. */
function RequireAuth({ children }: { children: ReactNode }) {
  const { ready, user } = useAuth();
  if (!ready) {
    return (
      <div className="flex min-h-screen items-center justify-center gap-2 text-ink-muted">
        <Loader2 className="h-5 w-5 animate-spin" />
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export default function ProtectedApp() {
  // keyed by pathname: each route change replays a short fade/slide-up
  // (CSS-only; disabled entirely under prefers-reduced-motion)
  const location = useLocation();
  return (
    <RequireAuth>
      <Shell>
        <ErrorBoundary>
          <div key={location.pathname} className="animate-page-enter h-full">
            <Routes>
            <Route index element={<AppHome />} />
            {/* dedicated boundary: a React Flow crash must not take down the
                whole routed view (ERROR_HANDLING.md §3.1) */}
            <Route
              path="graph"
              element={
                <ErrorBoundary>
                  <AttackMap />
                </ErrorBoundary>
              }
            />
            <Route path="paths" element={<PathsPage />} />
            <Route path="paths/:id" element={<PathDetailPage />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="assets" element={<AssetsPage />} />
            <Route path="assets/:id" element={<AssetDetailPage />} />
            <Route path="url-analyzer" element={<UrlAnalyzerPage />} />
            <Route path="report" element={<ReportPage />} />
            <Route path="live" element={<LiveWatchPage />} />
            <Route path="remediate/:findingId" element={<RemediationConsole />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="*" element={<Navigate to="/app" replace />} />
            </Routes>
          </div>
        </ErrorBoundary>
      </Shell>
    </RequireAuth>
  );
}
