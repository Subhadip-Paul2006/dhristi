// Drishti v0.1 — root provider and router setup | 11-Jul-2026
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { Suspense, lazy, useEffect } from "react";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AuthProvider } from "./auth";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ToastHost } from "./components/Toast";
import NeuralBackground from "@/components/ui/flow-field-background";
import { ScrollToTopButton } from "./components/ui/scroll-to-top";
import heroBg from "./assets/hero-bg.jpg";

// Code-split the heavy halves: the public marketing pages, the auth pages, and
// the authed app (React Flow, Recharts, feature code) load only when their
// route does.
const Landing = lazy(() => import("./features/landing/Landing"));
const TopologyPage = lazy(() =>
  import("./features/landing/Landing").then((m) => ({ default: m.TopologyPage }))
);
const PipelinePage = lazy(() =>
  import("./features/landing/Landing").then((m) => ({ default: m.PipelinePage }))
);
const ArchitecturePage = lazy(() =>
  import("./features/landing/Landing").then((m) => ({ default: m.ArchitecturePage }))
);
const ComparisonPage = lazy(() =>
  import("./features/landing/Landing").then((m) => ({ default: m.ComparisonPage }))
);
const PlaybooksPage = lazy(() =>
  import("./features/landing/Landing").then((m) => ({ default: m.PlaybooksPage }))
);
const LoginPage = lazy(() =>
  import("./features/auth/LoginPage").then((m) => ({ default: m.LoginPage }))
);
const SignupPage = lazy(() =>
  import("./features/auth/SignupPage").then((m) => ({ default: m.SignupPage }))
);
const AuthShell = lazy(() =>
  import("./features/auth/AuthLayout").then((m) => ({ default: m.AuthShell }))
);
const ProtectedApp = lazy(() => import("./ProtectedApp"));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 5_000 },
  },
});

function RouteFallback() {
  return (
    <div className="flex min-h-screen items-center justify-center gap-2 text-ink-muted">
      <Loader2 className="h-5 w-5 animate-spin" />
    </div>
  );
}

/** Automatically handles smooth scrolling to top on route navigation,
 * or jumping to anchor element when hash is present (e.g. #faq). */
function ScrollToTop() {
  const { pathname, hash } = useLocation();

  useEffect(() => {
    if (hash) {
      const el = document.getElementById(hash.replace("#", ""));
      if (el) {
        el.scrollIntoView({ behavior: "smooth" });
        return;
      }
    }
    window.scrollTo({ top: 0, left: 0, behavior: "instant" });
  }, [pathname, hash]);

  return null;
}

/** The particle canvas is hidden behind marketing pages to prevent unnecessary rAF loops.
 * On marketing routes, preload hero image if applicable. */
function BackgroundLayer() {
  const { pathname } = useLocation();
  const isMarketing =
    pathname === "/" ||
    pathname === "/topology" ||
    pathname === "/pipeline" ||
    pathname === "/architecture" ||
    pathname === "/comparison" ||
    pathname === "/playbooks";

  useEffect(() => {
    if (pathname !== "/") return;
    if (document.querySelector(`link[href="${heroBg}"]`)) return;
    const link = document.createElement("link");
    link.rel = "preload";
    link.as = "image";
    link.href = heroBg;
    link.setAttribute("fetchpriority", "high");
    document.head.appendChild(link);
  }, [pathname]);

  if (isMarketing) return null;
  return (
    <div className="fixed inset-0 -z-10 pointer-events-none">
      <NeuralBackground color="#38c6f4" trailOpacity={0.1} speed={0.8} />
    </div>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <ScrollToTop />
          <BackgroundLayer />
          <Suspense fallback={<RouteFallback />}>
            <ErrorBoundary>
              <Routes>
                <Route path="/" element={<Landing />} />
                <Route path="/topology" element={<TopologyPage />} />
                <Route path="/pipeline" element={<PipelinePage />} />
                <Route path="/architecture" element={<ArchitecturePage />} />
                <Route path="/comparison" element={<ComparisonPage />} />
                <Route path="/playbooks" element={<PlaybooksPage />} />
                <Route element={<AuthShell />}>
                  <Route path="/login" element={<LoginPage />} />
                  <Route path="/signup" element={<SignupPage />} />
                </Route>
                <Route path="/app/*" element={<ProtectedApp />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </ErrorBoundary>
          </Suspense>
          <ToastHost />
          <ScrollToTopButton />
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
