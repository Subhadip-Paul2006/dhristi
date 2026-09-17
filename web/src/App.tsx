// Drishti v0.1 — root provider and router setup | 11-Jul-2026
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { Suspense, lazy, useEffect } from "react";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AuthProvider } from "./auth";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ToastHost } from "./components/Toast";
import NeuralBackground from "@/components/ui/flow-field-background";
import heroBg from "./assets/hero-bg.jpg";

// Code-split the heavy halves: the public marketing page, the auth pages, and
// the authed app (React Flow, Recharts, feature code) load only when their
// route does.
const Landing = lazy(() => import("./features/landing/Landing"));
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

/** The particle canvas is fully hidden behind the landing page's opaque
 * background but still burns a rAF loop — mount it only where it's visible.
 * On the landing route, spend that budget preloading the hero LCP image
 * instead (the lazy chunk would otherwise discover it three hops late). */
function BackgroundLayer() {
  const { pathname } = useLocation();
  const onLanding = pathname === "/";

  useEffect(() => {
    if (!onLanding) return;
    if (document.querySelector(`link[href="${heroBg}"]`)) return;
    const link = document.createElement("link");
    link.rel = "preload";
    link.as = "image";
    link.href = heroBg;
    link.setAttribute("fetchpriority", "high");
    document.head.appendChild(link);
  }, [onLanding]);

  if (onLanding) return null;
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
          <BackgroundLayer />
          <Suspense fallback={<RouteFallback />}>
            <ErrorBoundary>
              <Routes>
                <Route path="/" element={<Landing />} />
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
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
