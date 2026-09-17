// Drishti v0.1 — user login page | 11-Jul-2026
import { useState, type FormEvent } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { ApiError } from "../../api/client";
import { useAuth } from "../../auth";
import { AuthButton, AuthLayout, Field } from "./AuthLayout";

export function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (user) return <Navigate to="/app" replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!email || !password) {
      setError("Enter your email and password.");
      return;
    }
    setBusy(true);
    try {
      await login(email, password);
      navigate("/app");
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 401
          ? "Invalid email or password."
          : "Couldn't sign in — is the server reachable?",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthLayout
      title="Sign in"
      subtitle="Welcome back — your attack surface is waiting."
      footer={
        <>
          New to Drishti?{" "}
          <Link to="/signup" className="font-medium text-accent-blue hover:underline">
            Create an account
          </Link>
        </>
      }
    >
      {/* Demo creds are dev-only — never shipped in a production bundle. */}
      {import.meta.env.DEV && (
        <button
          type="button"
          onClick={() => {
            setEmail("analyst@acme-retail.dev");
            setPassword("drishti-demo");
            setError(null);
          }}
          className="relative mb-5 w-full overflow-hidden rounded-xl bg-surface-2 px-4 py-3 text-left text-ink transition-all border border-hairline hover:border-accent-400/50 hover:bg-surface-2/80"
        >
          <span className="block text-xs font-medium tracking-wide">
            Demo workspace — click to fill
          </span>
          <span className="mt-0.5 block font-mono text-sm">analyst@acme-retail.dev · drishti-demo</span>
        </button>
      )}
      <form onSubmit={submit} className="space-y-5" noValidate>
        <Field
          label="Email"
          type="email"
          autoComplete="email"
          autoFocus
          placeholder="you@company.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <Field
          label="Password"
          type="password"
          autoComplete="current-password"
          placeholder="••••••••"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {error && (
          <div
            role="alert"
            className="rounded-xl border border-risk-critical/30 bg-risk-critical/10 px-4 py-3 text-sm text-risk-critical"
          >
            {error}
          </div>
        )}
        <AuthButton type="submit" loading={busy}>
          Sign in
        </AuthButton>
      </form>
    </AuthLayout>
  );
}
