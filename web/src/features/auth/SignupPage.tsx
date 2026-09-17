// Drishti v0.1 — user registration page | 11-Jul-2026
import { useState, type FormEvent } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { ApiError } from "../../api/client";
import { useAuth } from "../../auth";
import { AuthButton, AuthLayout, Field } from "./AuthLayout";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function SignupPage() {
  const { user, register } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: "", email: "", password: "", org_name: "" });
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (user) return <Navigate to="/app" replace />;

  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  const validate = (): boolean => {
    const errs: Record<string, string> = {};
    if (!form.name.trim()) errs.name = "Your name is required.";
    if (!EMAIL_RE.test(form.email)) errs.email = "Enter a valid email address.";
    if (form.password.length < 8) errs.password = "At least 8 characters.";
    if (!form.org_name.trim()) errs.org_name = "Organization name is required.";
    setFieldErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!validate()) return;
    setBusy(true);
    try {
      await register(form);
      navigate("/app");
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 409
          ? "An account with this email already exists — try signing in instead."
          : "Couldn't create the account — is the server reachable?",
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthLayout
      title="Get started"
      subtitle="Create your organization's workspace in seconds."
      footer={
        <>
          Already have an account?{" "}
          <Link to="/login" className="font-medium text-accent-blue hover:underline">
            Sign in
          </Link>
        </>
      }
    >
      <form onSubmit={submit} className="space-y-5" noValidate>
        <Field
          label="Your name"
          autoComplete="name"
          autoFocus
          placeholder="Ada Lovelace"
          value={form.name}
          onChange={set("name")}
          error={fieldErrors.name}
        />
        <Field
          label="Work email"
          type="email"
          autoComplete="email"
          placeholder="you@company.com"
          value={form.email}
          onChange={set("email")}
          error={fieldErrors.email}
        />
        <Field
          label="Password"
          type="password"
          autoComplete="new-password"
          placeholder="••••••••"
          hint="At least 8 characters."
          value={form.password}
          onChange={set("password")}
          error={fieldErrors.password}
        />
        <Field
          label="Organization name"
          placeholder="NewCo Security"
          hint="Creates a new workspace — you'll be its first admin."
          value={form.org_name}
          onChange={set("org_name")}
          error={fieldErrors.org_name}
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
          Create account
        </AuthButton>
      </form>
    </AuthLayout>
  );
}
