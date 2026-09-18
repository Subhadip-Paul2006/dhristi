// Drishti v0.1 — organization settings page | 11-Jul-2026
import { useMutation, useQuery } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { ApiError, api } from "../../api/client";
import { useAuth } from "../../auth";
import { Button } from "../../components/Button";
import { Card } from "../../components/primitives";
import { useToast } from "../../store/graphStore";
import { Field } from "../auth/AuthLayout";

export function SettingsPage() {
  const { user, refreshMe } = useAuth();
  const toast = useToast();
  const orgQ = useQuery({ queryKey: ["org"], queryFn: () => api.org() });

  const [name, setName] = useState(user?.name ?? "");
  const [pw, setPw] = useState({ current: "", next: "", confirm: "" });
  const [pwError, setPwError] = useState<string | null>(null);

  const saveName = useMutation({
    mutationFn: () => api.patchMe({ name: name.trim() }),
    onSuccess: async () => {
      await refreshMe();
      toast.show("Profile updated", "success");
    },
    onError: () => toast.show("Couldn't update the profile — retry", "error"),
  });

  const changePw = useMutation({
    mutationFn: () => api.patchMe({ current_password: pw.current, new_password: pw.next }),
    onSuccess: () => {
      setPw({ current: "", next: "", confirm: "" });
      toast.show("Password changed", "success");
    },
    onError: (err) =>
      setPwError(
        err instanceof ApiError && err.status === 401
          ? "Current password is incorrect."
          : "Couldn't change the password — retry.",
      ),
  });

  const submitName = (e: FormEvent) => {
    e.preventDefault();
    if (name.trim()) saveName.mutate();
  };
  const submitPw = (e: FormEvent) => {
    e.preventDefault();
    setPwError(null);
    if (pw.next.length < 8) {
      setPwError("New password needs at least 8 characters.");
      return;
    }
    if (pw.next !== pw.confirm) {
      setPwError("New passwords don't match.");
      return;
    }
    changePw.mutate();
  };

  const tgQ = useQuery({
    queryKey: ["telegram-status"],
    queryFn: () => api.telegramStatus(),
    refetchInterval: 10000,
  });

  const testTelegram = useMutation({
    mutationFn: () => api.telegramTest(),
    onSuccess: (data) => {
      toast.show(`Test alert delivered to Telegram (${data.results.length} recipient)`, "success");
      tgQ.refetch();
    },
    onError: (err) => {
      toast.show(err instanceof Error ? err.message : "Failed to send Telegram test alert", "error");
    },
  });

  return (
    <div className="console-atmos min-h-screen">
      <div className="mx-auto max-w-2xl space-y-6 p-4 sm:p-6 lg:p-8">
        <header className="border-b border-hairline/60 pb-5">
          <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-accent-400">
            <span className="inline-block h-2 w-2 rounded-full bg-accent-500 shadow-[0_0_8px_#00ff66]" />
            <span>SYS.CONFIG // USER_CREDENTIALS_AND_ORGS</span>
          </div>
          <h1 className="mt-2 font-display text-display font-semibold tracking-tight text-ink-primary">
            Platform Settings
          </h1>
          <p className="mt-1 font-mono text-small text-ink-secondary">
            User credentials, active cryptographic session tokens, and organization fleet telemetry.
          </p>
        </header>

        <Card className="space-y-4 p-5 border border-hairline bg-surface-1/90 shadow-2xl relative">
          <div className="font-mono text-xs font-bold uppercase tracking-wider text-accent-400">[OPERATOR PROFILE]</div>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-small">
            <dt className="font-mono text-xs text-ink-muted">EMAIL</dt>
            <dd className="font-mono text-ink-primary font-semibold">{user?.email}</dd>
            <dt className="font-mono text-xs text-ink-muted">ROLE</dt>
            <dd className="font-mono text-accent-400 font-bold uppercase">{user?.role}</dd>
            <dt className="font-mono text-xs text-ink-muted">ORGANIZATION</dt>
            <dd className="font-mono text-ink-secondary">
              {user?.org_name}
              {orgQ.data && (
                <span className="text-ink-muted">
                  {" "}
                  · {orgQ.data.asset_count} assets · {orgQ.data.member_count} member
                  {orgQ.data.member_count === 1 ? "" : "s"}
                </span>
              )}
            </dd>
          </dl>
          <form onSubmit={submitName} className="flex items-end gap-3 pt-2">
            <div className="flex-1">
              <Field label="Display name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <Button type="submit" loading={saveName.isPending} disabled={!name.trim()}>
              Save
            </Button>
          </form>
        </Card>

        <Card className="space-y-4 p-5 border border-hairline bg-surface-1/90 shadow-2xl relative">
          <div className="font-mono text-xs font-bold uppercase tracking-wider text-accent-400">[AUTHENTICATION CREDENTIALS]</div>
          <form onSubmit={submitPw} className="space-y-3" noValidate>
            <Field
              label="Current password"
              type="password"
              autoComplete="current-password"
              value={pw.current}
              onChange={(e) => setPw((s) => ({ ...s, current: e.target.value }))}
            />
            <Field
              label="New password"
              type="password"
              autoComplete="new-password"
              value={pw.next}
              onChange={(e) => setPw((s) => ({ ...s, next: e.target.value }))}
            />
            <Field
              label="Confirm new password"
              type="password"
              autoComplete="new-password"
              value={pw.confirm}
              onChange={(e) => setPw((s) => ({ ...s, confirm: e.target.value }))}
            />
            {pwError && (
              <div className="rounded border border-risk-critical/30 bg-risk-critical/10 p-2.5 font-mono text-xs text-risk-critical">
                {pwError}
              </div>
            )}
            <Button type="submit" loading={changePw.isPending} disabled={!pw.current || !pw.next}>
              Change password
            </Button>
          </form>
        </Card>

        <Card className="space-y-4 p-5 border border-hairline bg-surface-1/90 shadow-2xl relative">
          <div className="flex items-center justify-between">
            <div className="font-mono text-xs font-bold uppercase tracking-wider text-accent-400">
              [TELEGRAM ALERT NOTIFICATIONS]
            </div>
            {tgQ.data?.configured ? (
              <span className="flex items-center gap-1.5 font-mono text-xs text-risk-low">
                <span className="inline-block h-2 w-2 rounded-full bg-risk-low animate-pulse" />
                ACTIVE DISPATCHER
              </span>
            ) : (
              <span className="font-mono text-xs text-ink-muted">NOT CONFIGURED</span>
            )}
          </div>
          <p className="font-mono text-xs text-ink-secondary">
            Outbound automated push notifications dispatched to your verified Telegram bot for critical findings and active network threats.
          </p>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-small">
            <dt className="font-mono text-xs text-ink-muted">DISPATCHER STATUS</dt>
            <dd className="font-mono text-xs font-semibold text-ink-primary">
              {tgQ.data?.running ? "Running (30s background scan)" : tgQ.data?.configured ? "Ready" : "Disabled"}
            </dd>
            <dt className="font-mono text-xs text-ink-muted">TARGET CHAT ID(S)</dt>
            <dd className="font-mono text-xs text-ink-primary">
              {tgQ.data?.chat_ids_masked?.join(", ") || "None configured"}
            </dd>
            <dt className="font-mono text-xs text-ink-muted">PROCESSED THREATS/CVEs</dt>
            <dd className="font-mono text-xs text-ink-secondary">
              {tgQ.data?.alerted_count ?? 0} dispatched items
            </dd>
          </dl>
          <div className="pt-2">
            <Button
              type="button"
              variant="ghost"
              loading={testTelegram.isPending}
              disabled={!tgQ.data?.configured}
              onClick={() => testTelegram.mutate()}
            >
              Send Test Alert to Telegram
            </Button>
          </div>
        </Card>
      </div>
    </div>
  );
}
