// Drishti v0.1 — first-run onboarding wizard | 11-Jul-2026
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Network, PlayCircle, TerminalSquare } from "lucide-react";
import { api } from "../../api/client";
import { useAuth } from "../../auth";
import { Button } from "../../components/Button";
import { CodeBlock } from "../../components/CodeBlock";
import { Card } from "../../components/primitives";
import { useToast } from "../../store/graphStore";
import type { AgentToken } from "../../api/types";

/** First-run screen for an EMPTY org: load the sample assessment, or connect
 * a real network via the edge agent. All numbers afterwards come from the
 * engine — this screen never fabricates data. */
export function Onboarding() {
  const { user } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();

  const loadSample = useMutation({
    mutationFn: () => api.loadSample(),
    onSuccess: () => {
      qc.invalidateQueries();
      toast.show("Sample assessment loaded — risk model computed", "success");
    },
    onError: () => toast.show("Couldn't load the sample — retry", "error"),
  });

  const agentToken = useMutation({ mutationFn: () => api.agentToken() });

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-8">
      <div>
        <h1 className="font-display text-h1 text-ink-primary">
          Welcome{user?.name ? `, ${user.name.split(" ")[0]}` : ""} 👋
        </h1>
        <p className="mt-1 text-body text-ink-secondary">
          <span className="text-ink-primary">{user?.org_name}</span> has no assets yet.
          Pick how you want to start:
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card className="flex flex-col gap-3 p-5">
          <PlayCircle className="h-6 w-6 text-accent-500" />
          <div>
            <div className="font-display text-h3 text-ink-primary">
              Load a sample assessment
            </div>
            <p className="mt-1 text-small text-ink-secondary">
              A realistic 10-asset retail network with live attack paths, blast radius, and
              dollar exposure — computed by the risk engine, not canned numbers.
            </p>
          </div>
          <Button
            className="mt-auto"
            loading={loadSample.isPending}
            onClick={() => loadSample.mutate()}
          >
            Load sample
          </Button>
        </Card>

        <Card className="flex flex-col gap-3 p-5">
          <Network className="h-6 w-6 text-accent-500" />
          <div>
            <div className="font-display text-h3 text-ink-primary">Connect your network</div>
            <p className="mt-1 text-small text-ink-secondary">
              Generate an agent token and run the single-file edge agent on a host you own.
              Scan metadata streams into this workspace.
            </p>
          </div>
          {!agentToken.data && (
            <Button
              variant="ghost"
              className="mt-auto"
              loading={agentToken.isPending}
              onClick={() => agentToken.mutate()}
            >
              <TerminalSquare className="h-4 w-4" /> Generate agent token
            </Button>
          )}
          {agentToken.isError && (
            <div className="text-small text-risk-high">
              Couldn't generate a token — try again.
            </div>
          )}
        </Card>
      </div>

      {agentToken.data && <AgentInstructions token={agentToken.data} />}
    </div>
  );
}

function AgentInstructions({ token }: { token: AgentToken }) {
  const origin = window.location.origin;
  const command = [
    "python3 drishti_agent.py --once \\",
    `  --server ${origin} \\`,
    `  --token ${token.token} \\`,
    `  --org-slug ${token.org_slug}`,
  ].join("\n");
  return (
    <Card className="space-y-3 p-5">
      <div className="font-display text-h3 text-ink-primary">Run the edge agent</div>
      <p className="text-small text-ink-secondary">
        This token is shown <span className="text-ink-primary">once</span> — store it safely.
        Grab <span className="font-mono text-ink-primary">agent/drishti_agent.py</span> from the
        repo and run:
      </p>
      <CodeBlock code={command} />
      <p className="text-small text-ink-muted">
        The dashboard fills in as soon as the first snapshot is accepted. Generating a new
        token replaces this one.
      </p>
    </Card>
  );
}
