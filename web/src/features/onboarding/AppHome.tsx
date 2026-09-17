// Drishti v0.1 — post-login home and onboarding | 11-Jul-2026
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import { ErrorState, LoadingBlock } from "../../components/primitives";
import { Dashboard } from "../dashboard/Dashboard";
import { Onboarding } from "./Onboarding";

/** /app index: brand-new empty orgs get onboarding; orgs with assets get the
 * dashboard. The gate reads real org counts — nothing is faked. */
export function AppHome() {
  const orgQ = useQuery({ queryKey: ["org"], queryFn: () => api.org() });

  if (orgQ.isLoading) return <LoadingBlock label="Loading your workspace…" />;
  if (orgQ.isError || !orgQ.data)
    return (
      <div className="p-8">
        <ErrorState message="Couldn't load your organization." onRetry={() => orgQ.refetch()} />
      </div>
    );
  return orgQ.data.asset_count === 0 ? <Onboarding /> : <Dashboard />;
}
