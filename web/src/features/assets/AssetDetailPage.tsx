// Drishti v0.1 — single asset detail page | 11-Jul-2026
import { ArrowLeft } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { AssetDetailPanel } from "./AssetDetailPanel";

export function AssetDetailPage() {
  const { id } = useParams<{ id: string }>();
  return (
    <div className="mx-auto max-w-2xl p-6">
      <Link
        to="/app/assets"
        className="mb-4 inline-flex items-center gap-1.5 text-small text-ink-muted hover:text-ink-primary"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> All assets
      </Link>
      {id && <AssetDetailPanel assetId={id} showViewOnMap />}
    </div>
  );
}
