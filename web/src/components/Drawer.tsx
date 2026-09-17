// Drishti v0.1 — slide-in detail drawer | 11-Jul-2026
import { X } from "lucide-react";
import type { ReactNode } from "react";

/** Right-hand slide-over used for node/path detail over the graph (UIUX.md §5). */
export function Drawer({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
}) {
  return (
    <div
      className={`pointer-events-none fixed inset-y-0 right-0 z-30 w-full max-w-md transition-[transform,opacity] duration-[220ms] ease-out motion-reduce:transition-none ${
        open ? "translate-x-0 opacity-100" : "translate-x-full opacity-0"
      }`}
      aria-hidden={!open}
    >
      <div
        className={`pointer-events-auto flex h-full flex-col border-l border-edge-subtle bg-bg-raised shadow-pop ${
          open ? "" : "invisible"
        }`}
      >
        <div className="flex items-center justify-between border-b border-edge-subtle px-4 py-3">
          <div className="min-w-0 font-display text-h3 text-ink-primary">{title}</div>
          <button
            onClick={onClose}
            aria-label="Close panel"
            className="rounded-sm p-1 text-ink-muted hover:bg-bg-surface hover:text-ink-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-500/70"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="scrollbar-thin flex-1 overflow-y-auto p-4">{children}</div>
      </div>
    </div>
  );
}
