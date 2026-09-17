// Drishti v0.1 — syntax-highlighted code block | 11-Jul-2026
import { Check, Copy } from "lucide-react";
import { useEffect, useRef, useState } from "react";

export function CodeBlock({ code, language }: { code: string; language?: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // don't let a pending "Copied" reset fire after unmount
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked — ignore */
    }
  };
  return (
    <div className="overflow-hidden rounded-md border border-edge-subtle bg-bg-inset">
      <div className="flex items-center justify-between border-b border-edge-subtle px-3 py-1.5">
        <span className="font-mono text-small uppercase tracking-[0.02em] text-ink-muted">
          {language ?? "script"}
        </span>
        <button
          onClick={copy}
          className="inline-flex items-center gap-1.5 rounded-sm px-2 py-1 text-small text-ink-secondary hover:bg-bg-raised hover:text-ink-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent-500/70"
        >
          {copied ? <Check className="h-3.5 w-3.5 text-risk-safe" /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="scrollbar-thin max-h-[420px] overflow-auto p-4 text-small leading-relaxed">
        <code className="font-mono text-ink-secondary">{code}</code>
      </pre>
    </div>
  );
}
