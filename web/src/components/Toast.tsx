// Drishti v0.1 — toast notification component | 11-Jul-2026
import { CheckCircle2, Info, XCircle } from "lucide-react";
import { useEffect } from "react";
import { useToast } from "../store/graphStore";

export function ToastHost() {
  const { message, variant, hide } = useToast();
  useEffect(() => {
    if (!message) return;
    const t = setTimeout(hide, 3200);
    return () => clearTimeout(t);
  }, [message, hide]);

  if (!message) return null;
  const Icon = variant === "success" ? CheckCircle2 : variant === "error" ? XCircle : Info;
  const tint =
    variant === "success"
      ? "text-risk-safe"
      : variant === "error"
        ? "text-risk-critical"
        : "text-accent-500";
  return (
    // key remounts per message so the slide-in replays. -translate-x-1/2 is in
    // BOTH the class and the keyframes: the animation transform wins while it
    // runs, and the class keeps the toast centered under reduced motion.
    <div
      key={message}
      className="animate-toast-in pointer-events-none fixed bottom-6 left-1/2 z-50 -translate-x-1/2"
    >
      <div className="pointer-events-auto flex items-center gap-2 rounded-md border border-edge-subtle bg-bg-raised px-4 py-2.5 text-body text-ink-primary shadow-pop">
        <Icon className={`h-4 w-4 ${tint}`} />
        {message}
      </div>
    </div>
  );
}
