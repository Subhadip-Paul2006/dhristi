// Drishti v0.1 — auth page layout wrapper (Framer aesthetic) | 12-Jul-2026
import {
  Activity,
  ArrowRight,
  Database,
  Eye,
  EyeOff,
  Globe,
  Layers,
  Loader2,
  Server,
  ShieldCheck,
} from "lucide-react";
import { AnimatePresence, MotionConfig, motion } from "framer-motion";
import { Suspense, useId, useState, type ButtonHTMLAttributes, type ComponentType, type ReactNode } from "react";
import { Link, useLocation, useOutlet } from "react-router-dom";

/** Card slide/fade variants — direction depends on which page we're heading to. */
const cardVariants = {
  enter: (dir: number) => ({ x: dir * 56, opacity: 0, scale: 0.98, filter: "blur(6px)" }),
  center: { x: 0, opacity: 1, scale: 1, filter: "blur(0px)" },
  exit: (dir: number) => ({ x: dir * -56, opacity: 0, scale: 0.98, filter: "blur(6px)" }),
};

/** Persistent shell for /login and /signup: brand panel stays put while the
 * card cross-slides between the two pages. Rendered as a layout route. */
export function AuthShell() {
  const { pathname } = useLocation();
  const outlet = useOutlet();
  // login → signup slides left (forward), signup → login slides right (back)
  const dir = pathname === "/signup" ? 1 : -1;
  return (
    <div className="flex min-h-screen bg-canvas font-body text-ink antialiased selection:bg-accent-blue/30 selection:text-ink">
      <BrandPanel />
      <main className="relative flex flex-1 items-center justify-center overflow-hidden p-6">
        {/* quiet terrain behind the card — dot grid dissolving at the edges */}
        <div
          aria-hidden
          className="dot-terrain absolute inset-0 opacity-50 [mask-image:radial-gradient(ellipse_at_center,black_0%,transparent_72%)]"
        />
        <MotionConfig reducedMotion="user">
          <AnimatePresence mode="wait" custom={dir}>
            <motion.div
              key={pathname}
              custom={dir}
              variants={cardVariants}
              initial="enter"
              animate="center"
              exit="exit"
              transition={{ duration: 0.28, ease: [0.2, 0.8, 0.2, 1] }}
              className="relative w-full max-w-md"
            >
              <Suspense fallback={null}>{outlet}</Suspense>
            </motion.div>
          </AnimatePresence>
        </MotionConfig>
      </main>
    </div>
  );
}

/** Card content shared by /login and /signup, Framer skin. */
export function AuthLayout({
  title,
  subtitle,
  children,
  footer,
}: {
  title: string;
  subtitle: string;
  children: ReactNode;
  footer: ReactNode;
}) {
  return (
    <>
      <div className="mb-6 flex justify-center lg:hidden">
        <Logo />
      </div>
      <div className="relative overflow-hidden rounded-xxl border border-hairline bg-surface-1/90 shadow-light-edge backdrop-blur-sm">
        <span
          aria-hidden
          className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-accent-400/60 to-transparent"
        />
        <div className="px-7 pb-2 pt-8 text-center">
          <h1 className="font-display text-display-md tracking-tight text-ink">{title}</h1>
          <p className="mt-2 text-body text-ink-muted">{subtitle}</p>
        </div>
        <div className="px-7 pb-8 pt-6">{children}</div>
      </div>
      <div className="mt-6 text-center text-body-sm text-ink-muted">{footer}</div>
    </>
  );
}

function Logo({ inverse = false }: { inverse?: boolean }) {
  return (
    <Link to="/" className="flex items-center gap-2.5 hover:opacity-80 transition-opacity">
      <span
        className={`flex h-10 w-10 items-center justify-center rounded-xl ${
          inverse ? "bg-canvas text-ink" : "bg-surface-2 text-ink border border-hairline"
        }`}
      >
        <Activity className="h-5 w-5" />
      </span>
      <span className={`text-xl font-medium tracking-tight ${inverse ? "text-ink" : "text-ink"}`}>
        Drishti
      </span>
    </Link>
  );
}

/* ------------------------------------------------------- left brand panel */

function BrandPanel() {
  return (
    <aside className="auth-atmos relative hidden w-[46%] flex-col justify-between overflow-hidden border-r border-hairline-soft p-10 text-ink xl:w-[42%] xl:p-14 lg:flex">
      <div className="relative z-10">
        <Logo inverse />
      </div>

      <div className="relative z-10">
        <span className="inline-flex items-center gap-2 rounded-full border border-hairline bg-canvas/80 px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.12em] text-ink-muted">
          <span className="h-1.5 w-1.5 rounded-full bg-accent-400" />
          Deterministic attack-path intelligence
        </span>
        <h2 className="mt-6 max-w-md font-display text-display-lg leading-none tracking-tight">
          Every breach
          <br />
          is a path.
        </h2>
        <p className="mt-4 max-w-sm text-body-lg text-ink/80">
          Drishti maps the routes, prices the risk in dollars, and drafts the defensive fix.
        </p>
        <PathRail />
      </div>

      <p className="relative z-10 text-body-sm text-ink/60">
        Defensive by design — Drishti maps and fixes, never attacks.
      </p>
    </aside>
  );
}

/** The signature element: the attacker's route, cut at the sign-in gate. */
function PathRail() {
  return (
    <div className="mt-10 space-y-2" aria-hidden>
      <RailNode icon={Globe} label="internet" sub="entry point" />
      <RailEdge />
      <RailNode icon={Server} label="web tier" sub="internet-facing" />
      <RailEdge />
      <RailNode icon={Layers} label="app tier" sub="lateral movement" />
      <RailEdge />
      <div className="flex items-center gap-4 rounded-xl bg-canvas px-4 py-3 border border-hairline">
        <ShieldCheck className="h-5 w-5 shrink-0 text-semantic-success" />
        <span className="text-body-sm font-medium tracking-wide">sign-in required</span>
      </div>
      <RailEdge />
      <RailNode icon={Database} label="crown jewel" sub="protected" />
    </div>
  );
}

function RailNode({
  icon: Icon,
  label,
  sub,
}: {
  icon: ComponentType<{ className?: string }>;
  label: string;
  sub: string;
}) {
  return (
    <div className="flex items-center gap-4 rounded-xl bg-surface-2 px-4 py-3 border border-hairline/50">
      <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-canvas">
        <Icon className="h-4 w-4" />
      </span>
      <span className="text-body-sm font-medium">{label}</span>
      <span className="ml-auto text-caption text-ink-muted">{sub}</span>
    </div>
  );
}

function RailEdge() {
  return (
    <svg className="ml-[30px] block h-5 w-0.5 overflow-visible" aria-hidden>
      <line
        x1="1"
        y1="0"
        x2="1"
        y2="20"
        stroke="rgba(255,94,36,0.5)"
        strokeWidth="1.5"
        className="auth-dash"
      />
    </svg>
  );
}

/* ------------------------------------------------------------ form field */
/** Framer styled text field with floating label. */
export function Field({
  label,
  error,
  hint,
  ...input
}: {
  label: string;
  error?: string | null;
  hint?: string;
} & React.InputHTMLAttributes<HTMLInputElement>) {
  const id = useId();
  const [show, setShow] = useState(false);
  const isPassword = input.type === "password";
  const describedBy = error ? `${id}-error` : hint ? `${id}-hint` : undefined;
  const borderCls = error
    ? "border-risk-critical focus:border-risk-critical focus:ring-1 focus:ring-risk-critical"
    : "border-hairline focus:border-accent-blue focus:ring-1 focus:ring-accent-blue";
  return (
    <div className="mb-4">
      <div className="relative">
        <input
          {...input}
          id={id}
          type={isPassword && show ? "text" : input.type}
          placeholder=" "
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          className={`peer h-14 w-full rounded-lg border bg-surface-2 px-4 text-body text-ink outline-none transition-all duration-200 ${
            isPassword ? "pr-12" : ""
          } ${borderCls}`}
        />
        <label
          htmlFor={id}
          className={`pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 bg-surface-2 px-1.5 text-body transition-all duration-200 peer-focus:top-0 peer-focus:text-micro peer-[:not(:placeholder-shown)]:top-0 peer-[:not(:placeholder-shown)]:text-micro ${
            error
              ? "text-risk-critical"
              : "text-ink-muted peer-focus:text-accent-blue"
          }`}
        >
          {label}
        </label>
        {isPassword && (
          <button
            type="button"
            aria-label={show ? "Hide password" : "Show password"}
            onClick={() => setShow((s) => !s)}
            className="absolute right-2 top-1/2 flex h-9 w-9 -translate-y-1/2 items-center justify-center rounded-full text-ink-muted hover:text-ink transition-colors"
          >
            {show ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
          </button>
        )}
      </div>
      {error ? (
        <span id={`${id}-error`} className="mt-2 block px-2 text-micro text-risk-critical">
          {error}
        </span>
      ) : hint ? (
        <span id={`${id}-hint`} className="mt-2 block px-2 text-micro text-ink-muted">
          {hint}
        </span>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------ submit button */
/** Framer styled CTA button */
export function AuthButton({
  loading = false,
  children,
  disabled,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { loading?: boolean }) {
  return (
    <button
      {...rest}
      disabled={disabled || loading}
      className="group relative flex h-12 w-full items-center justify-center gap-2 rounded-pill bg-ink text-button text-inverse-ink shadow-[0_10px_28px_-10px_rgba(233,238,247,0.35)] transition-all hover:scale-[1.02] hover:shadow-[0_14px_34px_-10px_rgba(233,238,247,0.45)] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-60 disabled:hover:scale-100"
    >
      {loading && <Loader2 className="h-5 w-5 animate-spin" aria-hidden />}
      {children}
      {!loading && (
        <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
      )}
    </button>
  );
}
