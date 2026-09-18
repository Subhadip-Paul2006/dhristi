/**
 * Design tokens — Drishti Luxury Obsidian & Electric Cyan SOC Command Center (Dark Theme).
 *
 * Single source of truth for the WHOLE app. Remapping the tokens here re-skins
 * every screen with a cohesive, modern cybersecurity aesthetic.
 * Base surfaces: #020b14 (canvas), #051322 (surface-1), #091a2e (surface-2), #0e233d (surface-3).
 * Primary accent: Electric Cyan (#38c6f4, #0ea5e9) / Indigo (#6366f1).
 * Threat colors: Critical (#ef4444), High (#f97316), Medium (#f59e0b), Safe/Low (#10b981).
 */
/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // ── 21st.dev Favorites Chromatic Gradient Palette ───────────────
        primary: "#c084fc", // Luminous Lavender / Purple
        "on-primary": "#030208", // Dark label on purple fill
        "accent-blue": "#818cf8", // Electric Indigo
        ink: "#f8fafc", // Crisp light readout
        "ink-muted": "#94a3b8", // Slate muted text
        canvas: "#030208", // Deep Obsidian Violet
        "surface-1": "#0a0718", // Card & sidebar surface
        "surface-2": "#120d28", // Inset wells & secondary panels
        "surface-3": "#1c153d", // Elevated purple chrome
        hairline: "rgba(168, 85, 247, 0.16)", // Fine violet border
        "hairline-soft": "rgba(168, 85, 247, 0.08)", // Subtle divider
        "inverse-canvas": "#f8fafc",
        "inverse-ink": "#030208",

        // Severity ramp — functional cybersecurity semantics
        risk: {
          safe: "#10b981",
          low: "#10b981",
          medium: "#f59e0b",
          high: "#f97316",
          critical: "#ef4444",
          glow: "rgba(239, 68, 68, 0.35)",
        },
        status: {
          open: "#f97316",
          remediating: "#f59e0b",
          resolved: "#10b981",
          info: "#38bdf8",
        },

        // Surface aliases
        bg: {
          base: "#030208",
          surface: "#0a0718",
          raised: "#120d28",
          inset: "#020104",
        },
        edge: {
          subtle: "rgba(168, 85, 247, 0.16)",
          strong: "rgba(192, 132, 252, 0.35)",
        },

        // Text ramp: High-contrast modern hierarchy
        "ink-primary": "#f8fafc", // Crisp primary white
        "ink-secondary": "#cbd5e1", // Slate medium gray
        "ink-subtle": "#94a3b8", // Subordinate metadata

        // Accent = Luminous Violet & Indigo ramp
        accent: {
          300: "#d8b4fe",
          400: "#c084fc", // High-readability lavender
          500: "#a855f7", // Vivid purple
          600: "#9333ea", // Deep violet for pressed/hover
          glow: "rgba(168, 85, 247, 0.28)",
        },

        md: {
          primary: "#c084fc",
          "on-primary": "#030208",
          "primary-container": "#120d28",
          "on-primary-container": "#f8fafc",
          secondary: "#cbd5e1",
          "on-secondary": "#030208",
          error: "#ef4444",
          background: "#030208",
          "on-background": "#f8fafc",
          surface: "#0a0718",
          "surface-lowest": "#020104",
        },

        // Legacy token mappings for 100% backwards-compatibility
        "signal-orange": "#ea580c",
        "ember-crust": "#1c153d",
        "cloud-mist": "#120d28",
        "graphite-ink": "#f8fafc",
        "paper-white": "#0a0718",
        "slate-pencil": "#cbd5e1",
        "ash-mist": "#94a3b8",
        "blush-shadow": "#1c153d",
        "midnight-ink": "#030208",
        "semantic-success": "#10b981",
      },
      ringColor: { DEFAULT: "#c084fc" },
      fontFamily: {
        display: ["'Space Grotesk'", "'Inter'", "system-ui", "sans-serif"],
        body: ["'Inter'", "'Manrope'", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "monospace"],
        roboto: ["'Inter'", "system-ui", "sans-serif"],
      },
      fontSize: {
        "display-xxl": ["110px", { lineHeight: "0.85", letterSpacing: "-5.5px", fontWeight: "600" }],
        "display-xl": ["85px", { lineHeight: "0.95", letterSpacing: "-4.25px", fontWeight: "600" }],
        "display-lg": ["62px", { lineHeight: "1.00", letterSpacing: "-3.1px", fontWeight: "600" }],
        "display-md": ["32px", { lineHeight: "1.13", letterSpacing: "-1.0px", fontWeight: "600" }],
        headline: ["22px", { lineHeight: "1.20", letterSpacing: "-0.8px", fontWeight: "700" }],
        subhead: ["24px", { lineHeight: "1.30", letterSpacing: "-0.01px", fontWeight: "400" }],
        "body-lg": ["18px", { lineHeight: "1.30", letterSpacing: "-0.18px", fontWeight: "400" }],
        "body-sm": ["14px", { lineHeight: "1.40", letterSpacing: "-0.14px", fontWeight: "500" }],
        button: ["14px", { lineHeight: "1.00", letterSpacing: "-0.14px", fontWeight: "600" }],
        small: ["0.8125rem", { lineHeight: "1.45" }],
        body: ["0.9375rem", { lineHeight: "1.5" }],
        h3: ["1.0625rem", { lineHeight: "1.3" }],
        h2: ["1.375rem", { lineHeight: "1.25", letterSpacing: "-0.01em" }],
        h1: ["1.75rem", { lineHeight: "1.2", letterSpacing: "-0.015em" }],
        display: ["2.25rem", { lineHeight: "1.1", letterSpacing: "-0.02em" }],
        "mono-data": ["0.9375rem", { lineHeight: "1.4" }],
        caption: ["13px", { lineHeight: "1.20", letterSpacing: "-0.13px", fontWeight: "500" }],
        micro: ["12px", { lineHeight: "1.20", letterSpacing: "-0.12px", fontWeight: "400" }],
      },
      borderRadius: {
        xs: "3px",
        sm: "4px",
        md: "6px",
        lg: "8px",
        xl: "12px",
        xxl: "16px",
        node: "8px",
        pill: "100px",
        full: "9999px",
      },
      spacing: {
        hair: "1px",
        xxs: "4px",
        xs: "8px",
        sm: "12px",
        md: "15px",
        lg: "20px",
        xl: "30px",
        xxl: "40px",
        section: "96px",
      },
      boxShadow: {
        "focus-ring": "0 0 0 1px rgba(0,255,102,0.35)",
        "light-edge": "0 1px 2px rgba(0,0,0,0.8), 0 0 0 1px #152219",
        "accent-glow": "0 0 0 1px rgba(0,255,102,0.4), 0 0 16px rgba(0,255,102,0.2)",
        "matrix-glow": "0 0 24px -4px rgba(0,255,102,0.3)",
        "threat-glow": "0 0 24px -4px rgba(239,68,68,0.4)",
        card: "0 2px 4px rgba(0,0,0,0.6), 0 0 0 1px #152219",
        pop: "0 8px 24px rgba(0,0,0,0.8), 0 0 0 1px #1e3828",
        neo: "2px 2px 0px 0px #152219",
        "neo-md": "3px 3px 0px 0px #152219",
        "neo-lg": "4px 4px 0px 0px #152219",
      },
      keyframes: {
        "dash-flow": { to: { strokeDashoffset: "-16" } },
        "blast-pulse": {
          "0%": { boxShadow: "0 0 0 0 rgba(239,68,68,0.45)" },
          "100%": { boxShadow: "0 0 0 18px rgba(239,68,68,0)" },
        },
        "terminal-cursor": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0" },
        },
        shimmer: {
          "0%": { opacity: "0.2" },
          "50%": { opacity: "0.5" },
          "100%": { opacity: "0.2" },
        },
        "spin-slow": { from: { transform: "rotate(0deg)" }, to: { transform: "rotate(360deg)" } },
      },
      animation: {
        "dash-flow": "dash-flow 1s linear infinite",
        "blast-pulse": "blast-pulse 600ms ease-out 1",
        "terminal-cursor": "terminal-cursor 1s step-end infinite",
        shimmer: "shimmer 1.6s ease-in-out infinite",
        "spin-slow": "spin-slow 10s linear infinite",
      },
    },
  },
  plugins: [],
};
