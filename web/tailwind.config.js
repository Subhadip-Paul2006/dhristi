/**
 * Design tokens — Drishti "Cybersecurity Terminal + Matrix + SOC Command Center" (Dark Theme).
 *
 * Single source of truth for the WHOLE app. Remapping the tokens here re-skins
 * every screen without breaking existing component contracts.
 * Base surfaces: #050706 (canvas), #080B09 (surface-1), #0C100E (surface-2), #101612 (surface-3).
 * Primary accent: Matrix / Terminal Green (#00ff66, #00e575).
 * Threat colors: Critical (#ef4444), High (#f97316), Medium (#f59e0b), Safe/Low (#00ff66).
 */
/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // ── Cyber Terminal & Matrix Palette ────────────────────────────────
        primary: "#00ff66", // Matrix terminal green
        "on-primary": "#050706", // Dark label on green fill
        "accent-blue": "#00ff66", // Remapped to terminal green
        ink: "#e6edf3", // Crisp light terminal readout
        "ink-muted": "#52665a", // Deep muted technical sage
        canvas: "#050706", // Deep obsidian near-black
        "surface-1": "#080b09", // Terminal panel surface
        "surface-2": "#0c100e", // Inset wells & secondary panels
        "surface-3": "#101612", // Elevated HUD chrome
        hairline: "#152219", // Fine technical border
        "hairline-soft": "#0e1812", // Subtle divider
        "inverse-canvas": "#e6edf3",
        "inverse-ink": "#050706",

        // Severity ramp — functional cybersecurity semantics
        risk: {
          safe: "#00ff66",
          low: "#10b981",
          medium: "#f59e0b",
          high: "#f97316",
          critical: "#ef4444",
          glow: "rgba(239, 68, 68, 0.35)",
        },
        status: {
          open: "#f97316",
          remediating: "#f59e0b",
          resolved: "#00ff66",
          info: "#52665a",
        },

        // Surface aliases
        bg: {
          base: "#050706",
          surface: "#080b09",
          raised: "#0c100e",
          inset: "#030504",
        },
        edge: {
          subtle: "#152219",
          strong: "#1e3828",
        },

        // Text ramp: High-contrast terminal hierarchy
        "ink-primary": "#e6edf3", // Crisp primary white/green
        "ink-secondary": "#9ca3af", // Terminal dim gray/green
        "ink-subtle": "#52665a", // Subordinate metadata

        // Accent = Matrix / Terminal Green ramp
        accent: {
          300: "#6ee7b7",
          400: "#00e575", // High-readability terminal green
          500: "#00ff66", // Matrix phosphor green
          600: "#059669", // Deep emerald for pressed/hover
          glow: "rgba(0, 255, 102, 0.20)",
        },

        md: {
          primary: "#00ff66",
          "on-primary": "#050706",
          "primary-container": "#0c100e",
          "on-primary-container": "#e6edf3",
          secondary: "#9ca3af",
          "on-secondary": "#050706",
          error: "#ef4444",
          background: "#050706",
          "on-background": "#e6edf3",
          surface: "#080b09",
          "surface-lowest": "#030504",
        },

        // Legacy token mappings for 100% backwards-compatibility
        "signal-orange": "#00ff66",
        "ember-crust": "#064e3b",
        "cloud-mist": "#0c100e",
        "graphite-ink": "#e6edf3",
        "paper-white": "#080b09",
        "slate-pencil": "#9ca3af",
        "ash-mist": "#52665a",
        "blush-shadow": "#101612",
        "midnight-ink": "#050706",
        "semantic-success": "#00ff66",
      },
      ringColor: { DEFAULT: "#00ff66" },
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
