// frontend/lib/severity.ts
// Single source of truth for severity → visual tokens. Components must
// import from here instead of hand-rolling colors so the dashboard stays
// visually consistent across table, charts, KPI tiles, drawers, and the
// SOC dark palette.

import type { Severity } from "@/lib/api";

// Numeric rank for sorting. Higher = more severe. critical=4 … info=0.
// Stable contract: priority.ts and tests depend on these values.
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

/**
 * Single-character glyphs used as redundant cues alongside color, so
 * severity is still recognizable without color (color-blindness, dark
 * theme low contrast, printed reports). Glyphs are intentionally simple
 * — they don't replace the label, they reinforce it.
 *   critical → ●  high → ▲  medium → ◆  low → ■  info → ·
 */
export const SEVERITY_GLYPH: Record<Severity, string> = {
  critical: "●",
  high: "▲",
  medium: "◆",
  low: "■",
  info: "·",
};

export interface SeverityTone {
  // Tailwind class fragments. Kept in `light dark:` paired form so both
  // themes are covered. Light values match the prior palette to avoid
  // visual regressions; dark values lean cooler/punchier (SOC console).
  badge: string;     // for severity pill (border + bg + text)
  dot: string;       // for small status dots (bg only)
  bar: string;       // for chart bars (bg only)
  text: string;      // for inline number / accent text
  ring: string;      // for focus rings on tile interactions (future)
}

export const SEVERITY_TONE: Record<Severity, SeverityTone> = {
  critical: {
    badge:
      "bg-red-100 text-red-700 border-red-200 dark:bg-red-950/50 dark:text-red-200 dark:border-red-800/70",
    dot: "bg-red-500 dark:bg-red-400",
    bar: "bg-red-500 dark:bg-red-400",
    text: "text-red-600 dark:text-red-300",
    ring: "ring-red-500/40 dark:ring-red-400/40",
  },
  high: {
    badge:
      "bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-950/50 dark:text-orange-200 dark:border-orange-800/70",
    dot: "bg-orange-500 dark:bg-orange-400",
    bar: "bg-orange-500 dark:bg-orange-400",
    text: "text-orange-600 dark:text-orange-300",
    ring: "ring-orange-500/40 dark:ring-orange-400/40",
  },
  medium: {
    badge:
      "bg-amber-100 text-amber-700 border-amber-200 dark:bg-amber-950/50 dark:text-amber-200 dark:border-amber-800/70",
    dot: "bg-amber-500 dark:bg-amber-400",
    bar: "bg-amber-500 dark:bg-amber-400",
    text: "text-amber-600 dark:text-amber-300",
    ring: "ring-amber-500/40 dark:ring-amber-400/40",
  },
  low: {
    badge:
      "bg-blue-100 text-blue-700 border-blue-200 dark:bg-blue-950/50 dark:text-blue-200 dark:border-blue-800/70",
    dot: "bg-blue-500 dark:bg-blue-400",
    bar: "bg-blue-500 dark:bg-blue-400",
    text: "text-blue-600 dark:text-blue-300",
    ring: "ring-blue-500/40 dark:ring-blue-400/40",
  },
  info: {
    badge:
      "bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800/70 dark:text-slate-200 dark:border-slate-700",
    dot: "bg-slate-400 dark:bg-slate-300",
    bar: "bg-slate-400 dark:bg-slate-300",
    text: "text-slate-600 dark:text-slate-300",
    ring: "ring-slate-500/40 dark:ring-slate-400/40",
  },
};

export function compareSeverityDesc(a: Severity, b: Severity): number {
  return SEVERITY_RANK[b] - SEVERITY_RANK[a];
}
