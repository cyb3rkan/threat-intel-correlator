"use client";

import * as React from "react";
import {
  LayoutDashboard,
  Table2,
  Plug,
  Download,
  Lock,
  BookOpen,
  Activity,
} from "lucide-react";
import { cn } from "@/lib/utils";

export type SectionId =
  | "dashboard"
  | "findings"
  | "providers"
  | "exports"
  | "inputs"
  | "diagnostics"
  | "security";

const TABS: { id: SectionId; label: string; icon: React.ReactNode }[] = [
  { id: "dashboard", label: "Overview", icon: <LayoutDashboard className="h-4 w-4" /> },
  { id: "findings", label: "Findings", icon: <Table2 className="h-4 w-4" /> },
  { id: "providers", label: "Providers", icon: <Plug className="h-4 w-4" /> },
  { id: "exports", label: "Report", icon: <Download className="h-4 w-4" /> },
  { id: "inputs", label: "Inputs", icon: <BookOpen className="h-4 w-4" /> },
  { id: "diagnostics", label: "Diagnostics", icon: <Activity className="h-4 w-4" /> },
  { id: "security", label: "Security", icon: <Lock className="h-4 w-4" /> },
];

interface Props {
  current: SectionId;
  onChange: (id: SectionId) => void;
}

export function SectionTabs({ current, onChange }: Props) {
  // Roving-tabindex pattern: only the active tab is in the natural tab
  // order. ← / → and Home/End move focus AND change the active section.
  // Other keys (Tab, Shift+Tab) escape the tablist normally.
  const tablistRef = React.useRef<HTMLDivElement | null>(null);

  const onKeyDown: React.KeyboardEventHandler<HTMLDivElement> = (e) => {
    const order = TABS.map((t) => t.id);
    const idx = order.indexOf(current);
    if (idx < 0) return;
    let nextIdx = idx;
    if (e.key === "ArrowRight") nextIdx = (idx + 1) % order.length;
    else if (e.key === "ArrowLeft") nextIdx = (idx - 1 + order.length) % order.length;
    else if (e.key === "Home") nextIdx = 0;
    else if (e.key === "End") nextIdx = order.length - 1;
    else return;
    e.preventDefault();
    const next = order[nextIdx]!;
    onChange(next);
    // Move DOM focus to the newly active tab after React commits.
    requestAnimationFrame(() => {
      const root = tablistRef.current;
      if (!root) return;
      const target = root.querySelector<HTMLButtonElement>(`[data-tab-id="${next}"]`);
      target?.focus();
    });
  };

  return (
    // Horizontal scroll fallback for narrow screens — tablist keeps a
    // single row so analysts always see the same vertical rhythm; on
    // mobile the user can scroll the row instead of it wrapping mid-line.
    <div className="border-b border-border bg-background">
      <div
        ref={tablistRef}
        role="tablist"
        aria-label="Sections"
        onKeyDown={onKeyDown}
        className="mx-auto flex w-full max-w-[1400px] items-center gap-1 overflow-x-auto px-2"
      >
        {TABS.map((t) => {
          const active = current === t.id;
          return (
            <button
              key={t.id}
              data-tab-id={t.id}
              role="tab"
              type="button"
              aria-selected={active}
              aria-current={active ? "page" : undefined}
              tabIndex={active ? 0 : -1}
              onClick={() => onChange(t.id)}
              className={cn(
                "inline-flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2.5 text-sm font-medium transition-colors",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background",
                active
                  ? "border-blue-600 text-blue-700 dark:text-blue-300"
                  : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              {t.icon}
              {t.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
