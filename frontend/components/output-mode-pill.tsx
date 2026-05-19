"use client";

import * as React from "react";
import { Eye, Lock, FileText, CircleDashed } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { OutputMode } from "@/lib/api";

interface Props {
  mode: OutputMode | string | null | undefined;
  // When true, render a single compact pill suitable for the top nav.
  // When false, render a slightly larger pill with the mode label spelled
  // out — used in the status strip.
  compact?: boolean;
  className?: string;
}

interface Token {
  label: string;
  short: string;
  icon: React.ReactNode;
  classes: string;
  title: string;
}

const ANALYST: Token = {
  label: "Analyst mode",
  short: "analyst",
  icon: <Eye className="h-3 w-3" aria-hidden="true" />,
  classes:
    "border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-900/60 dark:bg-blue-950/40 dark:text-blue-200",
  title:
    "Analyst mode — IOC değerleri ham olarak gösterilir. Yalnızca public-safe alanlar render edilir.",
};

const HASH: Token = {
  label: "Hash mode (pseudonymized)",
  short: "hash",
  icon: <Lock className="h-3 w-3" aria-hidden="true" />,
  classes:
    "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-200",
  title:
    "Hash mode — IOC değerleri hmac:<hex> pseudonym olarak döner. Ham değerler frontend'e hiçbir zaman gönderilmez.",
};

const SUMMARY: Token = {
  label: "Summary mode",
  short: "summary",
  icon: <FileText className="h-3 w-3" aria-hidden="true" />,
  classes:
    "border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-200",
  title:
    "Summary mode — IOC ayrıntıları toplulaştırılmış olarak gösterilir.",
};

const UNKNOWN: Token = {
  label: "Output mode bilinmiyor",
  short: "—",
  icon: <CircleDashed className="h-3 w-3" aria-hidden="true" />,
  classes:
    "border-border bg-muted/40 text-muted-foreground",
  title: "Bir sweep henüz çalıştırılmadı.",
};

function tokenFor(mode: OutputMode | string | null | undefined): Token {
  if (mode === "analyst") return ANALYST;
  if (mode === "hash") return HASH;
  if (mode === "summary") return SUMMARY;
  return UNKNOWN;
}

export function OutputModePill({ mode, compact = false, className }: Props) {
  const t = tokenFor(mode);
  return (
    <Badge
      variant="outline"
      title={t.title}
      aria-label={t.label}
      className={cn("gap-1 font-medium", t.classes, className)}
    >
      {t.icon}
      <span className={compact ? "text-[11px]" : "text-xs"}>
        {compact ? t.short : t.label}
      </span>
    </Badge>
  );
}
