"use client";

import * as React from "react";
import {
  Download,
  FileText,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Loader2,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ThemeToggle } from "@/components/theme-toggle";
import { OutputModePill } from "@/components/output-mode-pill";
import { API_BASE, type OutputMode } from "@/lib/api";

interface Props {
  healthy: boolean | null;
  outputMode?: OutputMode | string | null;
  onExport?: () => void;
  onReport?: () => void;
}

export function TopNav({ healthy, outputMode, onExport, onReport }: Props) {
  return (
    <header className="sticky top-0 z-30 border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80">
      <div className="mx-auto flex h-14 w-full max-w-[1400px] items-center gap-3 px-4">
        <div className="flex min-w-0 items-center gap-2">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-blue-600 text-white">
            <ShieldCheck className="h-4 w-4" aria-hidden="true" />
          </div>
          <div className="min-w-0 leading-tight">
            <div className="truncate text-sm font-semibold text-foreground">
              Threat Intel Correlator
            </div>
            <div className="hidden truncate text-[11px] uppercase tracking-wide text-muted-foreground sm:block">
              Local-only · Threat Hunting · IOC Correlation
            </div>
          </div>
        </div>

        <div className="ml-auto flex items-center gap-2">
          {outputMode ? (
            <OutputModePill mode={outputMode} compact className="hidden sm:inline-flex" />
          ) : null}
          <BackendBadge healthy={healthy} />
          <Button variant="outline" size="sm" onClick={onReport} className="hidden md:inline-flex">
            <FileText className="mr-1.5 h-4 w-4" />
            Rapor oluştur
          </Button>
          <Button variant="outline" size="sm" onClick={onExport} className="hidden md:inline-flex">
            <Download className="mr-1.5 h-4 w-4" />
            Export
          </Button>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}

function BackendBadge({ healthy }: { healthy: boolean | null }) {
  if (healthy === null) {
    return (
      <Badge
        variant="outline"
        className="gap-1 border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300"
        title={API_BASE}
      >
        <Loader2 className="h-3 w-3 animate-spin" />
        Kontrol ediliyor
      </Badge>
    );
  }
  if (healthy) {
    return (
      <Badge
        variant="outline"
        className="gap-1 border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-300"
        title={API_BASE}
      >
        <CheckCircle2 className="h-3 w-3" />
        Backend erişilebilir
      </Badge>
    );
  }
  return (
    <Badge
      variant="outline"
      className="gap-1 border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-300"
      title={API_BASE}
    >
      <AlertTriangle className="h-3 w-3" />
      Erişilemez
    </Badge>
  );
}
