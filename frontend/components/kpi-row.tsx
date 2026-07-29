"use client";

import * as React from "react";
import { ShieldAlert, Activity, AlertTriangle, CheckCircle2 } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { Severity, SweepResponse } from "@/lib/api";
import { SEVERITY_TONE } from "@/lib/severity";

interface Props {
  result: SweepResponse | null;
  counts: Record<Severity, number>;
}

export function KpiRow({ result, counts }: Props) {
  const placeholder = result === null;
  const above = !placeholder && result?.above_threshold;
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-8">
      <KpiCard
        label="Toplam findings"
        value={result?.finding_count ?? 0}
        icon={<Activity className="h-3.5 w-3.5" />}
        placeholder={placeholder}
      />
      <KpiCard label="Critical" value={counts.critical} valueClass={SEVERITY_TONE.critical.text} placeholder={placeholder} />
      <KpiCard label="High" value={counts.high} valueClass={SEVERITY_TONE.high.text} placeholder={placeholder} />
      <KpiCard label="Medium" value={counts.medium} valueClass={SEVERITY_TONE.medium.text} placeholder={placeholder} />
      <KpiCard label="Low" value={counts.low} valueClass={SEVERITY_TONE.low.text} placeholder={placeholder} />
      <KpiCard label="Info" value={counts.info} valueClass={SEVERITY_TONE.info.text} placeholder={placeholder} />
      <KpiCard
        label="Eşik üstünde"
        value={placeholder ? "—" : above ? "Evet" : "Hayır"}
        valueClass={above ? "text-red-600 dark:text-red-400" : "text-emerald-600 dark:text-emerald-400"}
        icon={above ? <ShieldAlert className="h-3.5 w-3.5" /> : <CheckCircle2 className="h-3.5 w-3.5" />}
        placeholder={placeholder}
      />
      <KpiCard
        label="Exit code"
        value={result?.exit_code ?? "—"}
        icon={result && result.exit_code !== 0 ? <AlertTriangle className="h-3.5 w-3.5" /> : undefined}
        placeholder={placeholder}
      />
    </div>
  );
}

function KpiCard({
  label,
  value,
  icon,
  valueClass,
  placeholder,
}: {
  label: string;
  value: number | string;
  icon?: React.ReactNode;
  valueClass?: string;
  placeholder: boolean;
}) {
  return (
    <Card className="border border-border shadow-sm">
      <CardContent className="px-4 py-3">
        <div className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
          {icon}
          {label}
        </div>
        <div className={cn("mt-1 text-2xl font-semibold tabular-nums", valueClass ?? "text-foreground")}>
          {value}
        </div>
        {placeholder ? (
          <div className="mt-0.5 text-[10px] uppercase tracking-wide text-muted-foreground/70">placeholder</div>
        ) : null}
      </CardContent>
    </Card>
  );
}
