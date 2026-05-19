"use client";

import * as React from "react";
import { History, Trash2, ShieldAlert, CheckCircle2 } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { type RunHistoryEntry } from "@/lib/history";

interface Props {
  entries: RunHistoryEntry[];
  onClear: () => void;
}

export function RunHistory({ entries, onClear }: Props) {
  return (
    <Card className="border border-border shadow-sm">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div>
            <CardTitle className="text-sm">
              <span className="inline-flex items-center gap-2">
                <History className="h-4 w-4 text-blue-600" />
                Çalıştırma geçmişi
              </span>
            </CardTitle>
            <CardDescription className="text-xs">
              Son {entries.length || 0} sweep özeti — yalnızca tarayıcınızda saklanır. IOC
              değerleri, log içerikleri ve secrets buraya yazılmaz.
            </CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={onClear}
            disabled={entries.length === 0}
            aria-label="Çalıştırma geçmişini temizle"
          >
            <Trash2 className="mr-1.5 h-3.5 w-3.5" />
            Temizle
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {entries.length === 0 ? (
          <div className="rounded-md border border-dashed border-border p-4 text-center text-xs text-muted-foreground">
            Henüz çalıştırma kaydı yok. Lokal geçmişi oluşturmak için bir sweep çalıştırın.
          </div>
        ) : (
          <ul className="space-y-2">
            {entries.map((e) => (
              <li
                key={e.id}
                className="rounded-md border border-border bg-card p-2.5"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                  <div className="flex items-center gap-2">
                    {e.above_threshold ? (
                      <ShieldAlert className="h-3.5 w-3.5 text-red-600 dark:text-red-400" />
                    ) : (
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
                    )}
                    <span className="text-muted-foreground">
                      {new Date(e.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5 text-[11px]">
                    <Badge variant="outline" className="font-mono">
                      mode: {e.output_mode}
                    </Badge>
                    <Badge variant="outline" className="font-mono">
                      fail-on: {e.fail_on}
                    </Badge>
                    <Badge
                      variant="outline"
                      className="font-mono tabular-nums"
                      title="Exit code"
                    >
                      exit: {e.exit_code}
                    </Badge>
                  </div>
                </div>
                <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-muted-foreground">
                  <Stat label="findings" value={e.finding_count} />
                  <Stat label="critical" value={e.severity_counts.critical} tone="text-red-600 dark:text-red-400" />
                  <Stat label="high" value={e.severity_counts.high} tone="text-orange-600 dark:text-orange-400" />
                  <Stat label="medium" value={e.severity_counts.medium} tone="text-amber-600 dark:text-amber-400" />
                  <Stat label="low" value={e.severity_counts.low} tone="text-blue-600 dark:text-blue-400" />
                  <Stat label="info" value={e.severity_counts.info} />
                  <Stat label="ioc types" value={e.unique_ioc_types} />
                  <Stat label="providers" value={e.unique_providers} />
                  {e.partial_scan ? (
                    <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] text-amber-800 dark:bg-amber-950/40 dark:text-amber-300">
                      kısmi tarama
                    </span>
                  ) : null}
                  {e.ai_attempted && !e.ai_active ? (
                    <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] text-amber-800 dark:bg-amber-950/40 dark:text-amber-300">
                      AI kullanılamıyor
                    </span>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: string;
}) {
  return (
    <span className="inline-flex items-center gap-1 rounded border border-border bg-muted/40 px-1.5 py-0.5">
      <span className="uppercase tracking-wide">{label}</span>
      <span className={`tabular-nums font-medium ${tone ?? "text-foreground"}`}>{value}</span>
    </span>
  );
}
