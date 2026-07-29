"use client";

import * as React from "react";
import { ClipboardList } from "lucide-react";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { SEVERITY_ORDER } from "@/lib/api";
import { SEVERITY_TONE } from "@/lib/severity";
import type { ExecutiveSummary } from "@/lib/report";

export function ReportSummary({
  summary,
  filtered,
}: {
  summary: ExecutiveSummary;
  filtered: boolean;
}) {
  return (
    <Card className="border border-border shadow-sm">
      <CardHeader>
        <CardTitle className="text-sm">
          <span className="inline-flex items-center gap-2">
            <ClipboardList className="h-4 w-4 text-blue-600" />
            Executive summary
          </span>
        </CardTitle>
        <CardDescription className="text-xs">
          {filtered ? "Şu anda filtrelenmiş" : "Mevcut"} public-safe findings kullanılarak lokal
          olarak üretildi. Raw logs, raw provider payloads ve secrets değerleri buraya dahil edilmez.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
          {SEVERITY_ORDER.map((s) => (
            <div
              key={s}
              className="rounded-md border border-border bg-card px-3 py-2"
            >
              <div className="text-[11px] uppercase tracking-wide text-muted-foreground">{s}</div>
              <div className={`text-xl font-semibold tabular-nums ${SEVERITY_TONE[s].text}`}>
                {summary.severity[s]}
              </div>
            </div>
          ))}
        </div>

        <div className="grid gap-3 lg:grid-cols-3">
          <Block title="En sık IOC type değerleri">
            {summary.topIocTypes.length === 0 ? (
              <Empty>Yok.</Empty>
            ) : (
              <ul className="space-y-1 text-xs">
                {summary.topIocTypes.map((r) => (
                  <li key={r.name} className="flex items-center justify-between">
                    <code className="font-mono text-foreground/90">{r.name}</code>
                    <span className="tabular-nums text-muted-foreground">{r.value}</span>
                  </li>
                ))}
              </ul>
            )}
          </Block>
          <Block title="En sık source değerleri">
            {summary.topSources.length === 0 ? (
              <Empty>Yok.</Empty>
            ) : (
              <ul className="space-y-1 text-xs">
                {summary.topSources.map((r) => (
                  <li key={r.name} className="flex items-center justify-between">
                    <span className="truncate text-foreground/90" title={r.name}>
                      {r.name}
                    </span>
                    <span className="tabular-nums text-muted-foreground">{r.value}</span>
                  </li>
                ))}
              </ul>
            )}
          </Block>
          <Block title="Providers">
            {summary.providers.length === 0 ? (
              <Empty>
                Provider enrichment yok. Provider key’leri yapılandırılmadığında bu beklenen bir durumdur.
              </Empty>
            ) : (
              <ul className="space-y-1 text-xs">
                {summary.providers.map((p) => (
                  <li key={p.provider} className="flex items-center justify-between">
                    <span className="font-medium text-foreground/90">{p.provider}</span>
                    <span className="tabular-nums text-muted-foreground">{p.count}</span>
                  </li>
                ))}
              </ul>
            )}
          </Block>
        </div>

        <div>
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
            Önerilen sonraki adımlar
          </div>
          {summary.recommendations.length === 0 ? (
            <Empty>Öneri yok.</Empty>
          ) : (
            <ul className="list-disc space-y-1 pl-5 text-xs text-foreground/90">
              {summary.recommendations.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-border bg-muted/20 p-3">
      <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
        {title}
      </div>
      {children}
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <div className="text-xs text-muted-foreground/80">{children}</div>;
}
