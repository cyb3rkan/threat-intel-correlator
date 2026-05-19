"use client";

import * as React from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import {
  countByIocType,
  providerCoverage,
  scoreBuckets,
  SEVERITY_ORDER,
  type PublicFinding,
  type Severity,
} from "@/lib/api";
import { SEVERITY_TONE } from "@/lib/severity";

interface Props {
  findings: PublicFinding[];
  severityCounts: Record<Severity, number>;
}

export function DashboardCharts({ findings, severityCounts }: Props) {
  const total = findings.length;
  const iocBreakdown = React.useMemo(() => countByIocType(findings), [findings]);
  const providers = React.useMemo(() => providerCoverage(findings), [findings]);
  const buckets = React.useMemo(() => scoreBuckets(findings), [findings]);
  const maxBucket = Math.max(1, ...buckets.map((b) => b.count));

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-4">
      {/* Severity Distribution */}
      <Card className="border border-border shadow-sm">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Severity dağılımı</CardTitle>
          <CardDescription className="text-xs">Findings, severity bucket değerlerine göre gruplanır.</CardDescription>
        </CardHeader>
        <CardContent>
          {total === 0 ? (
            <EmptyState label="Henüz finding yok." />
          ) : (
            <ul className="space-y-2.5">
              {SEVERITY_ORDER.map((s) => {
                const count = severityCounts[s];
                const pct = total === 0 ? 0 : Math.round((count / total) * 100);
                return (
                  <li key={s} className="text-xs">
                    <div className="mb-1 flex items-center justify-between">
                      <span className="font-medium uppercase tracking-wide text-muted-foreground">{s}</span>
                      <span className="tabular-nums text-muted-foreground">
                        {count} · {pct}%
                      </span>
                    </div>
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                      <div
                        className={`h-full ${SEVERITY_TONE[s].bar}`}
                        style={{ width: `${pct}%` }}
                        aria-hidden
                      />
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </CardContent>
      </Card>

      {/* IOC Type Breakdown */}
      <Card className="border border-border shadow-sm">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">IOC type dağılımı</CardTitle>
          <CardDescription className="text-xs">Bu sweep’te bulunan benzersiz IOC type değerleri.</CardDescription>
        </CardHeader>
        <CardContent>
          {iocBreakdown.length === 0 ? (
            <EmptyState label="Eşleşen IOC yok." />
          ) : (
            <ul className="space-y-2">
              {iocBreakdown.slice(0, 6).map((row) => {
                const pct = total === 0 ? 0 : Math.round((row.value / total) * 100);
                return (
                  <li key={row.name} className="text-xs">
                    <div className="mb-1 flex items-center justify-between">
                      <span className="font-mono text-foreground/90">{row.name}</span>
                      <span className="tabular-nums text-muted-foreground">
                        {row.value} · {pct}%
                      </span>
                    </div>
                    <Progress value={pct} className="h-1.5" />
                  </li>
                );
              })}
              {iocBreakdown.length > 6 ? (
                <li className="text-[11px] text-muted-foreground/70">+{iocBreakdown.length - 6} daha</li>
              ) : null}
            </ul>
          )}
        </CardContent>
      </Card>

      {/* Provider Coverage */}
      <Card className="border border-border shadow-sm">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Provider coverage</CardTitle>
          <CardDescription className="text-xs">
            Provider başına dönen enrichment sayıları.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {providers.length === 0 ? (
            <EmptyState
              label={
                total === 0
                  ? "Doldurmak için bir sweep çalıştırın."
                  : "Provider enrichment yok. Backend keyring’inde provider key’leri yapılandırılmadığında bu beklenen bir durumdur."
              }
            />
          ) : (
            <ul className="space-y-2">
              {providers.map((p) => {
                const pct = total === 0 ? 0 : Math.round((p.count / total) * 100);
                return (
                  <li key={p.provider} className="text-xs">
                    <div className="mb-1 flex items-center justify-between">
                      <span className="font-medium text-foreground/90">{p.provider}</span>
                      <span className="tabular-nums text-muted-foreground">
                        {p.count} / {total}
                      </span>
                    </div>
                    <Progress value={pct} className="h-1.5" />
                  </li>
                );
              })}
            </ul>
          )}
        </CardContent>
      </Card>

      {/* Score Distribution */}
      <Card className="border border-border shadow-sm">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Score dağılımı</CardTitle>
          <CardDescription className="text-xs">Findings, risk score aralıklarına göre gruplanır.</CardDescription>
        </CardHeader>
        <CardContent>
          {total === 0 ? (
            <EmptyState label="Doldurmak için bir sweep çalıştırın." />
          ) : (
            <div className="flex h-32 items-end gap-2">
              {buckets.map((b) => {
                const heightPct = (b.count / maxBucket) * 100;
                return (
                  <div key={b.bucket} className="flex flex-1 flex-col items-center gap-1">
                    <div
                      className="w-full rounded-sm bg-blue-500/80"
                      style={{ height: `${Math.max(2, heightPct)}%` }}
                      title={`${b.bucket}: ${b.count}`}
                      aria-hidden
                    />
                    <div className="text-[10px] text-muted-foreground">{b.bucket}</div>
                    <div className="text-[10px] font-medium tabular-nums text-foreground/90">{b.count}</div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function EmptyState({ label }: { label: string }) {
  return (
    <div className="flex h-24 items-center justify-center rounded-md border border-dashed border-border text-xs text-muted-foreground/70">
      {label}
    </div>
  );
}
