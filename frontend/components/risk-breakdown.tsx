"use client";

import * as React from "react";
import { BarChart3 } from "lucide-react";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { SEVERITY_TONE } from "@/lib/severity";
import {
  countByIocType,
  providerCoverage,
  scoreBuckets,
  SEVERITY_ORDER,
  type PublicFinding,
  type Severity,
} from "@/lib/api";

interface Props {
  findings: PublicFinding[];
  severityCounts: Record<Severity, number>;
}

/**
 * Read-only risk breakdown for the Report tab. All data is derived from
 * the same helpers Overview's DashboardCharts uses; rendering shape is
 * tuned for a report context (denser, monochrome where possible). Plain
 * React text nodes throughout — no markdown render.
 */
export function RiskBreakdown({ findings, severityCounts }: Props) {
  const total = findings.length;
  const ioc = React.useMemo(() => countByIocType(findings), [findings]);
  const providers = React.useMemo(() => providerCoverage(findings), [findings]);
  const buckets = React.useMemo(() => scoreBuckets(findings), [findings]);
  const aiCovered = React.useMemo(
    () => findings.reduce((n, f) => (f.ai_narrative ? n + 1 : n), 0),
    [findings],
  );
  const aiPct = total === 0 ? 0 : Math.round((aiCovered / total) * 100);
  const maxBucket = Math.max(1, ...buckets.map((b) => b.count));

  return (
    <Card className="border border-border shadow-sm">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">
          <span className="inline-flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-blue-600 dark:text-blue-300" />
            Risk breakdown
          </span>
        </CardTitle>
        <CardDescription className="text-xs">
          Severity, score dağılımı, provider coverage, IOC type dağılımı ve AI narrative coverage —
          sadece public-safe finding alanlarından türetilmiştir.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Block title="Severity dağılımı">
            {total === 0 ? (
              <Empty>Henüz finding yok.</Empty>
            ) : (
              <ul className="space-y-2">
                {SEVERITY_ORDER.map((s) => {
                  const count = severityCounts[s];
                  const pct = total === 0 ? 0 : Math.round((count / total) * 100);
                  return (
                    <li key={s} className="text-xs">
                      <div className="mb-1 flex items-center justify-between gap-2">
                        <span className="font-medium uppercase tracking-wide text-muted-foreground">
                          {s}
                        </span>
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
          </Block>

          <Block title="Score dağılımı">
            {total === 0 ? (
              <Empty>Henüz finding yok.</Empty>
            ) : (
              <div className="flex h-32 items-end gap-2">
                {buckets.map((b) => {
                  const heightPct = (b.count / maxBucket) * 100;
                  return (
                    <div key={b.bucket} className="flex flex-1 flex-col items-center gap-1">
                      <div
                        className="w-full rounded-sm bg-blue-500/80 dark:bg-blue-400/80"
                        style={{ height: `${Math.max(2, heightPct)}%` }}
                        title={`${b.bucket}: ${b.count}`}
                        aria-hidden
                      />
                      <div className="text-[10px] text-muted-foreground">{b.bucket}</div>
                      <div className="text-[10px] font-medium tabular-nums text-foreground/90">
                        {b.count}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Block>

          <Block title="Provider coverage">
            {providers.length === 0 ? (
              <Empty>
                Bu sweep için hiçbir provider enrichment dönmedi. Yapılandırma için Providers
                sekmesindeki readiness panelini inceleyin.
              </Empty>
            ) : (
              <ul className="space-y-2">
                {providers.map((p) => {
                  const pct = total === 0 ? 0 : Math.round((p.count / total) * 100);
                  return (
                    <li key={p.provider} className="text-xs">
                      <div className="mb-1 flex items-center justify-between gap-2">
                        <span className="min-w-0 truncate font-medium text-foreground/90">
                          {p.provider}
                        </span>
                        <span className="shrink-0 tabular-nums text-muted-foreground">
                          {p.count} / {total}
                        </span>
                      </div>
                      <Progress value={pct} className="h-1.5" />
                    </li>
                  );
                })}
              </ul>
            )}
          </Block>

          <Block title="IOC type dağılımı">
            {ioc.length === 0 ? (
              <Empty>Eşleşen IOC yok.</Empty>
            ) : (
              <ul className="space-y-2">
                {ioc.slice(0, 8).map((row) => {
                  const pct = total === 0 ? 0 : Math.round((row.value / total) * 100);
                  return (
                    <li key={row.name} className="text-xs">
                      <div className="mb-1 flex items-center justify-between gap-2">
                        <code className="min-w-0 truncate font-mono text-foreground/90">
                          {row.name}
                        </code>
                        <span className="shrink-0 tabular-nums text-muted-foreground">
                          {row.value} · {pct}%
                        </span>
                      </div>
                      <Progress value={pct} className="h-1.5" />
                    </li>
                  );
                })}
                {ioc.length > 8 ? (
                  <li className="text-[11px] text-muted-foreground/70">
                    +{ioc.length - 8} daha
                  </li>
                ) : null}
              </ul>
            )}
          </Block>
        </div>

        <div className="mt-4 rounded-md border border-border bg-muted/20 p-3">
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
            AI narrative coverage
          </div>
          <div className="flex items-center gap-3 text-xs">
            <span className="tabular-nums text-foreground/90">
              {aiCovered} / {total}
            </span>
            <Progress value={aiPct} className="h-1.5 flex-1" />
            <span className="tabular-nums text-muted-foreground">{aiPct}%</span>
          </div>
          <p className="mt-1 text-[10px] leading-relaxed text-muted-foreground [overflow-wrap:anywhere]">
            AI narrative yalnızca tavsiyedir. Yüzdeler bir kalite ölçüsü değil, kapsamın
            göstergesidir.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-border bg-muted/10 p-3">
      <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
        {title}
      </div>
      {children}
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-dashed border-border p-3 text-center text-[11px] text-muted-foreground [overflow-wrap:anywhere]">
      {children}
    </div>
  );
}
