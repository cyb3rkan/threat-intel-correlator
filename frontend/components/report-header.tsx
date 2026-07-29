"use client";

import * as React from "react";
import {
  ClipboardList,
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  Sparkles,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { OutputModePill } from "@/components/output-mode-pill";
import { cn } from "@/lib/utils";
import { formatTimestamp } from "@/lib/format";
import type { Severity, SweepResponse } from "@/lib/api";

interface Props {
  result: SweepResponse | null;
  failOn: Severity | null;
}

/**
 * Cover-style executive header for the Overview tab. Shows the most
 * recent sweep's identity at a glance: timestamp, finding total, output
 * mode (analyst/hash/summary), AI status, fail-on threshold, partial
 * scan flag. No IOC values are rendered here — hash mode safe.
 */
export function ReportHeader({ result, failOn }: Props) {
  if (!result) {
    return (
      <Card className="border border-border bg-card/60 shadow-sm">
        <CardHeader>
          <div className="flex items-start gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-md bg-blue-600/10 text-blue-600 dark:bg-blue-500/15 dark:text-blue-300">
              <ClipboardList className="h-4 w-4" />
            </div>
            <div>
              <CardTitle className="text-base">Threat Intel Report</CardTitle>
              <CardDescription className="text-xs">
                Henüz bir sweep çalıştırılmadı. Sağ taraftaki <strong>Sweep runner</strong> üzerinden
                bir feed ve log dosyası yükleyerek başlayın. Tüm korelasyon ve enrichment işlemleri
                lokal backend’inizde çalışır.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
      </Card>
    );
  }

  const above = result.above_threshold;
  // The backend doesn't return a sweep timestamp in SweepResponse, so use
  // the most recent finding's created_at as a best-effort proxy. Falls
  // back to "—" when there are zero findings.
  const sweepTs = result.findings.length > 0 ? result.findings[0]!.created_at : "";

  return (
    <Card className="border border-border bg-card shadow-sm">
      <CardHeader className="pb-3">
        <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
          <div className="flex items-start gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-blue-600/10 text-blue-600 dark:bg-blue-500/15 dark:text-blue-300">
              <ClipboardList className="h-4 w-4" />
            </div>
            <div>
              <CardTitle className="text-base leading-tight">Threat Intel Report</CardTitle>
              <CardDescription className="mt-0.5 text-xs">
                {sweepTs ? <>Sweep · {formatTimestamp(sweepTs)}</> : <>Sweep tamamlandı</>}
                {" · "}
                <span className="tabular-nums">{result.finding_count}</span> finding
              </CardDescription>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <OutputModePill mode={result.output_mode ?? null} />
            <AIBadge active={result.ai_active} attempted={result.ai_attempted} />
            <ThresholdBadge above={above} />
            {failOn ? <FailOnBadge failOn={failOn} /> : null}
            {result.partial_scan ? <PartialScanBadge /> : null}
          </div>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        <p className="text-[11px] leading-relaxed text-muted-foreground">
          Bu özet, mevcut sweep’in public-safe projeksiyonundan üretildi. Raw logs, raw provider
          payloads ve secrets değerleri hiçbir zaman buraya dahil edilmez. AI narrative yalnızca
          tavsiye niteliğindedir ve analyst incelemesi gerektirir.
        </p>
      </CardContent>
    </Card>
  );
}

function AIBadge({ active, attempted }: { active: boolean; attempted: boolean }) {
  if (active) {
    return (
      <Badge
        variant="outline"
        className="gap-1 border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-800/70 dark:bg-amber-950/40 dark:text-amber-200"
        title="AI narrative üretildi — advisory only, analyst incelemesi gerekir."
      >
        <Sparkles className="h-3 w-3" />
        AI advisory
      </Badge>
    );
  }
  if (attempted) {
    return (
      <Badge
        variant="outline"
        className="gap-1 border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-800/70 dark:bg-amber-950/40 dark:text-amber-200"
        title="AI talep edildi ancak başlatılamadı."
      >
        <AlertTriangle className="h-3 w-3" />
        AI unavailable
      </Badge>
    );
  }
  return (
    <Badge
      variant="outline"
      className="gap-1 border-border bg-muted/40 text-muted-foreground"
      title="Bu sweep AI narration kullanmadan çalıştırıldı."
    >
      <Sparkles className="h-3 w-3" />
      AI off
    </Badge>
  );
}

function ThresholdBadge({ above }: { above: boolean }) {
  return above ? (
    <Badge
      variant="outline"
      className="gap-1 border-red-300 bg-red-50 text-red-700 dark:border-red-800/70 dark:bg-red-950/40 dark:text-red-200"
      title="Sweep, yapılandırılan fail-on eşiğinde veya üstünde finding üretti."
    >
      <ShieldAlert className="h-3 w-3" />
      Eşik üstünde
    </Badge>
  ) : (
    <Badge
      variant="outline"
      className="gap-1 border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-800/70 dark:bg-emerald-950/40 dark:text-emerald-200"
      title="Hiçbir finding fail-on eşiğine ulaşmadı."
    >
      <CheckCircle2 className="h-3 w-3" />
      Eşik altında
    </Badge>
  );
}

function FailOnBadge({ failOn }: { failOn: Severity }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "gap-1 border-border bg-muted/40 font-mono text-[11px] text-foreground/85",
      )}
      title="CI fail-on eşiği"
    >
      fail-on: {failOn}
    </Badge>
  );
}

function PartialScanBadge() {
  return (
    <Badge
      variant="outline"
      className="gap-1 border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-800/70 dark:bg-amber-950/40 dark:text-amber-200"
      title="Log dosyası satır limitine ulaşıldı; sonuçlar eksik olabilir."
    >
      <AlertTriangle className="h-3 w-3" />
      Kısmi tarama
    </Badge>
  );
}
