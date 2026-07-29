"use client";

import * as React from "react";
import {
  Activity,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  Copy,
  Check,
  Server,
  ShieldCheck,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { API_BASE } from "@/lib/api";
import type { OutputMode, ProviderStatusResponse } from "@/lib/api";

interface Props {
  healthy: boolean | null;
  lastChecked: Date | null;
  outputMode: OutputMode | string | null;
  providerStatus?: ProviderStatusResponse | null;
}

function buildCommands(apiBase: string) {
  // Generic project-relative commands. We deliberately do NOT echo
  // machine-specific paths, secrets, or env values.
  return {
    backendStart:
      "poetry run uvicorn tic.api.main:app --host 127.0.0.1 --port 8000",
    frontendStart: "cd frontend && npm install && npm run dev",
    healthCurl: `curl ${apiBase}/api/health`,
    sweepCurl: `curl -X POST ${apiBase}/api/sweep \\
  -F "feed_file=@./sample_iocs.csv" \\
  -F "log_file=@./sample_events.ndjson" \\
  -F "feed_format=csv" \\
  -F "output_mode=analyst" \\
  -F "fail_on=high" \\
  -F "with_ai=false"`,
  };
}

export function DiagnosticsPanel({ healthy, lastChecked, outputMode, providerStatus }: Props) {
  const cmds = React.useMemo(() => buildCommands(API_BASE), []);
  const env = process.env.NODE_ENV ?? "unknown";
  const providerSummary = React.useMemo(() => {
    if (!providerStatus) return null;
    const ready = providerStatus.providers.filter((p) => p.ready).length;
    const total = providerStatus.providers.length;
    const aiReady = providerStatus.ai.ready;
    const hmacReady = providerStatus.redaction_hmac.key_present;
    return { ready, total, aiReady, hmacReady };
  }, [providerStatus]);

  return (
    <div className="space-y-4">
      <Card className="border border-border shadow-sm">
        <CardHeader>
          <CardTitle className="text-sm">
            <span className="inline-flex items-center gap-2">
              <Activity className="h-4 w-4 text-blue-600" />
              Runtime diagnostics
            </span>
          </CardTitle>
          <CardDescription className="text-xs">
            Yalnızca lokal runtime bağlamını gösterir. Bir sorunla karşılaştığınızda; makine
            yollarınızı veya secrets değerlerini değil, buradaki değerleri paylaşın.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          <KV
            label="API base"
            value={<code className="font-mono text-xs">{API_BASE}</code>}
          />
          <KV label="Backend erişilebilir" value={<HealthBadge healthy={healthy} />} />
          <KV
            label="Son health check"
            value={
              <span className="text-xs text-muted-foreground">
                {lastChecked
                  ? lastChecked.toLocaleTimeString()
                  : "—"}
              </span>
            }
          />
          <KV
            label="Frontend env"
            value={
              <Badge variant="outline" className="font-mono">
                {env}
              </Badge>
            }
          />
          <KV
            label="Geçerli output mode"
            value={
              <Badge variant="outline" className="font-mono">
                {outputMode ?? "—"}
              </Badge>
            }
          />
          <KV
            label="Local-only"
            value={
              <Badge
                variant="outline"
                className="gap-1 border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-300"
              >
                <ShieldCheck className="h-3 w-3" />
                telemetri yok · dış çağrı yok
              </Badge>
            }
          />
          {providerSummary !== null ? (
            <>
              <KV
                label="Hazır provider"
                value={
                  <Badge
                    variant="outline"
                    className={
                      providerSummary.ready === providerSummary.total && providerSummary.total > 0
                        ? "gap-1 border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-300"
                        : "gap-1"
                    }
                  >
                    <CheckCircle2 className="h-3 w-3" />
                    {providerSummary.ready} / {providerSummary.total}
                  </Badge>
                }
              />
              <KV
                label="AI / HMAC keys"
                value={
                  <span className="text-xs text-muted-foreground">
                    AI: <span className={providerSummary.aiReady ? "text-emerald-700 dark:text-emerald-300" : "text-amber-700 dark:text-amber-300"}>
                      {providerSummary.aiReady ? "hazır" : "hazır değil"}
                    </span>{" "}
                    · HMAC: <span className={providerSummary.hmacReady ? "text-emerald-700 dark:text-emerald-300" : "text-amber-700 dark:text-amber-300"}>
                      {providerSummary.hmacReady ? "mevcut" : "eksik"}
                    </span>
                  </span>
                }
              />
            </>
          ) : null}
        </CardContent>
      </Card>

      <Card className="border border-border shadow-sm">
        <CardHeader>
          <CardTitle className="text-sm">
            <span className="inline-flex items-center gap-2">
              <Server className="h-4 w-4 text-blue-600" />
              Copyable commands
            </span>
          </CardTitle>
          <CardDescription className="text-xs">
            Genel proje çalıştırma komutları. Placeholder dosya yollarını kendi yollarınızla
            değiştirin; komutların kendisinde secrets bulunmaz.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <CmdRow label="Backend’i başlat (FastAPI)" cmd={cmds.backendStart} />
          <CmdRow label="Frontend’i başlat (Next.js)" cmd={cmds.frontendStart} />
          <CmdRow label="Health check" cmd={cmds.healthCurl} />
          <CmdRow label="Sweep (curl şablonu)" cmd={cmds.sweepCurl} multiline />
        </CardContent>
      </Card>
    </div>
  );
}

function KV({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-md border border-border bg-card px-3 py-2">
      <div className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-1">{value}</div>
    </div>
  );
}

function HealthBadge({ healthy }: { healthy: boolean | null }) {
  if (healthy === null) {
    return (
      <Badge variant="outline" className="gap-1">
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
      >
        <CheckCircle2 className="h-3 w-3" />
        Erişilebilir
      </Badge>
    );
  }
  return (
    <Badge
      variant="outline"
      className="gap-1 border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-300"
    >
      <AlertTriangle className="h-3 w-3" />
      Erişilemez
    </Badge>
  );
}

function CmdRow({
  label,
  cmd,
  multiline,
}: {
  label: string;
  cmd: string;
  multiline?: boolean;
}) {
  const [copied, setCopied] = React.useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };
  return (
    <div className="rounded-md border border-border bg-muted/30 p-2.5">
      <div className="mb-1.5 flex items-center justify-between">
        <span className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</span>
        <Button variant="ghost" size="sm" onClick={onCopy} className="h-7 gap-1 px-2 text-xs">
          {copied ? (
            <>
              <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
              Kopyalandı
            </>
          ) : (
            <>
              <Copy className="h-3.5 w-3.5" />
              Kopyala
            </>
          )}
        </Button>
      </div>
      <pre
        className={`overflow-auto rounded bg-background/60 p-2 font-mono text-[11px] leading-relaxed text-foreground/90 ${
          multiline ? "whitespace-pre" : "whitespace-pre-wrap"
        }`}
      >
        {cmd}
      </pre>
    </div>
  );
}
