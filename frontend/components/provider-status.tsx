"use client";

import * as React from "react";
import {
  CheckCircle2,
  AlertTriangle,
  KeyRound,
  ShieldOff,
  Plug,
  Globe,
  Lock,
  CircleDashed,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  PROVIDER_REASON_LABEL,
  type EndpointKind,
  type ProviderReason,
  type ProviderStatusEntry,
  type ProviderStatusResponse,
} from "@/lib/api";

interface Props {
  status: ProviderStatusResponse | null;
  loading: boolean;
}

export function ProviderStatusGrid({ status, loading }: Props) {
  if (loading && !status) {
    return (
      <Card className="border border-border shadow-sm">
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          <CircleDashed className="mx-auto mb-2 h-5 w-5 animate-spin text-muted-foreground" />
          Provider status yükleniyor…
        </CardContent>
      </Card>
    );
  }
  if (!status) {
    return (
      <Card className="border border-border shadow-sm">
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          Provider status kullanılamıyor. Backend erişilebilir mi?
        </CardContent>
      </Card>
    );
  }
  const readyCount = status.providers.filter((p) => p.ready).length;
  return (
    <Card className="border border-border shadow-sm">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div>
            <CardTitle className="text-sm">Provider readiness</CardTitle>
            <CardDescription className="text-xs">
              Toplam {status.providers.length} provider içinden {readyCount} tanesi hazır. Secrets,
              tam URL değerleri veya keyring tanımlayıcıları burada gösterilmez; yalnızca güvenli
              metadata gösterilir.
            </CardDescription>
          </div>
          <Badge
            variant="outline"
            className={
              readyCount > 0
                ? "gap-1 border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-300"
                : "gap-1 border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-300"
            }
            title={`${readyCount}/${status.providers.length}`}
          >
            <CheckCircle2 className="h-3 w-3" />
            {readyCount}/{status.providers.length} hazır
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {status.providers.map((p) => (
            <ProviderCard key={p.name} entry={p} />
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

function ProviderCard({ entry }: { entry: ProviderStatusEntry }) {
  const reasonKey = entry.reason as ProviderReason;
  const reasonLabel = PROVIDER_REASON_LABEL[reasonKey] ?? entry.reason;
  return (
    <li className="rounded-md border border-border bg-card p-3">
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="text-sm font-medium text-foreground">{entry.name}</span>
        <ReadyBadge ready={entry.ready} />
      </div>
      <div className="mb-2 flex flex-wrap gap-1.5 text-[11px] text-muted-foreground">
        <BoolPill label="configured" value={entry.configured} />
        <BoolPill label="enabled" value={entry.enabled} />
        <KeyPill present={entry.key_present} />
        <EndpointPill kind={entry.endpoint_kind} />
      </div>
      <div className="text-[11px] text-muted-foreground">
        <span className="font-medium text-foreground/80">Durum:</span> {reasonLabel}
      </div>
      {entry.supported_ioc_types.length > 0 ? (
        <div className="mt-2 flex flex-wrap gap-1">
          {entry.supported_ioc_types.map((t) => (
            <Badge key={t} variant="secondary" className="font-mono text-[10px]">
              {t}
            </Badge>
          ))}
        </div>
      ) : null}
    </li>
  );
}

function ReadyBadge({ ready }: { ready: boolean }) {
  return ready ? (
    <Badge
      variant="outline"
      className="gap-1 border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-300"
    >
      <CheckCircle2 className="h-3 w-3" />
      Hazır
    </Badge>
  ) : (
    <Badge
      variant="outline"
      className="gap-1 border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900/60 dark:bg-amber-950/40 dark:text-amber-300"
    >
      <AlertTriangle className="h-3 w-3" />
      Hazır değil
    </Badge>
  );
}

function BoolPill({ label, value }: { label: string; value: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 ${
        value
          ? "border-border bg-muted/40 text-foreground/80"
          : "border-border bg-muted/20 text-muted-foreground/70 line-through"
      }`}
    >
      {label}
    </span>
  );
}

function KeyPill({ present }: { present: boolean }) {
  return present ? (
    <span className="inline-flex items-center gap-1 rounded border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-emerald-700 dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-300">
      <KeyRound className="h-3 w-3" />
      key
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded border border-border bg-muted/30 px-1.5 py-0.5 text-muted-foreground">
      <ShieldOff className="h-3 w-3" />
      no key
    </span>
  );
}

function EndpointPill({ kind }: { kind: EndpointKind }) {
  if (kind === "public") {
    return (
      <span className="inline-flex items-center gap-1 rounded border border-border bg-muted/40 px-1.5 py-0.5 text-foreground/80">
        <Globe className="h-3 w-3" />
        public
      </span>
    );
  }
  if (kind === "internal") {
    return (
      <span className="inline-flex items-center gap-1 rounded border border-border bg-muted/40 px-1.5 py-0.5 text-foreground/80">
        <Lock className="h-3 w-3" />
        internal
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded border border-border bg-muted/20 px-1.5 py-0.5 text-muted-foreground/70">
      <Plug className="h-3 w-3" />
      none
    </span>
  );
}
