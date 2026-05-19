"use client";

import * as React from "react";
import {
  Sparkles,
  Lock,
  Clipboard,
  ClipboardCheck,
  ShieldAlert,
  Hash,
  Link2,
  Clock,
  Database,
  Tag,
  Activity,
  ListChecks,
  Code2,
  Info,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { OutputModePill } from "@/components/output-mode-pill";
import { cn } from "@/lib/utils";
import { SEVERITY_GLYPH, SEVERITY_LABEL, SEVERITY_TONE } from "@/lib/severity";
import { isHashedIoc, formatTimestamp } from "@/lib/format";
import { useClipboard } from "@/hooks/use-clipboard";
import type { AINarrative, PublicFinding } from "@/lib/api";

interface Props {
  finding: PublicFinding | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/**
 * Right-side analyst report card. Wraps shadcn Sheet so we get focus
 * trapping, ESC-to-close, and an overlay for free.
 *
 * Width:
 *   - Desktop  → ~520px (sm:max-w-[520px])
 *   - Mobile   → full screen (max-w-full)
 *
 * Overflow:
 *   - The drawer is a vertical flex container; the scrollable region is
 *     a single child div with overflow-y:auto + overflow-x:hidden. We
 *     do NOT use ScrollArea here because its inner viewport can race
 *     with long monospace content and force a horizontal scrollbar at
 *     the page level.
 *   - Every text container along the wrapping path carries min-w-0 so
 *     long IOC values, AI summaries, and JSON blocks never push the
 *     drawer wider than its column.
 *   - The public-safe JSON code box has its own horizontal scroll; the
 *     drawer itself never scrolls horizontally.
 *
 * Security:
 *   - Reads only the fields the backend already projects onto
 *     PublicFinding / PublicEnrichment / AINarrative. Backend-internal
 *     payloads, secrets, and tracebacks are never available to this
 *     component and are never rendered.
 *   - AI narrative is shown verbatim as plain text inside a labeled,
 *     amber-bordered region with "AI-generated · review required". No
 *     markdown rendering; no HTML-injection sinks are used anywhere.
 *   - Hash mode (output_mode === "hash", or any value starting with
 *     "hmac:") shows a lock icon next to the IOC value. The value is
 *     printed exactly as the backend returned it — no decode step, no
 *     normalization.
 *   - The clipboard helper only stringifies the typed PublicFinding
 *     argument; nothing else is attached.
 */
export function FindingsDetailDrawer({ finding, open, onOpenChange }: Props) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className={cn(
          // Override shadcn defaults: full-width on mobile, ~520px desktop.
          // overflow-hidden on the shell prevents any inner child from
          // contributing horizontal scroll to the page.
          "flex w-full max-w-full flex-col gap-0 overflow-hidden p-0 sm:max-w-[520px]",
        )}
      >
        {finding ? <DetailBody finding={finding} /> : <EmptyBody />}
      </SheetContent>
    </Sheet>
  );
}

function EmptyBody() {
  return (
    <>
      <SheetHeader className="pr-12">
        <SheetTitle className="text-sm">Finding detayları</SheetTitle>
        <SheetDescription className="text-xs">
          Detayları görüntülemek için Findings tablosundan veya Overview’deki triage queue’den bir
          satır seçin.
        </SheetDescription>
      </SheetHeader>
      <div className="flex flex-1 items-center justify-center p-8 text-center text-sm text-muted-foreground">
        Henüz bir finding seçilmedi.
      </div>
    </>
  );
}

function DetailBody({ finding }: { finding: PublicFinding }) {
  const tone = SEVERITY_TONE[finding.severity];
  const hashed = isHashedIoc(finding.ioc_value);
  const isLowSeverity = finding.severity === "info" || finding.severity === "low";

  return (
    <>
      {/* SheetContent renders an absolute close button at top-right; we
          reserve pr-12 on the header so badges/title don't overlap it. */}
      <SheetHeader className="min-w-0 border-b border-border pr-12">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <Badge
            variant="outline"
            className={cn("gap-1 border", tone.badge)}
            aria-label={`severity ${finding.severity}`}
          >
            <span aria-hidden="true">{SEVERITY_GLYPH[finding.severity]}</span>
            {SEVERITY_LABEL[finding.severity]}
          </Badge>
          <span className="text-xs text-muted-foreground">
            Score{" "}
            <span className={cn("font-semibold tabular-nums", tone.text)}>
              {finding.score}
            </span>
          </span>
          <Badge
            variant="outline"
            className="gap-1 border-border bg-muted/40 font-mono text-[11px] text-foreground/85"
          >
            {finding.ioc_type}
          </Badge>
          <OutputModePill mode={finding.output_mode ?? null} compact />
        </div>
        <SheetTitle
          className={cn(
            "mt-1 flex min-w-0 items-start gap-1.5 font-mono text-sm",
            // overflow-wrap:anywhere is the strongest wrapping mode for
            // long unbroken strings (hashes, URLs); paired with break-all
            // it guarantees no horizontal overflow.
            "[overflow-wrap:anywhere] break-all",
          )}
        >
          {hashed ? (
            <Lock
              className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-600 dark:text-emerald-300"
              aria-label="pseudonymized (hash mode)"
            />
          ) : null}
          <span className="min-w-0 flex-1 [overflow-wrap:anywhere] break-all">
            {finding.ioc_value}
          </span>
        </SheetTitle>
        <SheetDescription className="text-[11px] [overflow-wrap:anywhere]">
          Public-safe analyst kartı · raw logs, raw provider payloads ve secrets değerleri buraya
          dahil edilmez.
        </SheetDescription>
      </SheetHeader>

      {/* Single scroll region: vertical only. overflow-x-hidden keeps any
          inner overflowing child (e.g. long JSON line) from stretching
          the drawer width. */}
      <div className="min-h-0 min-w-0 flex-1 overflow-y-auto overflow-x-hidden">
        <div className="min-w-0 space-y-5 p-4 pb-8">
          <RiskSummary finding={finding} />
          <ProviderEvidence finding={finding} />
          {finding.ai_narrative ? (
            <AISection narrative={finding.ai_narrative} muted={isLowSeverity} />
          ) : null}
          <PublicSafeJsonSection finding={finding} />
        </div>
      </div>
    </>
  );
}

function RiskSummary({ finding }: { finding: PublicFinding }) {
  return (
    <section aria-labelledby="risk-summary-h" className="min-w-0">
      <h3
        id="risk-summary-h"
        className="mb-2 inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground"
      >
        <Activity className="h-3 w-3" />
        Risk özeti
      </h3>
      <div className="grid grid-cols-2 gap-2">
        <Stat
          icon={<ShieldAlert className="h-3 w-3" />}
          label="Eşleşme"
          value={String(finding.match_count)}
        />
        <Stat
          icon={<Activity className="h-3 w-3" />}
          label="IOC confidence"
          value={String(finding.ioc_confidence)}
        />
        <Stat
          icon={<Database className="h-3 w-3" />}
          label="Source"
          value={finding.ioc_source || "—"}
          wrap
        />
        <Stat
          icon={<Clock className="h-3 w-3" />}
          label="Oluşturulma"
          value={formatTimestamp(finding.created_at)}
        />
        <Stat
          icon={<Link2 className="h-3 w-3" />}
          label="Correlation ID"
          value={truncateId(finding.correlation_id)}
          mono
          title={finding.correlation_id}
        />
        <Stat
          icon={<Hash className="h-3 w-3" />}
          label="Finding ID"
          value={truncateId(finding.finding_id)}
          mono
          title={finding.finding_id}
        />
      </div>
      {finding.ioc_tags.length ? (
        <div className="mt-3 min-w-0">
          <div className="mb-1.5 inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
            <Tag className="h-3 w-3" />
            IOC tags
          </div>
          <div className="flex flex-wrap gap-1">
            {finding.ioc_tags.map((t) => (
              <Badge
                key={t}
                variant="secondary"
                className="max-w-full break-all text-[10px] [overflow-wrap:anywhere]"
              >
                {t}
              </Badge>
            ))}
          </div>
        </div>
      ) : null}
    </section>
  );
}

function ProviderEvidence({ finding }: { finding: PublicFinding }) {
  return (
    <section aria-labelledby="provider-evidence-h" className="min-w-0">
      <h3
        id="provider-evidence-h"
        className="mb-2 inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground"
      >
        <Database className="h-3 w-3" />
        Provider kanıtları
      </h3>
      {finding.enrichments.length === 0 ? (
        <div className="rounded-md border border-dashed border-border bg-muted/20 p-3 text-xs text-muted-foreground [overflow-wrap:anywhere]">
          Hiçbir enrichment provider veri döndürmedi. Yapılandırma ayrıntıları için{" "}
          <strong>Providers</strong> sekmesindeki readiness panelini inceleyin.
        </div>
      ) : (
        // overflow-x-auto on the wrapper so a wide table can scroll
        // horizontally INSIDE its own box without stretching the drawer.
        <div className="max-w-full overflow-x-auto overflow-y-hidden rounded-md border border-border">
          <Table>
            <TableHeader>
              <TableRow className="bg-muted/40 hover:bg-muted/40">
                <TableHead className="h-8 text-[11px]">Provider</TableHead>
                <TableHead className="h-8 w-[80px] text-right text-[11px]">
                  Reputation
                </TableHead>
                <TableHead className="h-8 text-[11px]">Tags</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {finding.enrichments.map((e, i) => (
                <TableRow key={`${e.provider}-${i}`}>
                  <TableCell className="py-2 text-xs font-medium [overflow-wrap:anywhere]">
                    {e.provider}
                  </TableCell>
                  <TableCell className="py-2 text-right tabular-nums text-xs text-muted-foreground">
                    {e.reputation_score == null ? "—" : e.reputation_score}
                  </TableCell>
                  <TableCell className="py-2">
                    {e.tags.length === 0 ? (
                      <span className="text-xs text-muted-foreground/70">—</span>
                    ) : (
                      <div className="flex flex-wrap gap-1">
                        {e.tags.map((t) => (
                          <Badge
                            key={t}
                            variant="secondary"
                            className="max-w-full break-all text-[10px] [overflow-wrap:anywhere]"
                          >
                            {t}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      <p className="mt-1.5 text-[10px] leading-relaxed text-muted-foreground/80 [overflow-wrap:anywhere]">
        Raw provider yanıtları backend sınırında bırakılır; UI yalnızca provider adı, reputation
        skoru ve etiketleri görüntüler.
      </p>
    </section>
  );
}

function AISection({
  narrative,
  muted,
}: {
  narrative: AINarrative;
  muted: boolean;
}) {
  return (
    <section aria-labelledby="ai-narrative-h" className="min-w-0">
      <div
        role="group"
        aria-labelledby="ai-narrative-h"
        className={cn(
          "min-w-0 rounded-md border p-3",
          // High-severity findings keep the amber band. Low/info findings
          // use a softer surface so the UI doesn't look urgent.
          muted
            ? "border-border bg-muted/30 text-foreground/90"
            : "border-amber-300/70 bg-amber-50 text-amber-900 dark:border-amber-700/60 dark:bg-amber-950/30 dark:text-amber-100",
        )}
      >
        <h3
          id="ai-narrative-h"
          className={cn(
            "mb-1 inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide",
            muted ? "text-muted-foreground" : "text-amber-800 dark:text-amber-200",
          )}
        >
          <Sparkles className="h-3 w-3" />
          AI-generated · review required
        </h3>
        <p
          className={cn(
            "whitespace-pre-wrap break-words text-xs leading-relaxed [overflow-wrap:anywhere]",
          )}
        >
          {narrative.summary}
        </p>
        <div className="mt-2 flex flex-wrap gap-1.5">
          <MetaPill label="FP olasılığı" value={narrative.false_positive_likelihood} />
          <MetaPill label="Confidence" value={narrative.confidence} />
          <MetaPill label="Model" value={narrative.model} mono />
        </div>
        {narrative.suggested_actions.length ? (
          <div className="mt-3 min-w-0">
            <div
              className={cn(
                "mb-1 inline-flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide",
                muted ? "text-muted-foreground" : "text-amber-800 dark:text-amber-200",
              )}
            >
              <ListChecks className="h-3 w-3" />
              Önerilen (advisory) adımlar
            </div>
            <ul className="list-disc space-y-1 pl-5 text-[11px] leading-relaxed [overflow-wrap:anywhere]">
              {narrative.suggested_actions.map((a, i) => (
                <li key={`${i}-${a.slice(0, 32)}`} className="break-words">
                  {a}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {/* Informational note — AI sees only redacted/pseudonymized input,
            so it may refer to IOC_pseudo. Calm grey styling so it doesn't
            read as a warning. */}
        <div
          className={cn(
            "mt-3 flex items-start gap-1.5 rounded border border-border bg-card/60 px-2 py-1.5",
            "text-[10px] leading-relaxed text-muted-foreground [overflow-wrap:anywhere]",
          )}
        >
          <Info className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
          <span className="min-w-0">
            AI narrative, finding’in redacted / pseudonymized görünümünden üretilir; bu nedenle
            metinde IOC_pseudo gibi yer tutucular geçebilir.
          </span>
        </div>
        <p
          className={cn(
            "mt-2 text-[10px] leading-relaxed [overflow-wrap:anywhere]",
            muted ? "text-muted-foreground/85" : "text-amber-900/85 dark:text-amber-100/80",
          )}
        >
          Bu metin AI tarafından üretilmiştir ve yalnızca tavsiyedir. Aksiyon almadan önce
          eşleşmeleri, provider verilerini ve log bağlamını bağımsız olarak doğrulayın.
        </p>
      </div>
    </section>
  );
}

function PublicSafeJsonSection({ finding }: { finding: PublicFinding }) {
  // JSON.stringify of a typed PublicFinding only — no enrichment with
  // backend-internal fields, no metadata leak.
  const json = React.useMemo(() => JSON.stringify(finding, null, 2), [finding]);
  const { copied, copy } = useClipboard();

  return (
    <section aria-labelledby="public-safe-json-h" className="min-w-0">
      {/* Accordion type="single" collapsible with no defaultValue ⇒ the
          item starts closed. Analysts only see the JSON when they opt in. */}
      <Accordion type="single" collapsible>
        <AccordionItem
          value="public-safe-json"
          className="min-w-0 rounded-md border border-border bg-muted/20"
        >
          <AccordionTrigger
            id="public-safe-json-h"
            className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground hover:no-underline"
          >
            <span className="inline-flex items-center gap-1.5">
              <Code2 className="h-3 w-3" />
              Public-safe JSON
            </span>
          </AccordionTrigger>
          <AccordionContent className="px-3 pb-3">
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <p className="min-w-0 max-w-full break-words text-[10px] leading-relaxed text-muted-foreground/85 [overflow-wrap:anywhere]">
                Yalnızca backend tarafından zaten public projekte edilmiş alanlardır. Raw logs,
                raw provider payloads ve secrets bu nesnede yer almaz.
              </p>
              <Button
                variant="outline"
                size="sm"
                className="h-7 shrink-0"
                onClick={() => {
                  void copy(json);
                }}
                aria-label="Public-safe JSON’u panoya kopyala"
              >
                {copied ? (
                  <>
                    <ClipboardCheck className="mr-1.5 h-3.5 w-3.5 text-emerald-600 dark:text-emerald-300" />
                    Kopyalandı
                  </>
                ) : (
                  <>
                    <Clipboard className="mr-1.5 h-3.5 w-3.5" />
                    JSON’u kopyala
                  </>
                )}
              </Button>
            </div>
            {/* The pre box has its own horizontal scroll (long JSON lines
                are kept readable monospaced); max-w-full + min-w-0 on the
                wrapper ensure that scroll stays INSIDE this box and never
                pushes the drawer wider. */}
            <div className="min-w-0 max-w-full overflow-hidden rounded-md border border-border bg-background/60">
              <pre className="max-h-72 max-w-full overflow-x-auto overflow-y-auto p-2 text-[10.5px] leading-snug text-foreground/90">
                {json}
              </pre>
            </div>
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </section>
  );
}

function Stat({
  icon,
  label,
  value,
  mono,
  wrap,
  title,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  mono?: boolean;
  wrap?: boolean;
  title?: string;
}) {
  return (
    <div className="min-w-0 rounded-md border border-border bg-card px-2.5 py-1.5">
      <div className="inline-flex items-center gap-1 text-[10px] uppercase tracking-wide text-muted-foreground">
        {icon}
        {label}
      </div>
      <div
        className={cn(
          "mt-0.5 text-xs text-foreground",
          mono && "font-mono",
          wrap ? "break-words [overflow-wrap:anywhere]" : "truncate",
        )}
        title={title ?? value}
      >
        {value}
      </div>
    </div>
  );
}

function MetaPill({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <span className="inline-flex max-w-full items-center gap-1 rounded border border-border bg-card px-1.5 py-0.5 text-[10px]">
      <Separator orientation="vertical" className="hidden h-3" />
      <span className="uppercase tracking-wide text-muted-foreground">{label}</span>
      <span
        className={cn("min-w-0 break-words text-foreground/90 [overflow-wrap:anywhere]", mono && "font-mono")}
        title={value}
      >
        {value}
      </span>
    </span>
  );
}

function truncateId(id: string): string {
  if (!id) return "—";
  return id.length <= 16 ? id : `${id.slice(0, 8)}…${id.slice(-4)}`;
}
