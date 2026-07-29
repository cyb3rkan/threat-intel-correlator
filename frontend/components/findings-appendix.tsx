"use client";

import * as React from "react";
import { ArrowRight, FileSearch, Lock, Sparkles } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { SEVERITY_GLYPH, SEVERITY_LABEL, SEVERITY_RANK, SEVERITY_TONE } from "@/lib/severity";
import { prioritize } from "@/lib/priority";
import { isHashedIoc, truncateIoc } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { PublicFinding, Severity } from "@/lib/api";

interface Props {
  findings: PublicFinding[];
  // Called when an appendix card is opened. The host page is responsible
  // for switching to the Findings tab and selecting the finding.
  onOpen: (id: string) => void;
  // Cap how many findings to show. Default 25 keeps the report readable;
  // analysts can still get the full list via export.
  limit?: number;
}

/**
 * Report appendix listing the most relevant findings. Defaults to
 * severity >= medium ordered by priority. If a sweep produced only
 * low/info findings, the appendix falls back to those without raising
 * any visual alarm.
 *
 * Hash-mode safety: `ioc_value` is rendered exactly as the backend
 * returned it. In hash mode that is `hmac:<hex>`; a lock icon
 * communicates pseudonymization. There is no decode step.
 *
 * Markdown is not rendered; no HTML-injection sinks are used; no raw
 * provider payloads are surfaced.
 */
export function FindingsAppendix({ findings, onOpen, limit = 25 }: Props) {
  const { rows, mode } = React.useMemo(() => selectAppendixRows(findings, limit), [findings, limit]);

  return (
    <Card className="border border-border shadow-sm">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">
          <span className="inline-flex items-center gap-2">
            <FileSearch className="h-4 w-4 text-blue-600 dark:text-blue-300" />
            Findings appendix
          </span>
        </CardTitle>
        <CardDescription className="text-xs [overflow-wrap:anywhere]">
          {mode === "empty"
            ? "Bu sweep için finding üretilmedi."
            : mode === "medium-plus"
              ? `Severity medium ve üzeri findings · ilk ${rows.length} kayıt`
              : `Bu sweep yalnızca low/info severity findings içeriyor · ilk ${rows.length} kayıt`}
          {mode === "medium-plus" ? (
            <span className="ml-1 text-muted-foreground/80">
              (low/info kayıtlar için Findings sekmesindeki filtreleri kullanın)
            </span>
          ) : null}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {mode === "empty" ? (
          <div className="rounded-md border border-dashed border-border p-4 text-center text-xs text-muted-foreground">
            Appendix’te gösterilecek finding bulunmuyor.
          </div>
        ) : (
          <ul className="space-y-2">
            {rows.map((f) => (
              <AppendixRow key={f.finding_id} finding={f} onOpen={() => onOpen(f.finding_id)} />
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

type AppendixMode = "empty" | "medium-plus" | "low-only";

function selectAppendixRows(
  findings: PublicFinding[],
  limit: number,
): { rows: PublicFinding[]; mode: AppendixMode } {
  if (findings.length === 0) return { rows: [], mode: "empty" };
  const mediumPlus = findings.filter(
    (f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK["medium" as Severity],
  );
  if (mediumPlus.length > 0) {
    return { rows: prioritize(mediumPlus, Math.max(0, limit)), mode: "medium-plus" };
  }
  return { rows: prioritize(findings, Math.max(0, limit)), mode: "low-only" };
}

function AppendixRow({
  finding,
  onOpen,
}: {
  finding: PublicFinding;
  onOpen: () => void;
}) {
  const tone = SEVERITY_TONE[finding.severity];
  const hashed = isHashedIoc(finding.ioc_value);
  const display = truncateIoc(finding.ioc_value, 64);

  return (
    <li>
      <div
        className={cn(
          "min-w-0 rounded-md border border-border bg-card p-2.5",
          "transition-colors hover:bg-muted/30 focus-within:bg-muted/30",
        )}
      >
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <Badge
            variant="outline"
            className={cn("gap-1 border", tone.badge)}
            aria-label={`severity ${finding.severity}`}
          >
            <span aria-hidden="true">{SEVERITY_GLYPH[finding.severity]}</span>
            {SEVERITY_LABEL[finding.severity]}
          </Badge>
          <span className="text-xs tabular-nums text-muted-foreground">
            score{" "}
            <span className={cn("font-semibold", tone.text)}>{finding.score}</span>
          </span>
          <Badge
            variant="outline"
            className="border-border bg-muted/40 font-mono text-[11px] text-foreground/85"
          >
            {finding.ioc_type}
          </Badge>
          <div className="ml-auto flex items-center gap-1.5">
            {finding.enrichments.length > 0 ? (
              <span
                className="text-[11px] text-muted-foreground"
                title="enrichment provider sayısı"
              >
                {finding.enrichments.length} prov
              </span>
            ) : null}
            {finding.ai_narrative ? (
              <Badge
                variant="outline"
                className="gap-1 border-amber-200 bg-amber-50 text-[10px] text-amber-800 dark:border-amber-800/70 dark:bg-amber-950/40 dark:text-amber-200"
                title="AI narrative present — advisory only"
              >
                <Sparkles className="h-2.5 w-2.5" />
                AI
              </Badge>
            ) : null}
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2"
              onClick={onOpen}
              aria-label={`Finding ${finding.finding_id.slice(0, 8)} aç`}
            >
              <span className="text-[11px]">Aç</span>
              <ArrowRight className="ml-1 h-3 w-3" />
            </Button>
          </div>
        </div>
        <div className="mt-1.5 flex min-w-0 items-start gap-1.5 font-mono text-xs">
          {hashed ? (
            <Lock
              className="mt-0.5 h-3 w-3 shrink-0 text-emerald-600 dark:text-emerald-300"
              aria-label="pseudonymized (hash mode)"
            />
          ) : null}
          <span
            className="min-w-0 flex-1 truncate text-foreground"
            title={hashed ? "hmac pseudonym (hash mode)" : finding.ioc_value}
          >
            {display}
          </span>
        </div>
        {finding.ioc_source ? (
          <div className="mt-1 text-[10.5px] text-muted-foreground [overflow-wrap:anywhere]">
            source: {finding.ioc_source}
          </div>
        ) : null}
      </div>
    </li>
  );
}
