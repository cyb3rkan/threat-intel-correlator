"use client";

import * as React from "react";
import { ArrowRight, Inbox, Lock, ListChecks, Sparkles } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { SEVERITY_GLYPH, SEVERITY_LABEL, SEVERITY_TONE } from "@/lib/severity";
import { prioritize } from "@/lib/priority";
import { isHashedIoc, truncateIoc } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { PublicFinding } from "@/lib/api";

interface Props {
  findings: PublicFinding[];
  // Default 5; consumers can override but the value is clamped to >=0.
  limit?: number;
  // Called when the analyst clicks a row or the "Tümünü gör" CTA.
  // `id === null` means "go to findings without selecting anything".
  onOpen: (id: string | null) => void;
}

/**
 * Overview "what should I look at first?" queue. Renders the top N
 * findings by (severity rank desc, score desc, finding_id asc).
 *
 * Hash-mode safety: the displayed IOC value is whatever the backend
 * returned — for output_mode=hash that is `hmac:<hex>`. We only truncate
 * for layout; we never decode or normalize. A small lock icon hints when
 * the value is a pseudonym.
 *
 * AI safety: a sparkle icon flags rows that carry an AI narrative, but
 * the narrative text itself is NOT rendered here — only its presence.
 */
export function PriorityQueue({ findings, limit = 5, onOpen }: Props) {
  const top = React.useMemo(() => prioritize(findings, Math.max(0, limit)), [findings, limit]);

  return (
    <Card className="border border-border shadow-sm">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div>
            <CardTitle className="text-sm">
              <span className="inline-flex items-center gap-2">
                <ListChecks className="h-4 w-4 text-blue-600 dark:text-blue-300" />
                Triage queue · top {top.length || limit}
              </span>
            </CardTitle>
            <CardDescription className="text-xs">
              Severity ve score’a göre öncelikli findings. AI önerileri yalnızca tavsiyedir;
              aksiyon almadan önce eşleşmeleri analyst incelemesinden geçirin.
            </CardDescription>
          </div>
          {findings.length > top.length ? (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => onOpen(null)}
              aria-label="Tüm findings’i görüntüle"
              className="text-xs"
            >
              Tümünü gör
              <ArrowRight className="ml-1 h-3.5 w-3.5" />
            </Button>
          ) : null}
        </div>
      </CardHeader>
      <CardContent>
        {top.length === 0 ? (
          <div className="flex flex-col items-center gap-2 rounded-md border border-dashed border-border p-6 text-center text-xs text-muted-foreground">
            <Inbox className="h-5 w-5 text-muted-foreground/80" />
            <div>
              Henüz triage edilecek finding yok. Sweep çalıştırıldığında en yüksek öncelikli
              kayıtlar burada görünür.
            </div>
          </div>
        ) : (
          <ul className="space-y-2">
            {top.map((f, i) => (
              <PriorityRow
                key={f.finding_id}
                rank={i + 1}
                finding={f}
                onOpen={() => onOpen(f.finding_id)}
              />
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

function PriorityRow({
  rank,
  finding,
  onOpen,
}: {
  rank: number;
  finding: PublicFinding;
  onOpen: () => void;
}) {
  const tone = SEVERITY_TONE[finding.severity];
  const hashed = isHashedIoc(finding.ioc_value);
  // 56 chars keeps layout stable on lg+ screens; truncateIoc preserves
  // head and tail so analysts still recognize the value.
  const display = truncateIoc(finding.ioc_value, 56);

  return (
    <li>
      <button
        type="button"
        onClick={onOpen}
        aria-label={`Finding ${finding.finding_id.slice(0, 8)} aç, severity ${finding.severity}, score ${finding.score}`}
        className={cn(
          "group flex w-full items-center gap-3 rounded-md border border-border bg-card px-3 py-2 text-left",
          "transition-colors hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        )}
      >
        <span className="w-5 shrink-0 text-center font-mono text-[11px] tabular-nums text-muted-foreground">
          {rank}
        </span>
        <Badge
          variant="outline"
          className={cn("shrink-0 gap-1 border", tone.badge)}
          aria-label={`severity ${finding.severity}`}
        >
          <span aria-hidden="true">{SEVERITY_GLYPH[finding.severity]}</span>
          {SEVERITY_LABEL[finding.severity]}
        </Badge>
        <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
          score <span className={cn("font-semibold", tone.text)}>{finding.score}</span>
        </span>
        <span className="shrink-0 font-mono text-[11px] text-muted-foreground">
          {finding.ioc_type}
        </span>
        <span
          className="flex min-w-0 flex-1 items-center gap-1 truncate font-mono text-xs text-foreground"
          title={hashed ? "hmac pseudonym (hash mode)" : finding.ioc_value}
        >
          {hashed ? (
            <Lock
              className="h-3 w-3 shrink-0 text-emerald-600 dark:text-emerald-300"
              aria-label="pseudonymized (hash mode)"
            />
          ) : null}
          <span className="truncate">{display}</span>
        </span>
        <span className="hidden items-center gap-1.5 text-[11px] text-muted-foreground sm:inline-flex">
          {finding.enrichments.length > 0 ? (
            <span title="enrichment provider sayısı">
              {finding.enrichments.length} prov
            </span>
          ) : null}
          {finding.ai_narrative ? (
            <Sparkles
              className="h-3 w-3 text-amber-600 dark:text-amber-300"
              aria-label="AI narrative present (advisory only)"
            />
          ) : null}
        </span>
        <ArrowRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
      </button>
    </li>
  );
}
