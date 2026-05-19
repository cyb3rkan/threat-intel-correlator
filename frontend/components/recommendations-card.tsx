"use client";

import * as React from "react";
import { Lightbulb } from "lucide-react";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { ExecutiveSummary } from "@/lib/report";

interface Props {
  summary: ExecutiveSummary;
}

/**
 * Standalone Overview card for the deterministic recommendation list
 * produced by `buildExecutiveSummary`. Each recommendation is a plain
 * string from a fixed code-path (no markdown render, no HTML, no AI
 * output). Safe to render as React text nodes directly.
 */
export function RecommendationsCard({ summary }: Props) {
  const recs = summary.recommendations;
  return (
    <Card className="border border-border shadow-sm">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">
          <span className="inline-flex items-center gap-2">
            <Lightbulb className="h-4 w-4 text-amber-500 dark:text-amber-300" />
            Önerilen sonraki adımlar
          </span>
        </CardTitle>
        <CardDescription className="text-xs">
          Deterministik kurallarla mevcut sweep özetinden türetildi. AI çıktısı içermez.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {recs.length === 0 ? (
          <div className="rounded-md border border-dashed border-border p-4 text-center text-xs text-muted-foreground">
            Şu an önerilen bir aksiyon yok.
          </div>
        ) : (
          <ol className="space-y-2 text-xs text-foreground/90">
            {recs.map((r, i) => (
              <li
                key={`${i}-${r.slice(0, 24)}`}
                className="flex items-start gap-2 rounded-md border border-border bg-muted/20 px-2.5 py-2"
              >
                <span className="mt-0.5 inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-blue-600/10 text-[10px] font-semibold text-blue-700 dark:bg-blue-500/15 dark:text-blue-200">
                  {i + 1}
                </span>
                <span className="leading-relaxed">{r}</span>
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}
