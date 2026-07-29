"use client";

import * as React from "react";
import { Download, FileText } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  findingsToCsv,
  findingsToJson,
  findingsToMarkdown,
  type PublicFinding,
  type SweepResponse,
} from "@/lib/api";
import {
  buildExecutiveSummary,
  executiveSummaryToMarkdown,
} from "@/lib/report";

interface Props {
  result: SweepResponse | null;
  findings: PublicFinding[];        // visible (filtered) findings — what gets exported
  totalFindings: number;            // unfiltered total
  filtered: boolean;
}

export function ExportPanel({ result, findings, totalFindings, filtered }: Props) {
  const disabled = findings.length === 0;
  return (
    <Card className="border border-border shadow-sm">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Exports</CardTitle>
        <CardDescription className="text-xs">
          Şu anda gösterilen public-safe findings’i tam IOC değerleriyle indirin. Raw logs, raw
          provider responses ve secrets değerleri export dosyalarına dahil edilmez; CSV hücreleri
          formula injection’a karşı korunur.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="rounded-md border border-border bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
          {filtered ? (
            <>
              Toplam {totalFindings} finding içinden{" "}
              <span className="font-medium text-foreground">{findings.length}</span>{" "}
              filtrelenmiş finding export edilecek.
            </>
          ) : (
            <>
              <span className="font-medium text-foreground">{findings.length}</span>{" "}
              finding export edilecek.
            </>
          )}
        </div>
        {disabled ? (
          <div className="rounded-md border border-dashed border-border p-4 text-center text-xs text-muted-foreground">
            Export edilecek finding bulunmuyor.
          </div>
        ) : (
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                downloadBlob(
                  findingsToJson(result, findings),
                  "findings.json",
                  "application/json",
                )
              }
            >
              <Download className="mr-1.5 h-4 w-4" /> JSON
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                downloadBlob(findingsToCsv(findings), "findings.csv", "text/csv")
              }
            >
              <Download className="mr-1.5 h-4 w-4" /> CSV
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                downloadBlob(
                  findingsToMarkdown(findings),
                  "findings.md",
                  "text/markdown",
                )
              }
            >
              <Download className="mr-1.5 h-4 w-4" /> Markdown
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                downloadBlob(
                  executiveSummaryToMarkdown(
                    buildExecutiveSummary(findings, {
                      aboveThreshold: result?.above_threshold ?? false,
                      aiActive: result?.ai_active ?? false,
                      partialScan: result?.partial_scan ?? false,
                    }),
                  ),
                  "executive_summary.md",
                  "text/markdown",
                )
              }
            >
              <FileText className="mr-1.5 h-4 w-4" /> Executive summary (yönetici özeti)
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function downloadBlob(text: string, filename: string, mime: string) {
  const blob = new Blob([text], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
