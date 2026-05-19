"use client";

import * as React from "react";
import { AlertTriangle, Loader2 } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AIAdvisoryBanner } from "@/components/ai-advisory-banner";
import { API_BASE, type SweepResponse } from "@/lib/api";

interface Props {
  loading: boolean;
  error: string | null;
  healthy: boolean | null;
  result: SweepResponse | null;
}

/**
 * Aggregated banner stack shown above every section: sweep loading,
 * backend reachability, sweep error, partial-scan warning, AI failure
 * warning, and (when AI is active) the AI advisory banner.
 *
 * Replaces the inline `StatusAlerts` previously defined in page.tsx so
 * the same banners can be reused after we split sections into separate
 * files in a later phase.
 */
export function SweepStatusStrip({ loading, error, healthy, result }: Props) {
  const aiAttemptedButFailed = !!result?.ai_attempted && !result.ai_active;
  return (
    <div className="space-y-2">
      {loading ? (
        <Alert className="border-blue-200 bg-blue-50 dark:border-blue-900/60 dark:bg-blue-950/30">
          <Loader2 className="h-4 w-4 animate-spin text-blue-600 dark:text-blue-300" />
          <AlertTitle className="text-blue-800 dark:text-blue-100">Sweep çalışıyor…</AlertTitle>
          <AlertDescription className="text-blue-700 dark:text-blue-200/90">
            Korelasyon, enrichment ve scoring işlemleri lokal backend üzerinde çalışıyor. Büyük
            log dosyalarında bu işlem birkaç saniye sürebilir.
          </AlertDescription>
        </Alert>
      ) : null}
      {healthy === false ? (
        <Alert className="border-amber-200 bg-amber-50 dark:border-amber-900/60 dark:bg-amber-950/30">
          <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-300" />
          <AlertTitle className="text-amber-800 dark:text-amber-100">Backend erişilemez</AlertTitle>
          <AlertDescription className="text-amber-700 dark:text-amber-200/90">
            <code className="font-mono">{API_BASE}</code> adresine ulaşılamadı. FastAPI backend’ini
            başlatın (bkz. Diagnostics → Copyable commands) ve yeniden deneyin.
          </AlertDescription>
        </Alert>
      ) : null}
      {error ? (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Sweep başarısız</AlertTitle>
          <AlertDescription>
            {error} Nedeninden emin değilseniz, format rehberi için <strong>Inputs</strong> sekmesini açın.
          </AlertDescription>
        </Alert>
      ) : null}
      {result?.partial_scan ? (
        <Alert className="border-amber-200 bg-amber-50 dark:border-amber-900/60 dark:bg-amber-950/30">
          <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-300" />
          <AlertTitle className="text-amber-800 dark:text-amber-100">Kısmi tarama</AlertTitle>
          <AlertDescription className="text-amber-700 dark:text-amber-200/90">
            Log dosyası satır limitine ulaşıldığı için kısmen tarandı. Sonuçlar eksik olabilir.
          </AlertDescription>
        </Alert>
      ) : null}
      {aiAttemptedButFailed ? (
        <Alert className="border-amber-200 bg-amber-50 dark:border-amber-900/60 dark:bg-amber-950/30">
          <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-300" />
          <AlertTitle className="text-amber-800 dark:text-amber-100">AI narration kullanılamıyor</AlertTitle>
          <AlertDescription className="text-amber-700 dark:text-amber-200/90">
            AI talep edildi ancak narrator başlatılamadı (keyring key eksik ya da settings içinde
            devre dışı). Sweep, AI olmadan tamamlandı.
          </AlertDescription>
        </Alert>
      ) : null}
      <AIAdvisoryBanner active={!!result?.ai_active} />
    </div>
  );
}
