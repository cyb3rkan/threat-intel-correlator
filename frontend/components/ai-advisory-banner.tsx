"use client";

import * as React from "react";
import { Sparkles } from "lucide-react";

import { cn } from "@/lib/utils";

interface Props {
  // Only renders when AI narration is active on the current sweep.
  active: boolean;
  className?: string;
}

/**
 * Visible, role=status ribbon shown whenever the current sweep contains
 * AI-generated narrative. The label is intentionally explicit: AI output
 * is advisory only and must be reviewed before any analyst action.
 *
 * The banner never renders AI text itself — it only signals presence and
 * disposition. The actual narrative is rendered (as plain text) inside
 * each finding's detail panel.
 */
export function AIAdvisoryBanner({ active, className }: Props) {
  if (!active) return null;
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        "flex items-start gap-2 rounded-md border border-amber-300/70 bg-amber-50 px-3 py-2 text-amber-900",
        "dark:border-amber-700/60 dark:bg-amber-950/40 dark:text-amber-100",
        className,
      )}
    >
      <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-300" aria-hidden="true" />
      <div className="text-xs leading-relaxed">
        <span className="font-semibold uppercase tracking-wide">
          AI-generated · review required
        </span>
        <span className="ml-1 text-amber-800/90 dark:text-amber-100/85">
          AI narrative yalnızca analyst incelemesi için bir öneridir. Aksiyon
          almadan önce eşleşmeleri, provider verilerini ve log bağlamını
          bağımsız olarak doğrulayın. Hiçbir AI çıktısı otomatik karar
          mercii olarak değerlendirilmemelidir.
        </span>
      </div>
    </div>
  );
}
