// frontend/lib/history.ts
// Local-only run history. Stores **only** safe summary metadata in
// localStorage. No raw logs, no uploaded file content, no IOC values,
// no provider responses, no secrets.

import type { OutputMode, Severity, SweepResponse } from "@/lib/api";

export const HISTORY_STORAGE_KEY = "tic-run-history-v1";
export const HISTORY_MAX = 5;

export interface RunHistoryEntry {
  id: string;
  timestamp: string;
  finding_count: number;
  severity_counts: Record<Severity, number>;
  output_mode: OutputMode | string;
  fail_on: Severity;
  above_threshold: boolean;
  exit_code: number;
  partial_scan: boolean;
  ai_attempted: boolean;
  ai_active: boolean;
  unique_ioc_types: number;
  unique_providers: number;
}

function safeRandomId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

export function summarize(
  res: SweepResponse,
  failOn: Severity,
): RunHistoryEntry {
  const counts: Record<Severity, number> = {
    info: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };
  const types = new Set<string>();
  const providers = new Set<string>();
  for (const f of res.findings) {
    counts[f.severity] += 1;
    types.add(f.ioc_type);
    for (const e of f.enrichments) providers.add(e.provider);
  }
  return {
    id: safeRandomId(),
    timestamp: new Date().toISOString(),
    finding_count: res.finding_count,
    severity_counts: counts,
    output_mode: res.output_mode ?? "analyst",
    fail_on: failOn,
    above_threshold: res.above_threshold,
    exit_code: res.exit_code,
    partial_scan: res.partial_scan,
    ai_attempted: res.ai_attempted,
    ai_active: res.ai_active,
    unique_ioc_types: types.size,
    unique_providers: providers.size,
  };
}

function _looksLikeEntry(x: unknown): x is RunHistoryEntry {
  if (!x || typeof x !== "object") return false;
  const e = x as Record<string, unknown>;
  return (
    typeof e.id === "string" &&
    typeof e.timestamp === "string" &&
    typeof e.finding_count === "number" &&
    typeof e.severity_counts === "object" && e.severity_counts !== null &&
    typeof e.output_mode === "string" &&
    typeof e.fail_on === "string" &&
    typeof e.above_threshold === "boolean" &&
    typeof e.exit_code === "number"
  );
}

export function loadHistory(): RunHistoryEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    // Validate each entry's shape — skip malformed ones from older versions
    // instead of letting a corrupt entry crash the dashboard at render time.
    return parsed.filter(_looksLikeEntry).slice(0, HISTORY_MAX);
  } catch {
    return [];
  }
}

export function appendHistory(
  current: RunHistoryEntry[],
  entry: RunHistoryEntry,
): RunHistoryEntry[] {
  const next = [entry, ...current].slice(0, HISTORY_MAX);
  saveHistory(next);
  return next;
}

export function saveHistory(entries: RunHistoryEntry[]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(
      HISTORY_STORAGE_KEY,
      JSON.stringify(entries.slice(0, HISTORY_MAX)),
    );
  } catch {
    // localStorage may be disabled / quota exceeded — fail silently;
    // history is a convenience, not a requirement.
  }
}

export function clearHistory(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(HISTORY_STORAGE_KEY);
  } catch {
    // ignore
  }
}
