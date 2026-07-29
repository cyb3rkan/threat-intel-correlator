// frontend/lib/filters.ts
// Frontend-only filtering. Never mutates the API response.

import type { PublicFinding, Severity } from "@/lib/api";

export type SortDir = "asc" | "desc";

export interface FilterState {
  query: string;
  severity: Severity | "all";
  iocType: string;
  minScore: number;
  minProviders: number;
  aiOnly: boolean;
  sortDir: SortDir;
}

export const DEFAULT_FILTERS: FilterState = {
  query: "",
  severity: "all",
  iocType: "all",
  minScore: 0,
  minProviders: 0,
  aiOnly: false,
  sortDir: "desc",
};

export function isFiltering(state: FilterState): boolean {
  return (
    state.query.trim() !== "" ||
    state.severity !== "all" ||
    state.iocType !== "all" ||
    state.minScore > 0 ||
    state.minProviders > 0 ||
    state.aiOnly
  );
}

export function applyFilters(
  findings: PublicFinding[],
  state: FilterState,
): PublicFinding[] {
  const q = state.query.trim().toLowerCase();
  const filtered = findings.filter((f) => {
    if (state.severity !== "all" && f.severity !== state.severity) return false;
    if (state.iocType !== "all" && f.ioc_type !== state.iocType) return false;
    if (f.score < state.minScore) return false;
    if (f.enrichments.length < state.minProviders) return false;
    if (state.aiOnly && !f.ai_narrative) return false;
    if (!q) return true;
    return (
      f.ioc_value.toLowerCase().includes(q) ||
      f.ioc_type.toLowerCase().includes(q) ||
      f.ioc_source.toLowerCase().includes(q) ||
      f.finding_id.toLowerCase().includes(q)
    );
  });
  filtered.sort((a, b) =>
    state.sortDir === "desc" ? b.score - a.score : a.score - b.score,
  );
  return filtered;
}
