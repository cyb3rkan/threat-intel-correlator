// frontend/lib/priority.ts
// Deterministic priority ordering for findings — used by the Overview
// priority queue. Pure function over PublicFinding[]; no side effects.
//
// Order:
//   1. Severity rank desc (critical first)
//   2. Score desc
//   3. finding_id asc (stable tiebreak so renders don't shuffle)
//
// The input list is never mutated; the result is a new array.

import type { PublicFinding } from "@/lib/api";
import { SEVERITY_RANK } from "@/lib/severity";

export function comparePriority(a: PublicFinding, b: PublicFinding): number {
  const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
  if (sev !== 0) return sev;
  if (b.score !== a.score) return b.score - a.score;
  // Stable tiebreaker: lexicographic finding_id ascending.
  if (a.finding_id < b.finding_id) return -1;
  if (a.finding_id > b.finding_id) return 1;
  return 0;
}

export function prioritize(
  findings: readonly PublicFinding[],
  limit?: number,
): PublicFinding[] {
  const sorted = [...findings].sort(comparePriority);
  if (typeof limit === "number" && limit >= 0) {
    return sorted.slice(0, limit);
  }
  return sorted;
}
