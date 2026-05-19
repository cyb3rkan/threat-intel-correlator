// frontend/lib/format.ts
// Public-safe formatting helpers for UI rendering. Pure — no side effects.
// None of these helpers can leak hash-mode pseudonyms back to raw values;
// they only inspect the string the backend already returned.

const HASH_PREFIX = "hmac:";

/**
 * True iff the value looks like a hash-mode pseudonym produced by the
 * backend (output_mode=hash). The check is intentionally narrow — anything
 * else is treated as a raw analyst-mode value.
 */
export function isHashedIoc(value: string): boolean {
  return typeof value === "string" && value.startsWith(HASH_PREFIX);
}

/**
 * Trim a long IOC string for table cells / chips while keeping enough
 * context to identify it. Preserves both head and tail; falls back to a
 * plain truncate for very short max widths. Never alters hash-mode
 * pseudonyms beyond truncation (no decoding, no normalization).
 */
export function truncateIoc(value: string, max = 48): string {
  if (typeof value !== "string") return "";
  if (value.length <= max) return value;
  if (max < 8) return value.slice(0, max);
  const head = Math.ceil((max - 1) / 2);
  const tail = Math.floor((max - 1) / 2);
  return `${value.slice(0, head)}…${value.slice(value.length - tail)}`;
}

/**
 * Locale-aware timestamp for display. Accepts ISO strings (PublicFinding's
 * `created_at`). Returns the original string on parse failure so the UI
 * never silently swallows the value.
 */
export function formatTimestamp(iso: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

/**
 * Short, fixed-format timestamp suitable for compact strips ("14:22:08").
 * Falls back to formatTimestamp on parse failure.
 */
export function formatClock(iso: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString();
}
