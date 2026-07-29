// frontend/lib/api.ts
// Thin client for the local FastAPI backend. No business logic here —
// the backend (src/tic/api/main.py) is the single source of truth.

const _DEFAULT_API_BASE = "http://127.0.0.1:8000";

/**
 * Resolve API_BASE from NEXT_PUBLIC_API_BASE with a strict local-only guard.
 * Protects against misconfiguration that would send local sweep data to a
 * remote host (e.g. typo, shared .env, build cache from another project).
 * Falls back to 127.0.0.1:8000 with a console warning if rejected.
 */
function _resolveApiBase(raw: string | undefined): string {
  if (!raw) return _DEFAULT_API_BASE;
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return _DEFAULT_API_BASE;
  }
  // Only allow plain http(s); only allow loopback hosts. The frontend is
  // local-only by design and must not reach a remote backend.
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return _DEFAULT_API_BASE;
  }
  const host = parsed.hostname.toLowerCase();
  const isLoopback = host === "127.0.0.1" || host === "localhost" || host === "::1" || host === "[::1]";
  if (!isLoopback) {
    return _DEFAULT_API_BASE;
  }
  // Strip trailing slash so route concatenation stays well-formed.
  return raw.replace(/\/+$/, "");
}

export const API_BASE: string = _resolveApiBase(process.env.NEXT_PUBLIC_API_BASE);

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type FeedFormat = "csv" | "ndjson" | "misp-json" | "stix";
export type OutputMode = "analyst" | "summary" | "hash";

export interface PublicEnrichment {
  provider: string;
  reputation_score: number | null;
  tags: string[];
}

export interface AINarrative {
  summary: string;
  false_positive_likelihood: "low" | "medium" | "high";
  suggested_actions: string[];
  confidence: "low" | "medium" | "high";
  model: string;
  generated_at: string;
  ai_origin: true;
}

export interface PublicFinding {
  finding_id: string;
  ioc_type: string;
  ioc_value: string;
  ioc_source: string;
  ioc_confidence: number;
  ioc_tags: string[];
  match_count: number;
  enrichments: PublicEnrichment[];
  score: number;
  severity: Severity;
  profile_hash: string;
  correlation_id: string;
  created_at: string;
  ai_narrative: AINarrative | null;
  output_mode: OutputMode | string;
}

export interface SweepResponse {
  finding_count: number;
  findings: PublicFinding[];
  above_threshold: boolean;
  exit_code: number;
  partial_scan: boolean;
  ai_attempted: boolean;
  ai_active: boolean;
  output_mode?: string;
}

export interface SweepFormInput {
  feed_file: File;
  log_file: File;
  feed_format: FeedFormat;
  output_mode: OutputMode;
  fail_on: Severity;
  with_ai: boolean;
}

export async function runSweep(
  input: SweepFormInput,
  options?: { signal?: AbortSignal },
): Promise<SweepResponse> {
  const fd = new FormData();
  fd.append("feed_file", input.feed_file);
  fd.append("log_file", input.log_file);
  fd.append("feed_format", input.feed_format);
  fd.append("output_mode", input.output_mode);
  fd.append("fail_on", input.fail_on);
  fd.append("with_ai", String(input.with_ai));

  const res = await fetch(`${API_BASE}/api/sweep`, {
    method: "POST",
    body: fd,
    signal: options?.signal,
  });

  if (!res.ok) {
    let detail = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (typeof body?.detail === "string") detail = body.detail;
    } catch {
      // ignore — keep generic detail
    }
    throw new Error(detail);
  }
  return (await res.json()) as SweepResponse;
}

// ---------------------------------------------------------------------------
// Provider status (GET /api/providers/status). Read-only, no secrets returned.
// ---------------------------------------------------------------------------

export type ProviderReason =
  | "ok"
  | "not_configured"
  | "disabled"
  | "no_keyring_key"
  | "endpoint_missing";

export type AIReason =
  | "ok"
  | "ai_disabled"
  | "endpoint_allowlist_empty"
  | "no_keyring_key";

export type EndpointKind = "public" | "internal" | "none";

export interface ProviderStatusEntry {
  name: string;
  configured: boolean;
  enabled: boolean;
  key_present: boolean;
  supported_ioc_types: string[];
  endpoint_kind: EndpointKind;
  ready: boolean;
  reason: ProviderReason | string;
}

export interface AIStatus {
  enabled: boolean;
  endpoint_count: number;
  key_present: boolean;
  ready: boolean;
  reason: AIReason | string;
}

export interface ProviderStatusResponse {
  providers: ProviderStatusEntry[];
  ai: AIStatus;
  redaction_hmac: { key_present: boolean };
}

export async function getProviderStatus(
  options?: { signal?: AbortSignal },
): Promise<ProviderStatusResponse | null> {
  try {
    const res = await fetch(`${API_BASE}/api/providers/status`, {
      cache: "no-store",
      signal: options?.signal,
    });
    if (!res.ok) return null;
    return (await res.json()) as ProviderStatusResponse;
  } catch {
    return null;
  }
}

export const PROVIDER_REASON_LABEL: Record<ProviderReason, string> = {
  ok: "Hazır",
  not_configured: "Yapılandırılmamış",
  disabled: "Settings’te devre dışı",
  no_keyring_key: "Keyring key yok",
  endpoint_missing: "Endpoint ayarlı değil",
};

export const AI_REASON_LABEL: Record<AIReason, string> = {
  ok: "Hazır",
  ai_disabled: "AI settings’te devre dışı",
  endpoint_allowlist_empty: "Allowlist’te endpoint yok",
  no_keyring_key: "Keyring key yok",
};

export async function checkHealth(options?: { signal?: AbortSignal }): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/api/health`, {
      cache: "no-store",
      signal: options?.signal,
    });
    if (!res.ok) return false;
    const j = await res.json();
    return j?.status === "ok";
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Pure UI helpers — derived purely from PublicFinding (no extra backend calls).
// ---------------------------------------------------------------------------

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function countBySeverity(findings: PublicFinding[]): Record<Severity, number> {
  const out: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) out[f.severity] += 1;
  return out;
}

export function countByIocType(findings: PublicFinding[]): Array<{ name: string; value: number }> {
  const m = new Map<string, number>();
  for (const f of findings) m.set(f.ioc_type, (m.get(f.ioc_type) ?? 0) + 1);
  return Array.from(m, ([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
}

export function providerCoverage(findings: PublicFinding[]): Array<{ provider: string; count: number }> {
  const m = new Map<string, number>();
  for (const f of findings) {
    for (const e of f.enrichments) m.set(e.provider, (m.get(e.provider) ?? 0) + 1);
  }
  return Array.from(m, ([provider, count]) => ({ provider, count })).sort((a, b) => b.count - a.count);
}

export function scoreBuckets(findings: PublicFinding[]): Array<{ bucket: string; count: number }> {
  const buckets = [
    { bucket: "0–19", count: 0 },
    { bucket: "20–39", count: 0 },
    { bucket: "40–59", count: 0 },
    { bucket: "60–79", count: 0 },
    { bucket: "80–100", count: 0 },
  ];
  for (const f of findings) {
    const s = f.score;
    if (s < 20) buckets[0].count += 1;
    else if (s < 40) buckets[1].count += 1;
    else if (s < 60) buckets[2].count += 1;
    else if (s < 80) buckets[3].count += 1;
    else buckets[4].count += 1;
  }
  return buckets;
}

// CSV formula-injection mitigation matching the backend's escape_csv_cell.
const FORMULA_PREFIXES = new Set(["=", "+", "-", "@", "\t", "\r"]);
function escapeCsvCell(value: string): string {
  if (value && FORMULA_PREFIXES.has(value[0]!)) return "'" + value;
  return value;
}

const CSV_COLUMNS = [
  "finding_id",
  "severity",
  "score",
  "ioc_type",
  "ioc_value",
  "ioc_source",
  "ioc_confidence",
  "match_count",
  "ioc_tags",
  "enrichment_providers",
  "profile_hash",
  "correlation_id",
  "created_at",
  "output_mode",
  // Phase C — CSV policy option C: only a yes/no flag, never the AI text.
  "ai_present",
] as const;

function quoteAll(cell: string): string {
  return `"${cell.replace(/"/g, '""')}"`;
}

export function findingsToCsv(findings: PublicFinding[]): string {
  const lines: string[] = [];
  lines.push(CSV_COLUMNS.map((c) => quoteAll(escapeCsvCell(c))).join(","));
  for (const f of findings) {
    const row = [
      f.finding_id,
      f.severity,
      String(f.score),
      f.ioc_type,
      f.ioc_value,
      f.ioc_source,
      String(f.ioc_confidence),
      String(f.match_count),
      f.ioc_tags.join(", "),
      f.enrichments.map((e) => e.provider).join(", "),
      f.profile_hash,
      f.correlation_id,
      f.created_at,
      f.output_mode,
      f.ai_narrative !== null ? "yes" : "no",
    ];
    lines.push(row.map((c) => quoteAll(escapeCsvCell(String(c)))).join(","));
  }
  return lines.join("\n") + "\n";
}

export function findingsToJson(response: SweepResponse | null, findings: PublicFinding[]): string {
  // Mirror the backend's render_json shape so the export stays consistent.
  return JSON.stringify(
    {
      version: 2,
      output_mode: response?.output_mode ?? "analyst",
      finding_count: findings.length,
      above_threshold: response?.above_threshold ?? false,
      exit_code: response?.exit_code ?? 0,
      findings,
    },
    null,
    2,
  );
}

const MD_SPECIAL = ["\\", "`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "<", ">", "|"];
function mdEscape(s: string): string {
  let out = s;
  for (const ch of MD_SPECIAL) out = out.split(ch).join("\\" + ch);
  return out;
}

// Render a value inside an inline code span without escaping. Markdown only
// terminates the span on a matching run of backticks, so a value that
// contains backticks needs a longer fence around it. Returns the value
// verbatim, so analysts see full IOC strings (URLs, hashes, CVE IDs, etc.).
function mdInlineCode(value: string): string {
  if (!value.includes("`")) return `\`${value}\``;
  let fence = "``";
  while (value.includes(fence)) fence += "`";
  const pad = value.startsWith("`") || value.endsWith("`") ? " " : "";
  return `${fence}${pad}${value}${pad}${fence}`;
}

// Markdown table cell escape: pipes break the row, backslashes need
// escaping, and a literal newline ends the cell. Other Markdown specials
// stay literal because table cells are rendered as inline phrasing.
function mdTableCell(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

export function findingsToMarkdown(findings: PublicFinding[]): string {
  const lines: string[] = [];
  lines.push("# Threat Intel Correlator — Findings Report", "");
  lines.push(`**Toplam finding sayısı:** ${findings.length}`, "");
  if (findings.length === 0) {
    lines.push("_Bu sweep için finding üretilmedi._", "");
    return lines.join("\n");
  }
  for (const [i, f] of findings.entries()) {
    lines.push(`### ${i + 1}. ${f.severity.toUpperCase()} — score ${f.score}`, "");
    lines.push(`- **IOC type:** ${mdInlineCode(f.ioc_type)}`);
    lines.push(`- **Value:** ${mdInlineCode(f.ioc_value)}`);
    lines.push(`- **Source:** ${mdEscape(f.ioc_source)}`);
    lines.push(`- **Eşleşme sayısı:** ${f.match_count}`);
    if (f.ioc_tags.length) lines.push(`- **Tags:** ${f.ioc_tags.map(mdEscape).join(", ")}`);
    lines.push(`- **Finding ID:** ${mdInlineCode(f.finding_id)}`);
    if (f.enrichments.length) {
      lines.push("", "**Enrichments:**", "", "| Provider | Reputation | Tags |", "|---|---|---|");
      for (const e of f.enrichments) {
        const rep = e.reputation_score == null ? "—" : String(e.reputation_score);
        const tags = e.tags.length ? e.tags.map((t) => mdTableCell(t)).join(", ") : "—";
        lines.push(`| ${mdTableCell(e.provider)} | ${rep} | ${tags} |`);
      }
    }
    lines.push("");
  }
  return lines.join("\n");
}
