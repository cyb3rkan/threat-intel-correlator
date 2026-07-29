// frontend/lib/report.ts
// Public-safe report helpers built on top of the PublicFinding payload.
// No raw logs, no provider raw payloads, no secrets — just deterministic
// aggregations of fields the backend already projected for the UI.

import {
  countByIocType,
  countBySeverity,
  providerCoverage,
  type PublicFinding,
  type Severity,
} from "@/lib/api";

export interface ExecutiveSummary {
  total: number;
  severity: Record<Severity, number>;
  topIocTypes: Array<{ name: string; value: number }>;
  topSources: Array<{ name: string; value: number }>;
  providers: Array<{ provider: string; count: number }>;
  recommendations: string[];
  aboveThreshold: boolean;
  aiActive: boolean;
  partialScan: boolean;
}

export interface SummaryContext {
  aboveThreshold: boolean;
  aiActive: boolean;
  partialScan: boolean;
}

export function buildExecutiveSummary(
  findings: PublicFinding[],
  ctx: SummaryContext,
): ExecutiveSummary {
  const severity = countBySeverity(findings);
  const topIocTypes = countByIocType(findings).slice(0, 5);

  const sourceCounts = new Map<string, number>();
  for (const f of findings) {
    const k = f.ioc_source || "(unknown)";
    sourceCounts.set(k, (sourceCounts.get(k) ?? 0) + 1);
  }
  const topSources = Array.from(sourceCounts, ([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 5);

  return {
    total: findings.length,
    severity,
    topIocTypes,
    topSources,
    providers: providerCoverage(findings),
    recommendations: deriveRecommendations(severity, ctx, findings.length),
    aboveThreshold: ctx.aboveThreshold,
    aiActive: ctx.aiActive,
    partialScan: ctx.partialScan,
  };
}

function deriveRecommendations(
  severity: Record<Severity, number>,
  ctx: SummaryContext,
  total: number,
): string[] {
  const out: string[] = [];
  if (total === 0) {
    out.push(
      "Hiç finding üretilmedi. IOC feed formatı ile log dosyasının birbiriyle uyumlu olduğunu kontrol edin; ayrıntılar için Inputs rehberine bakın.",
    );
    return out;
  }
  if (severity.critical > 0) {
    out.push(
      `Önce ${severity.critical} adet CRITICAL finding’i inceleyin; aksi kanıtlanana kadar devam eden bir incident olarak ele alın.`,
    );
  }
  if (severity.high > 0) {
    out.push(
      `${severity.high} adet HIGH finding’i mevcut detection değerleri ve son değişiklik pencerelerine karşı triage edin.`,
    );
  }
  if (severity.medium > 0 && severity.critical === 0 && severity.high === 0) {
    out.push(
      `${severity.medium} adet MEDIUM finding — aktif bir kampanyaya bağlı değilse ertesi günkü inceleme için planlayın.`,
    );
  }
  if (severity.low > 0 && severity.critical + severity.high + severity.medium === 0) {
    out.push(
      `${severity.low} adet LOW finding — arka plan bağlamı olarak faydalıdır; acil bir aksiyon gerektirmez.`,
    );
  }
  if (severity.info > 0) {
    out.push(
      `${severity.info} adet INFO finding izlenebilirlik için kaydedildi; ek bir aksiyon gerektirmez.`,
    );
  }
  if (ctx.aboveThreshold) {
    out.push(
      "Sweep exit code, yapılandırılan fail-on eşiğinde veya üzerinde finding olduğunu gösteriyor; CI tarafında bunu block veya page olarak ele alın.",
    );
  }
  if (ctx.partialScan) {
    out.push(
      "Log dosyası satır limitine ulaşıldığı için kısmen tarandı. Sonuçları tam bir sweep değil, bir örneklem olarak değerlendirin.",
    );
  }
  if (!ctx.aiActive) {
    out.push(
      "AI narration aktif değil. Findings yalnızca rule ve scoring sonucudur; aksiyon almadan önce başka bir araçla doğrulayın.",
    );
  }
  return out;
}

const MD_SPECIAL = ["\\", "`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "<", ">", "|"];
function mdEscape(s: string): string {
  let out = s;
  for (const ch of MD_SPECIAL) out = out.split(ch).join("\\" + ch);
  return out;
}

export function executiveSummaryToMarkdown(summary: ExecutiveSummary): string {
  const lines: string[] = [];
  lines.push("# Threat Intel Correlator — Executive Summary", "");
  lines.push(`**Toplam finding sayısı:** ${summary.total}`);
  lines.push(
    `**Fail-on eşiğinin üstünde:** ${summary.aboveThreshold ? "evet" : "hayır"}`,
  );
  lines.push(`**AI narration aktif:** ${summary.aiActive ? "evet" : "hayır"}`);
  lines.push(`**Kısmi tarama:** ${summary.partialScan ? "evet" : "hayır"}`, "");

  lines.push("## Severity dağılımı", "");
  lines.push("| Severity | Adet |", "|---|---|");
  (["critical", "high", "medium", "low", "info"] as Severity[]).forEach((s) => {
    lines.push(`| ${s.toUpperCase()} | ${summary.severity[s]} |`);
  });
  lines.push("");

  if (summary.topIocTypes.length) {
    lines.push("## En sık IOC type değerleri", "");
    lines.push("| Type | Adet |", "|---|---|");
    for (const r of summary.topIocTypes) {
      lines.push(`| \`${mdEscape(r.name)}\` | ${r.value} |`);
    }
    lines.push("");
  }

  if (summary.topSources.length) {
    lines.push("## En sık source değerleri", "");
    lines.push("| Source | Adet |", "|---|---|");
    for (const r of summary.topSources) {
      lines.push(`| ${mdEscape(r.name)} | ${r.value} |`);
    }
    lines.push("");
  }

  if (summary.providers.length) {
    lines.push("## Provider coverage", "");
    lines.push("| Provider | Enrichment |", "|---|---|");
    for (const p of summary.providers) {
      lines.push(`| ${mdEscape(p.provider)} | ${p.count} |`);
    }
    lines.push("");
  }

  if (summary.recommendations.length) {
    lines.push("## Önerilen sonraki adımlar", "");
    for (const r of summary.recommendations) {
      lines.push(`- ${r}`);
    }
    lines.push("");
  }

  lines.push(
    "_Public-safe veriler kullanılarak lokal olarak üretildi. Raw logs, raw provider payloads ve secrets değerleri dahil edilmez._",
    "",
  );
  return lines.join("\n");
}
