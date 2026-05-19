"use client";

// frontend/app/page.tsx
// Local-only enterprise-style dashboard for the Threat Intel Correlator FastAPI backend.

import * as React from "react";
import { Inbox, Plug } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { DashboardCharts } from "@/components/dashboard-charts";
import { DiagnosticsPanel } from "@/components/diagnostics-panel";
import { ExportPanel } from "@/components/export-panel";
import { FindingsAppendix } from "@/components/findings-appendix";
import { FindingsDetailDrawer } from "@/components/findings-detail-drawer";
import { FindingsTable } from "@/components/findings-table";
import { InputGuide } from "@/components/input-guide";
import { KpiRow } from "@/components/kpi-row";
import { PriorityQueue } from "@/components/priority-queue";
import { ProviderStatusGrid } from "@/components/provider-status";
import { RecommendationsCard } from "@/components/recommendations-card";
import { ReportCover } from "@/components/report-cover";
import { ReportHeader } from "@/components/report-header";
import { ReportSummary } from "@/components/report-summary";
import { RiskBreakdown } from "@/components/risk-breakdown";
import { RunHistory } from "@/components/run-history";
import { SecurityPanel } from "@/components/security-panel";
import { SectionTabs, type SectionId } from "@/components/section-tabs";
import { SweepForm } from "@/components/sweep-form";
import { SweepStatusStrip } from "@/components/sweep-status-strip";
import { TopNav } from "@/components/top-nav";
import {
  API_BASE,
  checkHealth,
  countBySeverity,
  getProviderStatus,
  providerCoverage,
  runSweep,
  type ProviderStatusResponse,
  type PublicFinding,
  type SweepFormInput,
  type SweepResponse,
} from "@/lib/api";
import {
  applyFilters,
  DEFAULT_FILTERS,
  isFiltering,
  type FilterState,
} from "@/lib/filters";
import {
  appendHistory,
  clearHistory as clearHistoryStore,
  loadHistory,
  summarize,
  type RunHistoryEntry,
} from "@/lib/history";
import { buildExecutiveSummary } from "@/lib/report";

export default function DashboardPage() {
  const [section, setSection] = React.useState<SectionId>("dashboard");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [result, setResult] = React.useState<SweepResponse | null>(null);
  const [healthy, setHealthy] = React.useState<boolean | null>(null);
  const [lastChecked, setLastChecked] = React.useState<Date | null>(null);
  const [selectedId, setSelectedId] = React.useState<string | null>(null);
  const [filters, setFilters] = React.useState<FilterState>(DEFAULT_FILTERS);
  const [history, setHistory] = React.useState<RunHistoryEntry[]>([]);
  const [lastFailOn, setLastFailOn] = React.useState<SweepFormInput["fail_on"] | null>(null);
  const [providerStatus, setProviderStatus] = React.useState<ProviderStatusResponse | null>(null);
  const [providerStatusLoading, setProviderStatusLoading] = React.useState<boolean>(true);
  const sweepAbortRef = React.useRef<AbortController | null>(null);

  // Hydrate history once on mount.
  React.useEffect(() => {
    setHistory(loadHistory());
  }, []);

  React.useEffect(() => {
    let alive = true;
    let healthAbort: AbortController | null = null;

    const tick = () => {
      if (typeof document !== "undefined" && document.visibilityState !== "visible") return;
      healthAbort?.abort();
      healthAbort = new AbortController();
      checkHealth({ signal: healthAbort.signal }).then((ok) => {
        if (alive) {
          setHealthy(ok);
          setLastChecked(new Date());
        }
      });
    };

    tick();
    const t = setInterval(tick, 30_000);
    const onVisibility = () => {
      if (document.visibilityState === "visible") tick();
    };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      alive = false;
      clearInterval(t);
      document.removeEventListener("visibilitychange", onVisibility);
      healthAbort?.abort();
    };
  }, []);

  // Cancel any in-flight sweep when the page unmounts.
  React.useEffect(() => {
    return () => sweepAbortRef.current?.abort();
  }, []);

  // Provider status: fetch once on mount, refetch when the backend
  // becomes reachable, and once after every sweep (a sweep often follows
  // the user setting up a key — keeps the UI fresh without polling).
  React.useEffect(() => {
    let alive = true;
    let abort: AbortController | null = null;
    if (healthy === false) {
      // Backend unreachable — keep last known value.
      return () => { alive = false; abort?.abort(); };
    }
    abort = new AbortController();
    setProviderStatusLoading(true);
    getProviderStatus({ signal: abort.signal })
      .then((s) => {
        if (alive) setProviderStatus(s);
      })
      .finally(() => {
        if (alive) setProviderStatusLoading(false);
      });
    return () => {
      alive = false;
      abort?.abort();
    };
  }, [healthy, result]);

  // Reset filters when a new result lands so users start fresh.
  React.useEffect(() => {
    if (result) setFilters(DEFAULT_FILTERS);
  }, [result]);

  async function handleRun(input: SweepFormInput) {
    sweepAbortRef.current?.abort();
    const controller = new AbortController();
    sweepAbortRef.current = controller;

    setError(null);
    setLoading(true);
    setSelectedId(null);
    setLastFailOn(input.fail_on);
    try {
      const r = await runSweep(input, { signal: controller.signal });
      if (controller.signal.aborted) return;
      setResult(r);
      setHistory((prev) => appendHistory(prev, summarize(r, input.fail_on)));
    } catch (err) {
      if (controller.signal.aborted) return;
      setError(err instanceof Error ? err.message : "Unexpected error.");
    } finally {
      if (sweepAbortRef.current === controller) sweepAbortRef.current = null;
      if (!controller.signal.aborted) setLoading(false);
    }
  }

  function handleClearHistory() {
    clearHistoryStore();
    setHistory([]);
  }

  // Memoise so reference identity is stable when `result` is unchanged —
  // otherwise downstream useMemo / props churn on every render.
  const findings = React.useMemo<PublicFinding[]>(
    () => result?.findings ?? [],
    [result],
  );
  const counts = React.useMemo(() => countBySeverity(findings), [findings]);
  const visibleFindings = React.useMemo(
    () => applyFilters(findings, filters),
    [findings, filters],
  );
  const filtering = React.useMemo(() => isFiltering(filters), [filters]);
  const selected = React.useMemo(
    () => findings.find((f) => f.finding_id === selectedId) ?? null,
    [findings, selectedId],
  );

  // When a new sweep result lands, drop a stale selection so the drawer
  // doesn't keep showing a finding that no longer exists. Filters get
  // reset separately by the existing effect; selection is reset here so
  // the user's "current view" isn't bound to a vanished finding_id.
  React.useEffect(() => {
    if (selectedId !== null && !findings.some((f) => f.finding_id === selectedId)) {
      setSelectedId(null);
    }
  }, [findings, selectedId]);

  // Opening a finding never switches tabs — the drawer is a global
  // overlay rendered next to the page shell. Only explicit "view all"
  // actions navigate.
  const handleOpenFinding = React.useCallback((id: string) => {
    setSelectedId(id);
  }, []);
  const handleViewAllFindings = React.useCallback(() => {
    setSelectedId(null);
    setSection("findings");
  }, []);
  const handleCloseDrawer = React.useCallback(() => {
    setSelectedId(null);
  }, []);

  return (
    <div className="min-h-screen">
      <TopNav
        healthy={healthy}
        outputMode={result?.output_mode ?? null}
        onExport={() => setSection("exports")}
        onReport={() => setSection("exports")}
      />
      <SectionTabs current={section} onChange={setSection} />

      <main className="mx-auto w-full max-w-[1400px] space-y-4 px-4 py-5">
        <SweepStatusStrip loading={loading} error={error} healthy={healthy} result={result} />

        {section === "dashboard" ? (
          <DashboardSection
            result={result}
            counts={counts}
            findings={findings}
            loading={loading}
            history={history}
            providerStatus={providerStatus}
            failOn={lastFailOn}
            onRun={handleRun}
            onClearHistory={handleClearHistory}
            onOpenInputs={() => setSection("inputs")}
            onOpenFinding={handleOpenFinding}
            onViewAllFindings={handleViewAllFindings}
          />
        ) : null}

        {section === "findings" ? (
          <FindingsSection
            result={result}
            findings={findings}
            visibleFindings={visibleFindings}
            filters={filters}
            setFilters={setFilters}
            selectedId={selectedId}
            onSelect={setSelectedId}
          />
        ) : null}

        {section === "providers" ? (
          <ProvidersSection
            findings={findings}
            providerStatus={providerStatus}
            providerStatusLoading={providerStatusLoading}
          />
        ) : null}

        {section === "exports" ? (
          <ExportsSection
            result={result}
            findings={visibleFindings}
            totalFindings={findings.length}
            filtered={filtering}
            failOn={lastFailOn}
            onOpenFinding={handleOpenFinding}
          />
        ) : null}

        {section === "inputs" ? <InputGuide /> : null}

        {section === "diagnostics" ? (
          <DiagnosticsPanel
            healthy={healthy}
            lastChecked={lastChecked}
            outputMode={result?.output_mode ?? null}
            providerStatus={providerStatus}
          />
        ) : null}

        {section === "security" ? <SecurityPanel /> : null}
      </main>

      {/* Global overlay — opening a finding from any tab (Overview's
          Priority Queue, the Findings table, the Report appendix) shows
          this drawer without navigating away from the current tab. */}
      <FindingsDetailDrawer
        finding={selected}
        open={selected !== null}
        onOpenChange={(o) => {
          if (!o) handleCloseDrawer();
        }}
      />

      <footer className="mx-auto w-full max-w-[1400px] break-words border-t border-border px-4 py-3 text-[11px] leading-relaxed text-muted-foreground [overflow-wrap:anywhere]">
        API base: <code className="font-mono">{API_BASE}</code> · Yalnızca public-safe alanlar
        render edilir. Raw logs, raw provider responses, API keys ve tracebacks hiçbir zaman gösterilmez.
        {lastFailOn ? (
          <> · Son fail-on: <code className="font-mono">{lastFailOn}</code></>
        ) : null}
      </footer>
    </div>
  );
}

function DashboardSection({
  result,
  counts,
  findings,
  loading,
  history,
  providerStatus,
  failOn,
  onRun,
  onClearHistory,
  onOpenInputs,
  onOpenFinding,
  onViewAllFindings,
}: {
  result: SweepResponse | null;
  counts: ReturnType<typeof countBySeverity>;
  findings: SweepResponse["findings"];
  loading: boolean;
  history: RunHistoryEntry[];
  providerStatus: ProviderStatusResponse | null;
  failOn: SweepFormInput["fail_on"] | null;
  onRun: (input: SweepFormInput) => void;
  onClearHistory: () => void;
  onOpenInputs: () => void;
  onOpenFinding: (id: string) => void;
  onViewAllFindings: () => void;
}) {
  // The executive summary is purely deterministic; cheap to derive each
  // render but useMemo keeps reference identity stable for any consumers
  // we wire up later (e.g. RecommendationsCard memoization).
  const summary = React.useMemo(
    () =>
      buildExecutiveSummary(findings, {
        aboveThreshold: result?.above_threshold ?? false,
        aiActive: result?.ai_active ?? false,
        partialScan: result?.partial_scan ?? false,
      }),
    [findings, result?.above_threshold, result?.ai_active, result?.partial_scan],
  );

  return (
    <div className="space-y-4">
      <ReportHeader result={result} failOn={failOn} />

      {result !== null ? <KpiRow result={result} counts={counts} /> : null}

      {result !== null ? (
        <div className="grid gap-4 lg:grid-cols-[1fr_360px]">
          <PriorityQueue
            findings={findings}
            onOpen={(id) => {
              // PriorityQueue passes `null` for its "Tümünü gör" CTA —
              // that's the only path that should navigate. Selecting a
              // specific row stays on the current tab; the drawer opens
              // as a global overlay.
              if (id === null) onViewAllFindings();
              else onOpenFinding(id);
            }}
          />
          <RecommendationsCard summary={summary} />
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[400px_1fr]">
        <Card className="border border-border shadow-sm">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Sweep runner</CardTitle>
            <CardDescription className="text-xs">
              Bir feed ve bir log dosyası yükleyin, seçenekleri belirleyin ve sweep’i başlatın.
              Örnek dosyalar için{" "}
              <button
                type="button"
                className="underline-offset-2 hover:underline"
                onClick={onOpenInputs}
              >
                Inputs
              </button>{" "}
              sekmesine bakabilirsiniz.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <SweepForm
              loading={loading}
              onSubmit={onRun}
              aiStatus={providerStatus?.ai ?? null}
              redactionHmacReady={providerStatus?.redaction_hmac.key_present ?? null}
            />
          </CardContent>
        </Card>
        {result !== null ? (
          <DashboardCharts findings={findings} severityCounts={counts} />
        ) : (
          <Card className="border border-dashed border-border bg-card">
            <CardContent className="flex h-full flex-col items-center justify-center gap-2 py-10 text-center text-sm text-muted-foreground">
              <Inbox className="h-6 w-6 text-muted-foreground" />
              <div>Hazır. KPI’ları, grafikleri ve findings’i doldurmak için ilk sweep’inizi çalıştırın.</div>
              <div className="text-xs text-muted-foreground/80">
                Lokal backend gerçek veri döndürene kadar hiçbir şey gösterilmez.
              </div>
              <button
                type="button"
                onClick={onOpenInputs}
                className="text-xs text-blue-700 underline-offset-2 hover:underline dark:text-blue-400"
              >
                Örnek dosyalara mı ihtiyacınız var? Inputs sekmesini açın.
              </button>
            </CardContent>
          </Card>
        )}
      </div>
      <RunHistory entries={history} onClear={onClearHistory} />
    </div>
  );
}

function FindingsSection({
  result,
  findings,
  visibleFindings,
  filters,
  setFilters,
  selectedId,
  onSelect,
}: {
  result: SweepResponse | null;
  findings: SweepResponse["findings"];
  visibleFindings: PublicFinding[];
  filters: FilterState;
  setFilters: (next: FilterState) => void;
  selectedId: string | null;
  onSelect: (id: string | null) => void;
}) {
  // The detail drawer lives on the page shell (one global instance), so
  // selecting a row here just sets the global selectedId — the user's
  // current tab is preserved when the drawer opens and closes.
  return (
    <Card className="border border-border shadow-sm">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Findings</CardTitle>
        <CardDescription className="text-xs">
          {result === null
            ? "Sonuçları görmek için önce bir sweep çalıştırın."
            : `Public-safe görünüm (output_mode: ${result.output_mode ?? "analyst"})`}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {result === null ? (
          <div className="rounded-md border border-dashed border-border p-8 text-center text-sm text-muted-foreground">
            Henüz bir sweep çalıştırılmadı. Yeni bir sweep başlatmak için <strong>Overview</strong> sekmesine geçin.
          </div>
        ) : (
          <FindingsTable
            findings={findings}
            visibleFindings={visibleFindings}
            selectedId={selectedId}
            onSelect={onSelect}
            filters={filters}
            onChange={setFilters}
          />
        )}
      </CardContent>
    </Card>
  );
}

function ProvidersSection({
  findings,
  providerStatus,
  providerStatusLoading,
}: {
  findings: SweepResponse["findings"];
  providerStatus: ProviderStatusResponse | null;
  providerStatusLoading: boolean;
}) {
  const coverage = providerCoverage(findings);
  return (
    <div className="space-y-4">
      <ProviderStatusGrid status={providerStatus} loading={providerStatusLoading} />
      <Card className="border border-border shadow-sm">
        <CardHeader>
          <CardTitle className="text-sm">Provider coverage (bu sweep)</CardTitle>
          <CardDescription className="text-xs">
            Yalnızca gerçek provider verisi gösterilir; hiçbir değer simüle edilmez. Hiç
            enrichment dönmediğinde coverage 0 olur; nedenini görmek için yukarıdaki readiness
            paneline bakın.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {coverage.length === 0 ? (
            <div className="flex flex-col items-center gap-2 rounded-md border border-dashed border-border p-10 text-center text-sm text-muted-foreground">
              <Plug className="h-6 w-6 text-muted-foreground" />
              <div>
                Bu sweep için hiçbir provider enrichment dönmedi. Nedenini (key yok, devre dışı,
                endpoint eksik, …) görmek için yukarıdaki readiness panelini inceleyin.
              </div>
            </div>
          ) : (
            <ul className="grid gap-3 sm:grid-cols-2">
              {coverage.map((p) => (
                <li key={p.provider} className="rounded-md border border-border px-3 py-2.5">
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-medium text-foreground">{p.provider}</span>
                    <span className="text-xs tabular-nums text-muted-foreground">
                      {p.count} enrichment
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function ExportsSection({
  result,
  findings,
  totalFindings,
  filtered,
  failOn,
  onOpenFinding,
}: {
  result: SweepResponse | null;
  findings: PublicFinding[];
  totalFindings: number;
  filtered: boolean;
  failOn: SweepFormInput["fail_on"] | null;
  onOpenFinding: (id: string) => void;
}) {
  // Executive summary is purely deterministic; the dep list pins the
  // exact flags so this only recomputes when any of them actually move.
  const summary = React.useMemo(
    () =>
      buildExecutiveSummary(findings, {
        aboveThreshold: result?.above_threshold ?? false,
        aiActive: result?.ai_active ?? false,
        partialScan: result?.partial_scan ?? false,
      }),
    [findings, result?.above_threshold, result?.ai_active, result?.partial_scan],
  );

  const severityCounts = React.useMemo(() => countBySeverity(findings), [findings]);

  if (result === null) {
    return (
      <Card className="border border-dashed border-border bg-card">
        <CardContent className="py-10 text-center text-sm text-muted-foreground">
          Henüz bir sweep çalıştırılmadı. Findings üretildikten sonra raporlar kullanılabilir olur.
        </CardContent>
      </Card>
    );
  }

  // Report flow: cover → executive summary → risk breakdown → findings
  // appendix → export bar (secondary). All sections render plain React
  // text nodes — markdown is not rendered, no HTML-injection sinks.
  return (
    <div className="space-y-4">
      <ReportCover result={result} failOn={failOn} />
      <ReportSummary summary={summary} filtered={filtered} />
      <RiskBreakdown findings={findings} severityCounts={severityCounts} />
      <FindingsAppendix findings={findings} onOpen={onOpenFinding} />
      <ExportPanel
        result={result}
        findings={findings}
        totalFindings={totalFindings}
        filtered={filtered}
      />
    </div>
  );
}
