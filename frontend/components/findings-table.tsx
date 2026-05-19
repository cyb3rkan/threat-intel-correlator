"use client";

import * as React from "react";
import { ArrowDown, ArrowUp, Search, Sparkles, X } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { SEVERITY_ORDER, type PublicFinding, type Severity } from "@/lib/api";
import { SEVERITY_GLYPH, SEVERITY_TONE } from "@/lib/severity";
import {
  DEFAULT_FILTERS,
  isFiltering,
  type FilterState,
} from "@/lib/filters";

interface Props {
  findings: PublicFinding[];        // unfiltered, original list
  visibleFindings: PublicFinding[]; // already filtered + sorted
  selectedId: string | null;
  onSelect: (id: string | null) => void;
  filters: FilterState;
  onChange: (next: FilterState) => void;
}

export function FindingsTable({
  findings,
  visibleFindings,
  selectedId,
  onSelect,
  filters,
  onChange,
}: Props) {
  const iocTypes = React.useMemo(() => {
    const s = new Set<string>();
    for (const f of findings) s.add(f.ioc_type);
    return Array.from(s).sort();
  }, [findings]);

  const update = <K extends keyof FilterState>(key: K, value: FilterState[K]) =>
    onChange({ ...filters, [key]: value });

  const filtering = isFiltering(filters);
  const totalScore = React.useMemo(
    () => Math.max(0, ...findings.map((f) => f.score)),
    [findings],
  );
  // Cap the slider at the actual max score so users get a useful range.
  const scoreMax = totalScore > 0 ? totalScore : 100;

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Value, type, source veya finding ID ile ara…"
            value={filters.query}
            onChange={(e) => update("query", e.target.value)}
            className="h-9 pl-8"
            aria-label="Findings içinde ara"
          />
        </div>
        <Select
          value={filters.severity}
          onValueChange={(v) => update("severity", v as Severity | "all")}
        >
          <SelectTrigger className="h-9 w-[140px]" aria-label="Severity ile filtrele">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Tüm severity’ler</SelectItem>
            {SEVERITY_ORDER.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={filters.iocType}
          onValueChange={(v) => update("iocType", v)}
        >
          <SelectTrigger className="h-9 w-[140px]" aria-label="IOC type ile filtrele">
            <SelectValue placeholder="IOC type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Tüm IOC type’ları</SelectItem>
            {iocTypes.map((t) => (
              <SelectItem key={t} value={t}>
                {t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="grid grid-cols-1 gap-3 rounded-md border border-border bg-muted/20 p-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="grid gap-1">
          <Label className="text-[11px] uppercase tracking-wide text-muted-foreground">
            Min score: <span className="tabular-nums text-foreground">{filters.minScore}</span>
          </Label>
          <input
            type="range"
            min={0}
            max={scoreMax}
            step={1}
            value={filters.minScore}
            onChange={(e) => update("minScore", Number(e.target.value))}
            className="accent-blue-600"
            aria-label="Minimum score"
          />
        </div>
        <div className="grid gap-1">
          <Label className="text-[11px] uppercase tracking-wide text-muted-foreground">
            Min provider:{" "}
            <span className="tabular-nums text-foreground">{filters.minProviders}</span>
          </Label>
          <input
            type="range"
            min={0}
            max={5}
            step={1}
            value={filters.minProviders}
            onChange={(e) => update("minProviders", Number(e.target.value))}
            className="accent-blue-600"
            aria-label="Minimum provider sayısı"
          />
        </div>
        <div className="flex items-center justify-between gap-2 rounded-md border border-border bg-card px-3">
          <Label htmlFor="ai-only" className="inline-flex items-center gap-1.5 text-xs">
            <Sparkles className="h-3.5 w-3.5 text-blue-600" />
            Yalnızca AI narrative
          </Label>
          <Switch
            id="ai-only"
            checked={filters.aiOnly}
            onCheckedChange={(v) => update("aiOnly", v)}
          />
        </div>
        <div className="flex items-center justify-end">
          <Button
            variant="outline"
            size="sm"
            disabled={!filtering}
            onClick={() => onChange({ ...DEFAULT_FILTERS, sortDir: filters.sortDir })}
            aria-label="Filtreleri temizle"
          >
            <X className="mr-1.5 h-3.5 w-3.5" />
            Filtreleri temizle
          </Button>
        </div>
      </div>

      <div className="max-w-full overflow-x-auto rounded-md border border-border bg-card">
        <Table>
          <TableHeader>
            <TableRow className="bg-muted/40 hover:bg-muted/40">
              <TableHead className="w-[110px]">Severity</TableHead>
              <TableHead
                className="w-[90px] select-none p-0"
                aria-sort={filters.sortDir === "desc" ? "descending" : "ascending"}
              >
                <button
                  type="button"
                  onClick={() =>
                    update("sortDir", filters.sortDir === "desc" ? "asc" : "desc")
                  }
                  className="inline-flex h-full w-full items-center gap-1 px-2 py-2 text-left font-medium hover:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  aria-label={`Score’a göre sırala, şu an ${filters.sortDir === "desc" ? "azalan" : "artan"}`}
                  title="Score’a göre sırala"
                >
                  Score
                  {filters.sortDir === "desc" ? (
                    <ArrowDown className="h-3 w-3" aria-hidden="true" />
                  ) : (
                    <ArrowUp className="h-3 w-3" aria-hidden="true" />
                  )}
                </button>
              </TableHead>
              <TableHead className="w-[100px]">IOC type</TableHead>
              <TableHead>Value</TableHead>
              <TableHead className="w-[80px] text-right">Eşleşme</TableHead>
              <TableHead className="w-[90px] text-right">Providers</TableHead>
              <TableHead className="w-[180px]">Source</TableHead>
              <TableHead className="w-[60px]">AI</TableHead>
              <TableHead className="w-[110px] font-mono text-[11px]">Finding ID</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {visibleFindings.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="py-10 text-center text-sm text-muted-foreground">
                  {findings.length === 0
                    ? "Bu sweep için finding üretilmedi."
                    : "Mevcut filtrelerle eşleşen finding bulunamadı."}
                </TableCell>
              </TableRow>
            ) : (
              visibleFindings.map((f) => {
                const active = f.finding_id === selectedId;
                return (
                  <TableRow
                    key={f.finding_id}
                    role="button"
                    tabIndex={0}
                    aria-selected={active}
                    aria-label={`Finding ${f.finding_id.slice(0, 8)} incele, severity ${f.severity}, score ${f.score}`}
                    className={cn(
                      "cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                      active
                        ? "bg-blue-50/70 hover:bg-blue-50 dark:bg-blue-950/30 dark:hover:bg-blue-950/40"
                        : "hover:bg-muted/40",
                    )}
                    onClick={() => onSelect(active ? null : f.finding_id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onSelect(active ? null : f.finding_id);
                      }
                    }}
                  >
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={cn("gap-1 border", SEVERITY_TONE[f.severity].badge)}
                        aria-label={`severity ${f.severity}`}
                      >
                        <span aria-hidden="true">{SEVERITY_GLYPH[f.severity]}</span>
                        {f.severity.toUpperCase()}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-medium tabular-nums">{f.score}</TableCell>
                    <TableCell className="font-mono text-xs">{f.ioc_type}</TableCell>
                    <TableCell className="max-w-[34ch] truncate font-mono text-xs">
                      <span title={f.ioc_value}>{f.ioc_value}</span>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{f.match_count}</TableCell>
                    <TableCell className="text-right tabular-nums">{f.enrichments.length}</TableCell>
                    <TableCell className="max-w-[24ch] truncate text-xs text-muted-foreground">
                      <span title={f.ioc_source}>{f.ioc_source}</span>
                    </TableCell>
                    <TableCell>{f.ai_narrative ? "Evet" : ""}</TableCell>
                    <TableCell className="font-mono text-[11px] text-muted-foreground">
                      {f.finding_id.slice(0, 8)}…
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>
          Toplam <span className="font-medium text-foreground">{findings.length}</span> finding
          içinden <span className="font-medium text-foreground">{visibleFindings.length}</span> tanesi gösteriliyor.
        </span>
        {filtering ? (
          <span className="text-[11px] text-muted-foreground/80">Filtreler aktif</span>
        ) : null}
      </div>
    </div>
  );
}
