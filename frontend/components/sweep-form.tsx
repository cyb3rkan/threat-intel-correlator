"use client";

// frontend/components/sweep-form.tsx
// Sweep form. Builds FormData and posts to FastAPI. UI-only — no business logic.

import * as React from "react";
import { Hash, Loader2, Play, Sparkles } from "lucide-react";

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
  AI_REASON_LABEL,
  type AIStatus,
  type FeedFormat,
  type OutputMode,
  type Severity,
  type SweepFormInput,
} from "@/lib/api";

const FEED_FORMATS: FeedFormat[] = ["csv", "ndjson", "misp-json", "stix"];
const OUTPUT_MODES: OutputMode[] = ["analyst", "summary", "hash"];
const FAIL_ON: Severity[] = ["info", "low", "medium", "high", "critical"];

interface Props {
  loading: boolean;
  onSubmit: (input: SweepFormInput) => void;
  /** Read-only AI readiness from /api/providers/status. null = unknown. */
  aiStatus?: AIStatus | null;
  /** Whether the redaction HMAC key is present (for hash mode). null = unknown. */
  redactionHmacReady?: boolean | null;
}

export function SweepForm({ loading, onSubmit, aiStatus, redactionHmacReady }: Props) {
  const [feedFile, setFeedFile] = React.useState<File | null>(null);
  const [logFile, setLogFile] = React.useState<File | null>(null);
  const [feedFormat, setFeedFormat] = React.useState<FeedFormat>("csv");
  const [outputMode, setOutputMode] = React.useState<OutputMode>("analyst");
  const [failOn, setFailOn] = React.useState<Severity>("high");
  const [withAi, setWithAi] = React.useState(false);
  const [localError, setLocalError] = React.useState<string | null>(null);

  const filesReady = feedFile !== null && logFile !== null;
  const submitDisabled = loading || !filesReady;

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!filesReady) {
      setLocalError("Sweep çalıştırmak için hem IOC feed hem de log dosyası seçilmelidir.");
      return;
    }
    setLocalError(null);
    onSubmit({
      feed_file: feedFile,
      log_file: logFile,
      feed_format: feedFormat,
      output_mode: outputMode,
      fail_on: failOn,
      with_ai: withAi,
    });
  }

  return (
    <form onSubmit={handleSubmit} className="grid gap-4">
      <div className="grid gap-1.5">
        <Label htmlFor="feed_file" className="text-xs font-medium text-foreground/90">
          IOC feed dosyası
        </Label>
        <Input
          id="feed_file"
          type="file"
          accept=".csv,.ndjson,.json,.txt"
          onChange={(e) => setFeedFile(e.target.files?.[0] ?? null)}
          disabled={loading}
          className="h-9"
        />
        <FileHint file={feedFile} hint="csv · ndjson · misp-json · stix" />
      </div>

      <div className="grid gap-1.5">
        <Label htmlFor="log_file" className="text-xs font-medium text-foreground/90">
          Log dosyası (NDJSON)
        </Label>
        <Input
          id="log_file"
          type="file"
          accept=".ndjson,.json,.log,.txt"
          onChange={(e) => setLogFile(e.target.files?.[0] ?? null)}
          disabled={loading}
          className="h-9"
        />
        <FileHint file={logFile} hint="Her satırda tek bir JSON objesi." />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="grid gap-2">
          <Label>Feed format</Label>
          <Select
            value={feedFormat}
            onValueChange={(v) => setFeedFormat(v as FeedFormat)}
            disabled={loading}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {FEED_FORMATS.map((f) => (
                <SelectItem key={f} value={f}>
                  {f}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="grid gap-2">
          <Label>Output mode</Label>
          <Select
            value={outputMode}
            onValueChange={(v) => setOutputMode(v as OutputMode)}
            disabled={loading}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {OUTPUT_MODES.map((m) => (
                <SelectItem key={m} value={m}>
                  {m}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="grid gap-2">
          <Label>Fail-on severity</Label>
          <Select
            value={failOn}
            onValueChange={(v) => setFailOn(v as Severity)}
            disabled={loading}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {FAIL_ON.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {outputMode === "hash" ? (
        redactionHmacReady === false ? (
          <div
            className="rounded-md border border-amber-200 bg-amber-50/60 px-3 py-2 text-[11px] text-amber-800 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200"
            role="alert"
          >
            <span className="inline-flex items-center gap-1.5 font-medium">
              <Hash className="h-3.5 w-3.5" /> Hash mode kullanılamıyor
            </span>{" "}
            Backend keyring’inde redaction HMAC key bulunamadı; bu nedenle hash mode anlaşılır
            bir hata ile başarısız olur. Çözmek için{" "}
            <code className="font-mono">tic config set-key redaction-hmac</code> komutunu çalıştırın
            ya da output mode olarak{" "}
            <code className="font-mono">analyst</code> veya{" "}
            <code className="font-mono">summary</code> seçin.
          </div>
        ) : (
          <div className="rounded-md border border-blue-200 bg-blue-50/40 px-3 py-2 text-[11px] text-blue-800 dark:border-blue-900/60 dark:bg-blue-950/30 dark:text-blue-200">
            <span className="inline-flex items-center gap-1.5 font-medium">
              <Hash className="h-3.5 w-3.5" /> Hash mode
            </span>{" "}
            IOC değerleri <code className="font-mono">hmac:&lt;hex&gt;</code>{" "}
            pseudonym formatında döner. Frontend bunları olduğu gibi gösterir; orijinal değerler backend tarafında kalır.
          </div>
        )
      ) : null}

      <div className="flex items-center justify-between rounded-md border border-border p-3">
        <div className="grid gap-0.5">
          <Label htmlFor="with_ai" className="inline-flex items-center gap-1.5 text-sm">
            <Sparkles className="h-3.5 w-3.5 text-blue-600" />
            AI narration
          </Label>
          <span className="text-xs text-muted-foreground">
            Varsayılan olarak kapalıdır. Yalnızca <code className="font-mono">ai.enabled</code>{" "}
            true olduğunda ve keyring içinde bir key bulunduğunda devreye girer. Hazır
            değilse sweep sessizce AI olmadan çalışır.
          </span>
          <AIStatusHint aiStatus={aiStatus} requested={withAi} />
        </div>
        <Switch
          id="with_ai"
          checked={withAi}
          onCheckedChange={setWithAi}
          disabled={loading}
        />
      </div>

      {localError ? (
        <p className="text-sm text-destructive" role="alert">
          {localError}
        </p>
      ) : null}

      <Button
        type="submit"
        disabled={submitDisabled}
        title={!filesReady ? "Önce hem IOC feed hem de log dosyası seçin." : undefined}
        className="w-full bg-blue-600 text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-blue-600/40"
      >
        {loading ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Çalışıyor…
          </>
        ) : (
          <>
            <Play className="mr-2 h-4 w-4" /> Sweep çalıştır
          </>
        )}
      </Button>
      {!filesReady && !loading ? (
        <p className="text-[11px] text-muted-foreground">
          Sweep’i başlatmak için her iki alana da birer dosya seçin.
        </p>
      ) : null}
    </form>
  );
}

function AIStatusHint({
  aiStatus,
  requested,
}: {
  aiStatus: AIStatus | null | undefined;
  requested: boolean;
}) {
  if (!aiStatus) return null;
  if (aiStatus.ready) {
    if (!requested) return null;
    return (
      <span className="text-[11px] text-emerald-700 dark:text-emerald-300">
        AI narrator backend’de hazır.
      </span>
    );
  }
  // Not ready — explain why with the safe enum reason (no secrets).
  const reasonKey = aiStatus.reason as keyof typeof AI_REASON_LABEL;
  const label = AI_REASON_LABEL[reasonKey] ?? aiStatus.reason;
  return (
    <span className="text-[11px] text-amber-700 dark:text-amber-300">
      AI narrator hazır değil ({label}). Talep edilse de sweep AI olmadan çalışır.
    </span>
  );
}

function FileHint({ file, hint }: { file: File | null; hint: string }) {
  if (!file) {
    return <span className="text-[11px] text-muted-foreground">{hint}</span>;
  }
  const kb = (file.size / 1024).toFixed(1);
  return (
    <span className="truncate text-[11px] text-muted-foreground" title={file.name}>
      Seçilen: <span className="font-mono text-foreground/90">{file.name}</span> · {kb} KB
    </span>
  );
}
