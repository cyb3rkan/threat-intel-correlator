"use client";

import * as React from "react";
import {
  Download,
  FileWarning,
  ListChecks,
  FileText,
  FileJson,
  AlertCircle,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  SAMPLE_EVENTS_FILENAME,
  SAMPLE_IOCS_FILENAME,
  getSampleEventsNdjson,
  getSampleIocsCsv,
} from "@/lib/samples";

function downloadText(text: string, filename: string, mime: string) {
  const blob = new Blob([text], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

const CSV_PREVIEW = `value,confidence,source,tags
198.51.100.23,80,sample-feed,doc;ipv4
malware.example.com,90,sample-feed,doc;domain`;

const NDJSON_PREVIEW = `{"@timestamp":"2025-01-12T08:14:02Z","source":"firewall","src_ip":"10.0.0.42","dst_ip":"198.51.100.23","action":"allow"}
{"@timestamp":"2025-01-12T08:14:30Z","source":"proxy","user":"alice","url":"http://malware.example.com/login"}`;

const COMMON_MISTAKES: { title: string; body: string }[] = [
  {
    title: "Dosyanın yanlış alana yüklenmesi",
    body:
      "IOC feed alanı CSV / NDJSON / MISP / STIX dosyası bekler. Log file alanı ise NDJSON (her satırda bir JSON objesi) bekler. IOC feed alanına NDJSON, log alanına CSV yüklemek parser katmanında hataya yol açar.",
  },
  {
    title: "CSV header satırı eksik",
    body:
      'CSV parser, "value" sütununu bulmak için ilk satırı header olarak kullanır. Dosya header yerine doğrudan veriyle başlıyorsa parse işlemi "CSV file missing required column" hatasıyla başarısız olur.',
  },
  {
    title: "Ayraç olarak noktalı virgül (;)",
    body:
      "Bazı Excel dillerinde CSV noktalı virgülle export edilir. Parser virgül diyalektini kullandığı için dosyayı \"CSV (Comma delimited)\" olarak kaydedin veya yüklemeden önce ayraçları dönüştürün.",
  },
  {
    title: "CSV içinde UTF-8 BOM",
    body:
      "Excel sıklıkla ilk sütun adını \"value\" yerine \"\\ufeffvalue\" hâline getiren bir BOM yazar. Dosyayı BOM olmadan \"CSV UTF-8\" olarak kaydedin ya da BOM’u bir metin editörüyle kaldırın.",
  },
  {
    title: "IOC feed alanında NDJSON seçimi",
    body:
      "Feed dosyanız NDJSON ise Feed format seçicisini \"ndjson\" olarak değiştirin. NDJSON dosyayla \"csv\" seçmek CSV header hatasına yol açar.",
  },
  {
    title: "Boş veya yalnızca boşluk içeren değerler",
    body:
      "Value sütunu boş olan satırlar sessizce atlanır. Eşleşme beklerken hiç finding görmüyorsanız value değerlerinin dolu ve baş/son boşluklardan arındırılmış olduğunu kontrol edin.",
  },
];

export function InputGuide() {
  return (
    <div className="space-y-4">
      <Card className="border border-border shadow-sm">
        <CardHeader>
          <CardTitle className="text-sm">Input formatları</CardTitle>
          <CardDescription className="text-xs">
            Backend parser’ın beklediği formatlar; çalışan backend üzerinde deneyebileceğiniz
            güvenli örnek dosyalarla birlikte.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 lg:grid-cols-2">
          <Section
            icon={<FileText className="h-4 w-4 text-blue-600" />}
            title="IOC feed — CSV"
            children={
              <>
                <p className="text-xs text-muted-foreground">
                  UTF-8 (BOM olmadan). Virgülle ayrılmış. İlk satır header olmalıdır. Zorunlu
                  sütun: <code className="font-mono">value</code>. Opsiyonel sütunlar:{" "}
                  <code className="font-mono">confidence</code> (0–100, varsayılan 50),{" "}
                  <code className="font-mono">source</code>, <code className="font-mono">tags</code>.
                  Ekstra sütunlar yok sayılır. IOC type (ip, domain, url, sha256…) normaliser
                  tarafından value değerinin kendisinden algılanır.
                </p>
                <CodeBlock>{CSV_PREVIEW}</CodeBlock>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    downloadText(getSampleIocsCsv(), SAMPLE_IOCS_FILENAME, "text/csv")
                  }
                >
                  <Download className="mr-1.5 h-4 w-4" />
                  {SAMPLE_IOCS_FILENAME} indir
                </Button>
              </>
            }
          />
          <Section
            icon={<FileJson className="h-4 w-4 text-blue-600" />}
            title="Log file — NDJSON"
            children={
              <>
                <p className="text-xs text-muted-foreground">
                  UTF-8. Her satırda bir JSON objesi, <code className="font-mono">\n</code>{" "}
                  karakteri ile ayrılır. Loader tarafından okunan opsiyonel alanlar:{" "}
                  <code className="font-mono">@timestamp</code> veya{" "}
                  <code className="font-mono">timestamp</code> (ISO-8601). Correlator her satırın
                  tüm metnini taradığı için IOC değerleri herhangi bir alanda yer alabilir
                  (<code className="font-mono">src_ip</code>, <code className="font-mono">url</code>,{" "}
                  <code className="font-mono">file_hash_md5</code>, …).
                </p>
                <CodeBlock>{NDJSON_PREVIEW}</CodeBlock>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    downloadText(
                      getSampleEventsNdjson(),
                      SAMPLE_EVENTS_FILENAME,
                      "application/x-ndjson",
                    )
                  }
                >
                  <Download className="mr-1.5 h-4 w-4" />
                  {SAMPLE_EVENTS_FILENAME} indir
                </Button>
              </>
            }
          />
        </CardContent>
      </Card>

      <Card className="border border-border shadow-sm">
        <CardHeader>
          <CardTitle className="text-sm">
            <span className="inline-flex items-center gap-2">
              <ListChecks className="h-4 w-4 text-blue-600" />
              Hızlı kontrol listesi
            </span>
          </CardTitle>
          <CardDescription className="text-xs">
            Bir sweep çalıştırmadan önce bunları doğrulayın.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="grid gap-2 text-xs sm:grid-cols-2">
            {[
              "Feed dosyası IOC feed alanında, log alanında değil.",
              "Feed format seçici dosyayla uyumlu (csv / ndjson / misp-json / stix).",
              "CSV, 'value' sütunu içeren bir header satırıyla başlıyor.",
              "CSV, BOM olmadan UTF-8 ve virgülle ayrılmış.",
              "Log dosyası her satırda bir JSON objesi.",
              "Output mode seçili (analyst / summary / hash) — hash, hmac:<hex> döner.",
            ].map((line) => (
              <li
                key={line}
                className="rounded-md border border-border bg-muted/30 px-3 py-2 text-foreground/90"
              >
                {line}
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>

      <Card className="border border-border shadow-sm">
        <CardHeader>
          <CardTitle className="text-sm">
            <span className="inline-flex items-center gap-2">
              <FileWarning className="h-4 w-4 text-amber-600" />
              Sık yapılan hatalar
            </span>
          </CardTitle>
          <CardDescription className="text-xs">
            Sweep başarısız olduysa veya hiç finding üretilmediyse önce bu listeyi gözden geçirin.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="grid gap-3 sm:grid-cols-2">
            {COMMON_MISTAKES.map((m) => (
              <li
                key={m.title}
                className="rounded-md border border-border bg-card p-3"
              >
                <div className="mb-1 inline-flex items-center gap-2 text-sm font-medium text-foreground">
                  <AlertCircle className="h-4 w-4 text-amber-600" />
                  {m.title}
                </div>
                <p className="text-xs leading-relaxed text-muted-foreground">{m.body}</p>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}

function Section({
  icon,
  title,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-2 rounded-md border border-border bg-card p-3">
      <div className="inline-flex items-center gap-2 text-sm font-medium text-foreground">
        {icon}
        {title}
      </div>
      {children}
    </div>
  );
}

function CodeBlock({ children }: { children: string }) {
  return (
    <pre className="max-h-48 overflow-auto rounded-md border border-border bg-muted/40 p-2 text-[11px] leading-relaxed text-foreground/90">
      {children}
    </pre>
  );
}
