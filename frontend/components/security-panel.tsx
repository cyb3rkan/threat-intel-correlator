"use client";

import * as React from "react";
import { Lock, Eye, KeyRound, FileLock2, Hash, ShieldCheck, Server } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const ITEMS: { icon: React.ReactNode; title: string; body: string }[] = [
  {
    icon: <Server className="h-4 w-4 text-blue-600" />,
    title: "Yalnızca lokal işlem",
    body:
      "Tüm korelasyon, enrichment ve scoring işlemleri lokal Python backend’inizde çalışır. Frontend sadece http://localhost:8000 ile iletişim kurar.",
  },
  {
    icon: <Eye className="h-4 w-4 text-blue-600" />,
    title: "Raw logs asla gösterilmez",
    body:
      "Log satırları backend sınırında ayıklanır. UI’a yalnızca eşleşme sayıları iletilir; orijinal log içeriği hiçbir zaman gönderilmez.",
  },
  {
    icon: <Lock className="h-4 w-4 text-blue-600" />,
    title: "Raw provider responses gizli kalır",
    body:
      "EnrichmentResult.truncated_raw alanı ve diğer raw provider payload değerleri backend dışına çıkmaz.",
  },
  {
    icon: <KeyRound className="h-4 w-4 text-blue-600" />,
    title: "API keys ve secrets gönderilmez",
    body:
      "Key değerleri backend içindeki OS keyring üzerinden okunur ve hiçbir API yanıtının parçası olmaz.",
  },
  {
    icon: <Hash className="h-4 w-4 text-blue-600" />,
    title: "Hash mode IOC değerlerini maskeler",
    body:
      "output_mode hash olarak ayarlandığında IOC değerleri hmac:<hex> pseudonym formatında döner. UI bunları olduğu gibi gösterir.",
  },
  {
    icon: <FileLock2 className="h-4 w-4 text-blue-600" />,
    title: "Yüklenen dosyalar backend tarafından temizlenir",
    body:
      "Dosyalar settings.paths.working_dir altında UUID isimlerle yazılır, safe_resolve_within ile doğrulanır ve her sweep sonunda silinir.",
  },
  {
    icon: <ShieldCheck className="h-4 w-4 text-blue-600" />,
    title: "Public-safe gösterim",
    body:
      "Yalnızca PublicFinding alanları render edilir. Tracebacks, dahili hata detayları ve raw provider payload değerleri kullanıcıya gösterilmez.",
  },
];

export function SecurityPanel() {
  return (
    <Card className="border border-border shadow-sm">
      <CardHeader>
        <CardTitle className="text-sm">Security & privacy</CardTitle>
        <CardDescription className="text-xs">
          Bu dashboard’un neleri gösterdiği ve neleri göstermediğine ilişkin özet.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="grid gap-3 sm:grid-cols-2">
          {ITEMS.map((it) => (
            <li
              key={it.title}
              className="rounded-md border border-border bg-muted/40 p-3"
            >
              <div className="mb-1 flex items-center gap-2 text-sm font-medium text-foreground">
                {it.icon}
                {it.title}
              </div>
              <p className="text-xs leading-relaxed text-muted-foreground">{it.body}</p>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
