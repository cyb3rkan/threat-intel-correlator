/** @type {import('next').NextConfig} */

// Content-Security-Policy (Part 5, Finding 4):
//  - 'unsafe-eval' is removed from production builds; it is enabled only in
//    development, where Next.js Fast Refresh (HMR) requires eval. Production
//    bundles never evaluate strings, so the directive is dropped there.
//  - 'unsafe-inline' remains for script-src and style-src as a documented
//    residual: Next.js emits inline hydration/bootstrap scripts and the styling
//    layer emits inline styles whose content varies per page, so static hashing
//    is impractical. Eliminating it requires a per-request nonce set from
//    middleware (SSR only) that Next propagates to its inline scripts; that is
//    the recommended follow-up (tracked in docs/OPERATIONS.md). Residual risk is
//    already contained by default-src 'none', a strict connect-src allowlist,
//    object-src 'none', base-uri 'self', and frame-ancestors 'none'.
const isDev = process.env.NODE_ENV !== "production"
const scriptSrc = isDev
  ? "'self' 'unsafe-inline' 'unsafe-eval'"
  : "'self' 'unsafe-inline'"

const csp = [
  "default-src 'none'",
  `script-src ${scriptSrc}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' http://localhost:8000 http://127.0.0.1:8000",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join("; ")

const securityHeaders = [
  { key: "Content-Security-Policy", value: csp },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },
  { key: "X-Permitted-Cross-Domain-Policies", value: "none" },
]

const nextConfig = {
  // Docker imajını küçük tutmak için standalone çıktı: `next build` sonrası
  // .next/standalone altında kendi kendine yeten bir sunucu üretilir; runtime
  // imajı node_modules'un tamamını taşımak zorunda kalmaz.
  output: "standalone",
  // Turbopack'in workspace kökünü bu frontend klasörüne sabitle. Aksi halde
  // Next.js üst dizinlerdeki (boş) package-lock.json'ları görüp kökü yanlış
  // seçiyor ve .git / .venv dahil tüm üst ağacı dosya-izlemeye alarak belleği
  // dolduruyordu. import.meta.dirname bu dosyanın bulunduğu dizini verir.
  turbopack: {
    root: import.meta.dirname,
  },
  typescript: {
    ignoreBuildErrors: false,
  },
  images: {
    unoptimized: true,
  },
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
    ]
  },
}

export default nextConfig
