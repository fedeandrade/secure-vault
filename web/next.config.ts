import type { NextConfig } from "next";

/**
 * Cabeçalhos de segurança.
 *
 * ⚠️ `httpOnly` no cookie protege-o de ser **lido**, não de ser **usado**: um XSS
 * faz `fetch('/api/vault')` na mesma origem e o cookie viaja sozinho. Quem fecha
 * essa porta é a CSP.
 *
 * Definidos aqui e **não** em `middleware.ts` de propósito: no Next 16 o
 * middleware roda no runtime Edge por padrão, onde o driver `pg` não carrega —
 * e misturar cabeçalho com checagem de sessão no mesmo lugar acabaria empurrando
 * a sessão para lá. A sessão é conferida em cada rota, por `sessaoValida()`.
 */
const csp = [
  "default-src 'self'",
  // Sem `unsafe-inline` no script: é o que impede que uma injeção de HTML
  // execute. O Next 16 com App Router não precisa dele para hidratar.
  "script-src 'self'",
  // `unsafe-inline` no estilo é inevitável hoje — o Tailwind e o Next injetam
  // <style> inline. Não é o vetor que interessa aqui.
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  // O vault só fala com a própria origem. Qualquer exfiltração para outro host
  // morre aqui.
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests",
].join("; ");

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: csp },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          // Isola a origem: sem isto, uma aba aberta por `window.open` mantém
          // referência ao vault.
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
        ],
      },
      {
        // O vault nunca pode ser cacheado por proxy ou pelo browser.
        source: "/api/:path*",
        headers: [
          { key: "Cache-Control", value: "no-store, max-age=0" },
          { key: "Referrer-Policy", value: "no-referrer" },
        ],
      },
    ];
  },
};

export default nextConfig;
