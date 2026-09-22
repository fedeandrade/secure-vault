import type { NextConfig } from "next";

/**
 * Cabeçalhos de segurança que **não** dependem de nonce.
 *
 * ⚠️ A `Content-Security-Policy` NÃO está aqui — ela vive em `src/proxy.ts`,
 * porque precisa de um nonce novo a cada requisição.
 *
 * ⚠️ ~~"Definidos aqui e não em `middleware.ts` de propósito: no Next 16 o
 * middleware roda no runtime Edge por padrão, onde o driver `pg` não carrega."~~
 * **Falso, e custou caro.** A doc da versão instalada diz o oposto
 * (`proxy.md:255`: *"Proxy defaults to using the Node.js runtime"*), e um proxy
 * que só gera nonce nem importa `pg`. Com a afirmação errada eu deixei a CSP sem
 * nonce, e ela **bloqueava os três `<script>` inline que o Next emite** — o
 * React não hidratava e o site não funcionava em navegador nenhum.
 *
 * `httpOnly` no cookie protege-o de ser **lido**, não de ser **usado**: um XSS
 * faz `fetch('/api/vault')` na mesma origem e o cookie viaja sozinho. Quem fecha
 * essa porta é a CSP do proxy.
 */
const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
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
