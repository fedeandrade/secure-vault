import { NextResponse, type NextRequest } from "next/server"

/**
 * CSP com nonce por requisição.
 *
 * ⛔ **Isto existe porque a versão anterior QUEBRAVA o site inteiro.** A CSP
 * estava em `next.config.ts` com `script-src 'self'`, sem nonce e sem
 * `'unsafe-inline'` — e o Next 16 emite **três `<script>` inline** em toda
 * página (o `self.__next_r` e dois `self.__next_f.push(...)` com o payload RSC).
 * Todos eram bloqueados, o React nunca hidratava, e como `page.tsx` é
 * `"use client"` o resultado era um cartão estático: o `GET /api/vault/config`
 * nunca acontecia e o botão "Destrancar" não fazia nada.
 *
 * ⚠️ **E a justificativa que eu tinha escrito para não usar proxy era FALSA.**
 * Eu afirmei, no `next.config.ts` e no ROADMAP, que *"no Next 16 o middleware
 * roda no Edge, onde o `pg` não carrega"*. A doc da versão instalada diz o
 * contrário, em duas linhas:
 *
 *   proxy.md:255 — "Proxy defaults to using the Node.js runtime."
 *   proxy.md:806 — "Middleware is deprecated and renamed to Proxy. Proxy
 *                   defaults to the Node.js runtime"
 *
 * E um proxy que só gera nonce não importa `pg` de forma alguma. A premissa não
 * existia.
 *
 * ⚠️ Nenhum teste pegou isso: `rotas.test.ts` conferia o **cabeçalho** e passava,
 * porque nunca carregou a página. `next build` compila. Só abrir o HTML servido
 * e contar os inline sem nonce mostra o defeito.
 *
 * A checagem de sessão **não** vive aqui, e isso continua certo: cada rota chama
 * `sessaoValida()`. Misturar as duas coisas neste arquivo é o que empurraria uma
 * consulta ao Postgres para dentro do caminho de toda requisição, inclusive de
 * arquivo estático.
 */
export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64")
  const ehDev = process.env.NODE_ENV === "development"

  const csp = [
    "default-src 'self'",
    // `strict-dynamic`: scripts carregados por um script com nonce herdam a
    // confiança. É o que permite os chunks do Next sem listar cada um.
    // `unsafe-eval` SÓ em dev — o React usa `eval` para reconstruir stack de
    // erro do servidor no browser. Em produção nem o React nem o Next usam.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${ehDev ? " 'unsafe-eval'" : ""}`,
    // O Tailwind e o Next injetam <style> inline; com nonce eles passam sem
    // `unsafe-inline`.
    `style-src 'self' 'nonce-${nonce}' 'unsafe-inline'`,
    "img-src 'self' blob: data:",
    "font-src 'self'",
    // O vault só fala com a própria origem. Exfiltração para outro host morre
    // aqui, mesmo que um script consiga rodar.
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests",
  ].join("; ")

  const cabecalhos = new Headers(request.headers)
  // O Next lê `x-nonce` da requisição e carimba o nonce nos inline que ele
  // mesmo gera. Sem esta linha o nonce do cabeçalho não bate com nada.
  cabecalhos.set("x-nonce", nonce)
  cabecalhos.set("Content-Security-Policy", csp)

  const resposta = NextResponse.next({ request: { headers: cabecalhos } })
  resposta.headers.set("Content-Security-Policy", csp)
  return resposta
}

export const config = {
  matcher: [
    // Tudo menos os estáticos do próprio Next e o favicon: eles não executam
    // script e passar por aqui só gastaria.
    {
      source: "/((?!_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
}
