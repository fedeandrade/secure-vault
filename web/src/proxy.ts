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
    // ⚠️ **`'unsafe-inline'` saiu daqui, e a razão é que ele NUNCA valeu.** O
    // comentário anterior dizia que os estilos passavam "sem `unsafe-inline`"
    // enquanto o token estava escrito na linha — duas afirmações incompatíveis
    // no mesmo lugar. Pior: pela CSP3 (§"Does a source list allow all inline
    // behavior"), a presença de QUALQUER nonce-source já faz o browser ignorar
    // `'unsafe-inline'`. Ou seja, ele não protegia nem liberava nada: só
    // sugeria ao próximo leitor uma permissão que o browser descarta.
    //
    // Medido no HTML servido, nos dois modos, em 22/09/2026:
    //
    //   next start : 0 `<style>` inline, 1 `<link rel=stylesheet>`, 0 `style=`
    //   next dev   : 0 `<style>` inline, 1 `<link rel=stylesheet>`, 0 `style=`
    //
    // Ou seja, não há UM estilo inline para liberar — o CSS entra por `<link>`,
    // que `'self'` cobre. Se um dia entrar `<style>` gerado pelo Next, o nonce
    // o alcança (`content-security-policy.md:189`); se entrar atributo
    // `style="..."` escrito à mão, aí sim o browser bloqueia — e a saída certa é
    // `style-src-attr`, não reabrir `'unsafe-inline'` para o documento inteiro.
    `style-src 'self' 'nonce-${nonce}'`,
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
  // ⚠️ **O que carimba o nonce é a linha de baixo, não o `x-nonce`** — eu tinha
  // escrito o contrário aqui. A doc da versão instalada descreve o mecanismo em
  // três passos (`content-security-policy.md:185-187`): o proxy gera o nonce, o
  // Next **parseia o cabeçalho `Content-Security-Policy` da requisição** e
  // extrai o valor pelo padrão `'nonce-{valor}'`, e só então o aplica.
  //
  // O `x-nonce` existe para a PÁGINA ler o nonce (via `headers()`) quando ela
  // precisa carimbar um `<Script>` próprio. Nenhuma página daqui faz isso hoje;
  // a linha fica porque é o contrato que a doc documenta e custa nada — mas
  // remover o `Content-Security-Policy` da requisição, achando que o `x-nonce`
  // basta, apaga o nonce de TODOS os scripts e derruba o site em silêncio.
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
