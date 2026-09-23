import { connection } from "next/server";

import VaultApp from "./VaultApp";

/**
 * ⛔ Este arquivo é um **server component** só por causa do `await connection()`,
 * e tirar essa linha quebra o site em produção de um jeito silencioso.
 *
 * O porquê, medido em 22/09/2026: a CSP com nonce (`src/proxy.ts`) só vale para
 * página **renderizada por requisição**. Sem isto, o `next build` prerenderizava
 * `/` como estático — HTML gerado no build, quando não existe requisição nem
 * cabeçalho, logo **sem nonce nenhum**. Resultado medido em `next start`:
 *
 *     9 <script> no HTML, 0 com nonce=, contra uma CSP que exige nonce
 *
 * E como o `script-src` usa `'strict-dynamic'`, o `'self'` passa a ser
 * **ignorado** pelo browser: nem os 7 `<script src>` carregavam. **Zero
 * JavaScript executava** — pior que o defeito original, em que ao menos o
 * runtime do React carregava.
 *
 * A doc do Next avisa (`content-security-policy.md:181`): *"To use a nonce, your
 * page must be dynamically rendered... Static pages are generated at build time,
 * when no request or response headers exist—so no nonce can be injected."*
 *
 * ⚠️ **Nenhum teste via isso**, porque eles sobem `next dev`, onde tudo é
 * dinâmico. Por isso o `scripts/gate.mjs` passou a reprovar se `/` reaparecer em
 * `.next/prerender-manifest.json` depois do build.
 */
export default async function Page() {
  // Espera a requisição chegar: é o que tira esta página do prerender.
  await connection();
  return <VaultApp />;
}
