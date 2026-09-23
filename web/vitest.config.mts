import { fileURLToPath } from "node:url"

// ⚠️ O Vitest NÃO carrega `.env` para `process.env` — o `loadEnv` do Vite só
// expõe o que tem prefixo `VITE_`, e em `import.meta.env`. Sem esta linha,
// `web/.env` existe, o `next build` o lê, o `prisma` o lê, e só os testes de
// rota continuam sendo PULADOS — em silêncio, dentro de um total verde.
// Os workers do Vitest herdam o `process.env` deste processo, então carregar
// aqui basta.
import "dotenv/config"
import { defineConfig } from "vitest/config"

export default defineConfig({
  // ⚠️ O `@/*` do `tsconfig.json` é resolvido pelo Next e pelo `tsc`, mas NÃO
  // pelo Vitest — ele não lê `paths` sozinho. Sem esta linha, qualquer teste que
  // importe código do app pelo alias falha com "Cannot find package
  // '@/generated/prisma/client'", e o arquivo inteiro vira "0 test": a suíte
  // reporta menos testes em vez de reprovar, que é o modo de falhar mais fácil
  // de ler como verde.
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  test: {
    // `node`, não `jsdom`: o que se testa aqui é WebCrypto, que o Node 22+ expõe
    // em `globalThis.crypto` com a mesma API do browser. Puxar jsdom só para
    // isso acrescentaria uma dependência grande a um gerenciador de senhas sem
    // testar nada a mais.
    environment: "node",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
  },
})
