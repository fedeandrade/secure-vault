import { defineConfig } from "vitest/config"

export default defineConfig({
  test: {
    // `node`, não `jsdom`: o que se testa aqui é WebCrypto, que o Node 22+ expõe
    // em `globalThis.crypto` com a mesma API do browser. Puxar jsdom só para
    // isso acrescentaria uma dependência grande a um gerenciador de senhas sem
    // testar nada a mais.
    environment: "node",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
  },
})
