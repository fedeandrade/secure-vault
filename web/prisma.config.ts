// `dotenv/config` é obrigatório: o CLI do Prisma 7 deixou de carregar `.env`
// sozinho. Sem esta linha, `DATABASE_URL` chega vazia em `migrate`/`studio` e o
// erro que aparece é de conexão, não de configuração.
import "dotenv/config"
import { defineConfig } from "prisma/config"

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: {
    path: "prisma/migrations",
  },
  datasource: {
    // Medido em 22/09/2026: `env("DATABASE_URL")` NÃO é preguiçoso — ele resolve
    // ao CARREGAR o config e aborta com `PrismaConfigEnvError` se a variável não
    // existir. Isso quebraria `prisma generate` no CI e no `next build` da Vercel,
    // onde a URL do banco não precisa (nem deve) estar presente para gerar tipos.
    // Com `process.env`, generate passa sem a variável e só `migrate`/`studio`
    // reclamam — que é quando a conexão realmente é necessária.
    url: process.env["DATABASE_URL"],
  },
})
