import { PrismaPg } from "@prisma/adapter-pg"

import { PrismaClient } from "@/generated/prisma/client"

// Em desenvolvimento o Next recarrega este módulo a cada edição. Sem o
// singleton no `globalThis`, cada recarga abre um pool novo e o Postgres acaba
// recusando conexão por limite atingido — um erro que só aparece depois de uns
// vinte salvamentos e parece aleatório.
const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient }

function criarCliente(): PrismaClient {
  const connectionString = process.env.DATABASE_URL
  if (!connectionString) {
    // Sem isto, `pg` cai nos padrões dele (localhost, usuário do processo,
    // database com o nome do usuário) e o app conecta em SILÊNCIO no banco
    // errado. O sintoma seria "o vault está vazio", não "faltou configurar".
    throw new Error(
      "DATABASE_URL não está definida. Copie web/.env.example para web/.env."
    )
  }
  // Prisma 7 não abre conexão sozinho: quem fala com o Postgres é o driver
  // adapter.
  return new PrismaClient({ adapter: new PrismaPg({ connectionString }) })
}

/// O cliente é criado na PRIMEIRA consulta, nunca ao carregar o módulo.
///
/// A checagem de `DATABASE_URL` precisa existir e precisa ser preguiçosa ao
/// mesmo tempo: `next build` roda este módulo para coletar as rotas, e no CI
/// (e na Vercel, em build) não há banco. Validar no topo deixaria o build
/// vermelho, e o "conserto" previsível de quem estiver com pressa é apagar a
/// checagem — que é justamente o buraco que ela fecha.
export const prisma = new Proxy({} as PrismaClient, {
  get(_alvo, propriedade) {
    const cliente = (globalForPrisma.prisma ??= criarCliente())
    return Reflect.get(cliente, propriedade, cliente)
  },
})
