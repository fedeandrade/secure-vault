import { setTimeout as esperar } from "node:timers/promises"

import { verify } from "@node-rs/argon2"
import { NextResponse } from "next/server"

import { atrasoDe, authValueValido, origemConfere } from "@/lib/auth-guardas"
import { prisma } from "@/lib/prisma"
import { criarSessao } from "@/lib/session"

/**
 * Login: recebe o `authValue` derivado no browser e devolve uma sessão.
 *
 * ⚠️ **A ORDEM dos passos aqui é segurança, não estilo:** formato → atraso →
 * semáforo → argon2id.
 *
 * ⚠️ **Mas o argumento que eu tinha escrito para a validação de formato era
 * errado**, e vale corrigir para ninguém "otimizar" o guard fora. Ele NÃO é o
 * que impede o amplificador de DoS: produzir base64 válido de 32 bytes
 * aleatórios custa zero ao atacante, e o próprio `auth-guardas.test.ts` prova
 * que esse lixo passa. **Quem segura a memória é o semáforo** (teto de
 * 2 × 64 MB). O guard de formato serve para rejeitar cedo o que é obviamente
 * inválido, e só.
 */

/** Mesmos parâmetros do lado Python — RFC 9106 para uso interativo. */
const CUSTO_ARGON = { memoryCost: 65536, timeCost: 3, parallelism: 4 }

/**
 * Semáforo de concorrência em volta do argon2id — a barreira que realmente
 * limita a memória alocada.
 *
 * Em processo, de propósito e com limite conhecido: **não sobrevive a múltiplas
 * instâncias serverless**. Por isso `failedAttempts` é persistido.
 */
const LIMITE_SIMULTANEO = 2
let emVoo = 0

function esperarVaga(): Promise<void> {
  return new Promise((resolve) => {
    const tentar = () => {
      if (emVoo < LIMITE_SIMULTANEO) {
        emVoo++
        resolve()
      } else {
        setTimeout(tentar, 25)
      }
    }
    tentar()
  })
}

export async function POST(req: Request) {
  if (!origemConfere(req.headers.get("origin"), req.headers.get("host"))) {
    return NextResponse.json({ error: "Origem inválida." }, { status: 403 })
  }

  let authValue: unknown
  try {
    authValue = (await req.json())?.authValue
  } catch {
    return NextResponse.json({ error: "Corpo inválido." }, { status: 400 })
  }
  if (!authValueValido(authValue)) {
    return NextResponse.json({ error: "Credenciais inválidas." }, { status: 401 })
  }

  const cfg = await prisma.vaultConfig.findUnique({ where: { id: 1 } })

  // ⛔ O atraso é pago POR ESTA REQUISIÇÃO, não gravado como portão global.
  //
  // A versão anterior escrevia `lockedUntil` em `VaultConfig`, que é singleton:
  // qualquer um mandando 1 requisição por segundo com bytes aleatórios mantinha
  // o portão fechado para **todo mundo, inclusive o dono**, indefinidamente. Da
  // 9ª falha em diante o atraso já estava no teto de 30 s, e cada 429 custava ao
  // atacante praticamente nada — ele saía antes do semáforo e antes do argon2id.
  // O `Retry-After` ainda dizia a ele quando a janela abria.
  //
  // Pagando aqui, o custo recai sobre quem errou. O dono que digita a senha
  // certa entra na hora, mesmo com alguém martelando a rota em paralelo.
  const atraso = atrasoDe(cfg?.failedAttempts ?? 0)
  if (atraso > 0) await esperar(atraso)

  await esperarVaga()
  try {
    // Vault não inicializado verifica contra um hash-dummy BEM-FORMADO e devolve
    // o mesmo 401: sem isso o tempo de resposta diria se o vault existe. Medido:
    // 24,6 ms com o dummy contra 26,9 ms com um hash real.
    const hashAlvo =
      cfg?.authHash ??
      "$argon2id$v=19$m=65536,t=3,p=4$c2VjdXJlLXZhdWx0LWR1bW15MDAwMA$Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4"

    let confere = false
    try {
      confere = await verify(hashAlvo, authValue, CUSTO_ARGON)
    } catch {
      confere = false
    }

    if (!confere) {
      if (cfg) {
        await prisma.vaultConfig.update({
          where: { id: 1 },
          data: { failedAttempts: cfg.failedAttempts + 1 },
        })
      }
      return NextResponse.json({ error: "Credenciais inválidas." }, { status: 401 })
    }

    if (cfg && cfg.failedAttempts !== 0) {
      await prisma.vaultConfig.update({
        where: { id: 1 },
        data: { failedAttempts: 0, lockedUntil: null },
      })
    }

    await criarSessao()
    return NextResponse.json({ ok: true })
  } finally {
    emVoo--
  }
}
