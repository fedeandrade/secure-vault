import { verify } from "@node-rs/argon2"
import { NextResponse } from "next/server"

import { atrasoDe, authValueValido, origemConfere } from "@/lib/auth-guardas"
import { prisma } from "@/lib/prisma"
import { criarSessao } from "@/lib/session"

/**
 * Login: recebe o `authValue` derivado no browser e devolve uma sessão.
 *
 * ⚠️ **A ORDEM dos passos aqui é segurança, não estilo.** Força bruta *online* já
 * é cara para o atacante (produzir um `authValue` válido custa 600k PBKDF2). O
 * furo é a **assimetria**: um `authValue` inválido não custa nada a ele e custa
 * argon2id ao servidor — 64 MB por verificação. Algumas dezenas de POSTs
 * concorrentes com bytes aleatórios alocam gigabytes e derrubam o processo.
 * **Zero credenciais necessárias.**
 *
 * Por isso: valida formato → checa bloqueio → semáforo → argon2id. Inverter
 * qualquer par transforma esta rota num amplificador de DoS.
 */

/** Mesmos parâmetros do lado Python — RFC 9106 para uso interativo. */
const CUSTO_ARGON = { memoryCost: 65536, timeCost: 3, parallelism: 4 }

/**
 * Semáforo de concorrência em volta do argon2id.
 *
 * Em processo, de propósito e com limite conhecido: **não sobrevive a múltiplas
 * instâncias serverless**. É a primeira barreira, não a única — `failedAttempts`
 * e `lockedUntil` são persistidos justamente porque este contador não é.
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

  // 1. Formato — ANTES de tocar no banco ou no argon2id.
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

  // 2. Bloqueio temporário, persistido.
  if (cfg?.lockedUntil && cfg.lockedUntil > new Date()) {
    const faltam = Math.ceil((cfg.lockedUntil.getTime() - Date.now()) / 1000)
    return NextResponse.json(
      { error: `Muitas tentativas. Tente novamente em ${faltam}s.` },
      { status: 429, headers: { "Retry-After": String(faltam) } }
    )
  }

  // 3. Semáforo em volta do argon2id.
  await esperarVaga()
  try {
    // Vault não inicializado verifica contra um hash-dummy e devolve o MESMO 401:
    // sem isso, o tempo de resposta diria ao atacante se o vault existe. (Com um
    // usuário só não há conta a enumerar, mas responder diferente é hábito ruim
    // que sobrevive à próxima mudança.)
    const hashAlvo =
      cfg?.authHash ??
      "$argon2id$v=19$m=65536,t=3,p=4$c2VjdXJlLXZhdWx0LWR1bW15$0000000000000000000000000000000000000000000"

    let confere = false
    try {
      confere = await verify(hashAlvo, authValue, CUSTO_ARGON)
    } catch {
      confere = false // hash-dummy malformado cai aqui, e é o que se quer
    }

    if (!confere) {
      if (cfg) {
        const tentativas = cfg.failedAttempts + 1
        await prisma.vaultConfig.update({
          where: { id: 1 },
          data: {
            failedAttempts: tentativas,
            lockedUntil: new Date(Date.now() + atrasoDe(tentativas)),
          },
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
