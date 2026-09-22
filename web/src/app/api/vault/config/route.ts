import { NextResponse } from "next/server"

import { prisma } from "@/lib/prisma"
import { sessaoValida } from "@/lib/session"

/**
 * Parâmetros do vault. **O que é público e o que não é foi medido, não suposto.**
 *
 * ✅ `salt` e `kdfIterations` saem SEM autenticação, e isso é correto e
 * necessário: o cliente não consegue derivar chave nenhuma sem eles, e não
 * consegue autenticar sem derivar. É o que todo vault Zero-Knowledge faz.
 *
 * ⛔ **`wrappedVaultKey` e `keyCheck` NÃO saem sem sessão** — e a versão anterior
 * os servia. Isso entregava um **oráculo de quebra offline** a quem fizesse um
 * único `GET` na URL: com `salt` + `iterações` + `wrappedVaultKey`, testa-se
 * dicionário localmente (`PBKDF2 → HKDF → AES-GCM.decrypt`), e a tag do GCM diz
 * se acertou. Reproduzido em 22/09/2026: senha recuperada a **96 ms por
 * palpite**, sem banco roubado, sem login, sem tocar no rate limit e sem deixar
 * rastro no log.
 *
 * ⚠️ Corrige também o modelo de ameaça do `docs/SPEC.md`: o ataque offline custa
 * **PBKDF2-SHA256** por palpite, não argon2id. A diferença não é cosmética —
 * PBKDF2-SHA256 é exatamente o que GPU faz bem, e argon2id com 64 MB é
 * exatamente o que ela faz mal.
 *
 * ⛔ **Não existe `POST` aqui, e a ausência é deliberada.** Uma rota de
 * inicialização por HTTP era takeover remoto não autenticado: entre o deploy e o
 * primeiro acesso do dono, qualquer um inicializava o vault com o próprio
 * `salt`/`authHash` e **trancava o dono para fora**. A inicialização é
 * `npm run vault:init`, local.
 */
export async function GET() {
  try {
    const cfg = await prisma.vaultConfig.findUnique({ where: { id: 1 } })

    if (!cfg) {
      return NextResponse.json({ initialized: false })
    }

    // `authHash`, `failedAttempts` e `lockedUntil` nunca saem: o primeiro é o
    // que o atacante quer para o ataque offline, e os outros dois contam a ele
    // como anda o rate limit.
    const publico = {
      initialized: true,
      salt: cfg.salt,
      kdfIterations: cfg.kdfIterations,
    }

    if (!(await sessaoValida())) {
      return NextResponse.json(publico)
    }

    return NextResponse.json({
      ...publico,
      wrappedVaultKey: cfg.wrappedVaultKey,
      keyCheck: cfg.keyCheck,
    })
  } catch {
    return NextResponse.json(
      { error: "Não foi possível ler a configuração do vault." },
      { status: 500 }
    )
  }
}
