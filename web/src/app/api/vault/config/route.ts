import { NextResponse } from "next/server"

import { prisma } from "@/lib/prisma"

/**
 * Parâmetros públicos do vault: o que o cliente precisa **antes** de ter
 * qualquer chave.
 *
 * ✅ **Servir isto sem autenticação é correto e necessário**, não um descuido.
 * O cliente não consegue derivar chave nenhuma sem o `salt`, e não consegue
 * autenticar sem derivar. É o que todo vault Zero-Knowledge faz. Nada aqui abre
 * dado: o `salt` é público por construção, e o `wrappedVaultKey` e o `keyCheck`
 * são ciphertext sob a chave da senha mestra.
 *
 * ⛔ **Não existe `POST` nesta rota, e a ausência é deliberada.** Uma rota de
 * inicialização por HTTP era takeover remoto não autenticado: entre o deploy e o
 * primeiro acesso do dono, qualquer um que achasse a URL inicializava o vault com
 * o próprio `salt`/`authHash` e **trancava o dono para fora** — recuperável só
 * com acesso ao filesystem. A inicialização é `npm run vault:init`, local.
 *
 * `initialized: false` não vaza nada: é um vault de um usuário só, não há conta
 * a enumerar.
 */
export async function GET() {
  try {
    const cfg = await prisma.vaultConfig.findUnique({ where: { id: 1 } })

    if (!cfg) {
      return NextResponse.json({ initialized: false })
    }

    return NextResponse.json({
      initialized: true,
      salt: cfg.salt,
      kdfIterations: cfg.kdfIterations,
      wrappedVaultKey: cfg.wrappedVaultKey,
      keyCheck: cfg.keyCheck,
      // `authHash`, `failedAttempts` e `lockedUntil` NÃO saem daqui: o primeiro
      // é o que o atacante quer para o ataque offline, e os outros dois contam
      // a ele como anda o rate limit.
    })
  } catch {
    return NextResponse.json(
      { error: "Não foi possível ler a configuração do vault." },
      { status: 500 }
    )
  }
}
