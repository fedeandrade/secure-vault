import { NextResponse } from "next/server"

import { prisma } from "@/lib/prisma"
import { origemConfere } from "@/lib/auth-guardas"
import { sessaoValida } from "@/lib/session"

const TAMANHO_MAXIMO = 64 * 1024

function blobValido(valor: unknown): valor is string {
  return typeof valor === "string" && valor.length > 0 && valor.length <= TAMANHO_MAXIMO
}

async function recusarSemSessao() {
  if (await sessaoValida()) return null
  return NextResponse.json({ error: "Não autenticado." }, { status: 401 })
}

export async function PUT(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const semSessao = await recusarSemSessao()
  if (semSessao) return semSessao
  if (!origemConfere(req.headers.get("origin"), req.headers.get("host"))) {
    return NextResponse.json({ error: "Origem inválida." }, { status: 403 })
  }

  try {
    const { id } = await params
    const { encryptedData } = await req.json()
    if (!blobValido(encryptedData)) {
      return NextResponse.json(
        { error: `encryptedData ausente, vazio ou maior que ${TAMANHO_MAXIMO} bytes.` },
        { status: 400 }
      )
    }

    const registro = await prisma.credential.update({
      where: { id },
      // `version` sobe a cada gravação. Hoje ninguém lê; existe para o AAD `v2`
      // amarrar o blob a `<id>|<version>` e fechar o ataque de restaurar o
      // `encryptedData` anterior de uma linha — que o cliente hoje decifra sem
      // erro nenhum, e o dono lê como atual a senha que acabou de trocar.
      data: { encryptedData, version: { increment: 1 } },
      select: { id: true, encryptedData: true, version: true, updatedAt: true },
    })
    return NextResponse.json(registro)
  } catch {
    return NextResponse.json({ error: "Falha ao atualizar o registro." }, { status: 500 })
  }
}

export async function DELETE(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const semSessao = await recusarSemSessao()
  if (semSessao) return semSessao
  if (!origemConfere(req.headers.get("origin"), req.headers.get("host"))) {
    return NextResponse.json({ error: "Origem inválida." }, { status: 403 })
  }

  try {
    const { id } = await params
    // ⚠️ Soft delete AQUI é diferente do lado Python, e de propósito: `deletedAt`
    // é a lápide de sincronização deste vault. O lado Python voltou a apagar
    // fisicamente porque lá o `vault passwd` re-cifrava a credencial apagada,
    // mantendo viva a senha que o dono apagou por ter vazado. Aqui não existe
    // re-cifragem por registro — o envelope resolve a troca de senha com UM
    // blob —, então a lápide não ressuscita segredo nenhum.
    await prisma.credential.update({ where: { id }, data: { deletedAt: new Date() } })
    return NextResponse.json({ ok: true })
  } catch {
    return NextResponse.json({ error: "Falha ao apagar o registro." }, { status: 500 })
  }
}
