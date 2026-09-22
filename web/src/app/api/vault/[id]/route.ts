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
    // ⛔ Exclusão FÍSICA, igual ao lado Python.
    //
    // ⚠️ ~~"Soft delete aqui é diferente do Python e de propósito: `deletedAt` é
    // a lápide de sincronização, e como não há re-cifragem por registro ela não
    // ressuscita segredo nenhum."~~ **O argumento respondia ao MECANISMO do
    // problema do Python, não ao DANO.** A linha continuava no Postgres, o `GET`
    // a escondia, e — pior aqui do que lá — como o envelope faz a `vaultKey`
    // **nunca rodar**, a credencial apagada seguia decifrável por qualquer chave
    // que o dono viesse a usar, para sempre, sem ele ter como saber que existia.
    // Não havia purga em lugar nenhum do repositório.
    //
    // O motivo real de alguém apagar uma credencial é a senha ter vazado.
    await prisma.credential.delete({ where: { id } })
    return NextResponse.json({ ok: true })
  } catch {
    return NextResponse.json({ error: "Falha ao apagar o registro." }, { status: 500 })
  }
}
