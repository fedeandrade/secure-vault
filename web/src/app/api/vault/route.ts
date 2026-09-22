import { NextResponse } from "next/server"

import { prisma } from "@/lib/prisma"
import { origemConfere } from "@/lib/auth-guardas"
import { sessaoValida } from "@/lib/session"

/**
 * Limite de tamanho do blob.
 *
 * Antes disto, `encryptedData` era aceito sem validação de tipo nem de tamanho:
 * depois da autenticação ainda permitia encher o disco, e **antes dela, qualquer
 * um podia**. 64 KB comporta com folga uma credencial com notas longas.
 */
const TAMANHO_MAXIMO = 64 * 1024

function blobValido(valor: unknown): valor is string {
  return typeof valor === "string" && valor.length > 0 && valor.length <= TAMANHO_MAXIMO
}

/** Sem sessão válida, nada responde — nem com lista vazia. */
async function recusarSemSessao() {
  if (await sessaoValida()) return null
  return NextResponse.json({ error: "Não autenticado." }, { status: 401 })
}

export async function GET() {
  const semSessao = await recusarSemSessao()
  if (semSessao) return semSessao

  try {
    const registros = await prisma.credential.findMany({
      orderBy: { createdAt: "desc" },
      // `select` explícito: o dia em que alguém acrescentar uma coluna ao
      // modelo, ela não vaza para a resposta por acidente.
      select: { id: true, encryptedData: true, version: true, updatedAt: true },
    })
    return NextResponse.json(registros)
  } catch {
    return NextResponse.json({ error: "Falha ao ler o vault." }, { status: 500 })
  }
}

export async function POST(req: Request) {
  const semSessao = await recusarSemSessao()
  if (semSessao) return semSessao
  if (!origemConfere(req.headers.get("origin"), req.headers.get("host"))) {
    return NextResponse.json({ error: "Origem inválida." }, { status: 403 })
  }

  try {
    const { encryptedData } = await req.json()
    if (!blobValido(encryptedData)) {
      return NextResponse.json(
        { error: `encryptedData ausente, vazio ou maior que ${TAMANHO_MAXIMO} bytes.` },
        { status: 400 }
      )
    }

    const registro = await prisma.credential.create({
      data: { encryptedData },
      select: { id: true, encryptedData: true, version: true, updatedAt: true },
    })
    return NextResponse.json(registro, { status: 201 })
  } catch {
    return NextResponse.json({ error: "Falha ao gravar o registro." }, { status: 500 })
  }
}
