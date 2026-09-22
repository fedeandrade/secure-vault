import { NextResponse } from "next/server"

import { origemConfere } from "@/lib/auth-guardas"
import { encerrarSessao } from "@/lib/session"

export async function POST(req: Request) {
  if (!origemConfere(req.headers.get("origin"), req.headers.get("host"))) {
    return NextResponse.json({ error: "Origem inválida." }, { status: 403 })
  }
  await encerrarSessao()
  return NextResponse.json({ ok: true })
}
