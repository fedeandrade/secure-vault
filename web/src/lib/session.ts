import { createHash, randomBytes, timingSafeEqual } from "node:crypto"

import { cookies } from "next/headers"

import { prisma } from "@/lib/prisma"

/**
 * Sessão do site — em **banco**, não em JWT.
 *
 * Por que não JWT, apesar de dar mais trabalho:
 *
 * 1. **Revogação.** Cookie roubado + TTL deslizante renovável = acesso
 *    indefinido: basta uma requisição a cada poucos minutos. Trocar a senha
 *    mestra não invalidaria nada.
 * 2. `alg confusion` e gerência de segredo deixam de existir.
 * 3. O pior: se o segredo de assinatura mora no `.env` ao lado do banco, quem
 *    rouba o banco rouba o segredo, **forja um cookie e lê todos os ciphertexts
 *    sem passar pelo argon2id**. Sessão em banco torna segredo vazado inútil.
 *
 * ⚠️ **Não existe `SESSION_SECRET` aqui, e a ausência é decisão.** O plano previa
 * um, herdado do desenho com JWT. Com sessão em banco e token de CSPRNG não há
 * nada para assinar — uma variável de ambiente que ninguém usa faz o próximo a
 * mexer acreditar que existe uma proteção que não existe. Mesma razão pela qual
 * `tokenVersion` saiu do schema.
 */

/** `__Host-` força `Secure`, trava `Path=/` e **proíbe** `Domain`. */
const NOME_COOKIE = "__Host-sv-session"

/** TTL deslizante: renovado a cada requisição autenticada. */
const JANELA_INATIVIDADE_MS = 15 * 60 * 1000

/** Teto que a renovação NÃO empurra. Sem ele, cookie roubado dura para sempre. */
const VIDA_MAXIMA_MS = 8 * 60 * 60 * 1000

/**
 * O banco guarda o **SHA-256 do token**, nunca o token.
 *
 * ⛔ Isto não é zelo extra: o argumento inteiro a favor de sessão em banco foi
 * *"vazar o banco não dá acesso"*. Gravar o token cru entregaria todas as
 * sessões ativas a quem lesse uma linha — e desfaria a decisão sem que ninguém
 * percebesse, porque tudo continuaria funcionando.
 *
 * SHA-256 sem salt é adequado aqui, e só aqui: a entrada tem 256 bits de
 * entropia de CSPRNG, então não há dicionário possível. Senha de gente é outro
 * problema e usa argon2id.
 */
function digerir(token: string): string {
  return createHash("sha256").update(token).digest("hex")
}

export async function criarSessao(): Promise<void> {
  const token = randomBytes(32).toString("base64url")
  const agora = Date.now()

  await prisma.session.create({
    data: {
      id: digerir(token),
      expiresAt: new Date(agora + JANELA_INATIVIDADE_MS),
      absoluteExpiresAt: new Date(agora + VIDA_MAXIMA_MS),
    },
  })

  const jar = await cookies()
  jar.set(NOME_COOKIE, token, {
    httpOnly: true,
    // `secure` mesmo em dev: o prefixo `__Host-` exige, e o browser trata
    // `http://localhost` como origem confiável, então funciona sem HTTPS local.
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: Math.floor(VIDA_MAXIMA_MS / 1000),
  })
}

/**
 * Devolve `true` se a requisição tem sessão válida, renovando a janela.
 *
 * ⚠️ `httpOnly` protege o cookie de ser **lido**, não de ser **usado**: um XSS
 * faz `fetch('/api/vault')` na mesma origem e o cookie viaja sozinho. Quem
 * fecha essa porta é a CSP, não esta função.
 */
export async function sessaoValida(): Promise<boolean> {
  const jar = await cookies()
  const token = jar.get(NOME_COOKIE)?.value
  if (!token) return false

  const sessao = await prisma.session.findUnique({ where: { id: digerir(token) } })
  if (!sessao) return false

  const agora = new Date()
  if (sessao.expiresAt <= agora || sessao.absoluteExpiresAt <= agora) {
    // Limpa na hora: sessão vencida que fica no banco é lixo que um dia alguém
    // varre com a consulta errada.
    await prisma.session.delete({ where: { id: sessao.id } }).catch(() => {})
    return false
  }

  // Desliza — mas nunca além do teto absoluto.
  const novoFim = new Date(
    Math.min(agora.getTime() + JANELA_INATIVIDADE_MS, sessao.absoluteExpiresAt.getTime())
  )
  await prisma.session.update({ where: { id: sessao.id }, data: { expiresAt: novoFim } })
  return true
}

export async function encerrarSessao(): Promise<void> {
  const jar = await cookies()
  const token = jar.get(NOME_COOKIE)?.value
  if (token) {
    await prisma.session.delete({ where: { id: digerir(token) } }).catch(() => {})
  }
  jar.delete(NOME_COOKIE)
}

/** Usado na troca de senha mestra e no "encerrar todas as sessões". */
export async function encerrarTodasAsSessoes(): Promise<void> {
  await prisma.session.deleteMany({})
}

/**
 * Compara dois textos em tempo constante.
 *
 * Aqui serve para o `SETUP_TOKEN` e afins; o `authValue` NÃO passa por isto —
 * ele vai para o argon2id, que já é resistente a temporização.
 */
export function iguaisEmTempoConstante(a: string, b: string): boolean {
  const ba = Buffer.from(a)
  const bb = Buffer.from(b)
  if (ba.length !== bb.length) return false
  return timingSafeEqual(ba, bb)
}
