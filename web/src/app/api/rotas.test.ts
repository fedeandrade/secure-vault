/**
 * Teste da camada HTTP: as rotas realmente devolvem 401 sem sessão?
 *
 * Por que isto não é redundante com `auth-guardas.test.ts`: lá se prova que a
 * FUNÇÃO que decide funciona. Aqui se prova que ela está **ligada** em cada
 * rota. Um `export async function GET` que esqueceu de chamar a guarda passaria
 * no outro teste e vazaria o vault inteiro.
 *
 * ⚠️ Sobe o Next de verdade (`next dev`) e bate nas rotas por HTTP. Precisa de
 * `DATABASE_URL`; sem ela os testes são **pulados**, nunca aprovados em falso.
 */

import { spawn, spawnSync, type ChildProcess } from "node:child_process"
import { setTimeout as esperar } from "node:timers/promises"

import { hash } from "@node-rs/argon2"
import { afterAll, beforeAll, describe, expect, it } from "vitest"

import { criarVault, derivarChaves, MIN_KDF_ITERATIONS } from "../../lib/crypto"
import { prisma } from "../../lib/prisma"

const TEM_BANCO = Boolean(process.env.DATABASE_URL)
const PORTA = 3987
const BASE = `http://127.0.0.1:${PORTA}`

let servidor: ChildProcess | undefined

async function esperarSubir(tentativas = 60): Promise<boolean> {
  for (let i = 0; i < tentativas; i++) {
    try {
      const r = await fetch(`${BASE}/api/vault/config`)
      if (r.status < 500) return true
    } catch {
      // ainda subindo
    }
    await esperar(1000)
  }
  return false
}

/** Alguém já está escutando na porta? */
async function portaOcupada(): Promise<boolean> {
  try {
    await fetch(`${BASE}/api/vault/config`, { signal: AbortSignal.timeout(2000) })
    return true
  } catch {
    return false
  }
}

/**
 * ⛔ **Matar o processo não basta no Windows, e o modo de falhar é silencioso.**
 *
 * `spawn(..., { shell: true })` não executa o Next: executa `cmd.exe`, que
 * executa `npx.cmd`, que executa o `node`. `servidor.kill()` mata o `cmd.exe` e
 * o neto continua escutando na 3987. Medido em 22/09/2026: o PID 6876 seguiu na
 * porta depois de a suíte terminar "verde".
 *
 * O estrago não é vazamento de processo — é **teste que valida código antigo**.
 * A rodada seguinte encontra a porta ocupada, bate no servidor velho e aprova
 * uma rota que o diff acabou de quebrar.
 */
function matarArvore(p: ChildProcess | undefined) {
  if (!p?.pid) return
  if (process.platform === "win32") {
    // `/T` derruba a árvore inteira (cmd → npx → node); `/F` não pergunta.
    spawnSync(`taskkill /pid ${p.pid} /T /F`, { shell: true, stdio: "ignore" })
  } else {
    // Com `detached`, o filho lidera o próprio grupo: PID negativo mata o grupo.
    try {
      process.kill(-p.pid, "SIGTERM")
    } catch {
      p.kill("SIGTERM")
    }
  }
}

beforeAll(async () => {
  if (!TEM_BANCO) return

  // ⛔ Recusar em vez de reaproveitar. Um servidor já na porta é, por definição,
  // de outro checkout ou de outra rodada — e aprovar o binário dele é pior que
  // não rodar teste nenhum, porque sai verde.
  if (await portaOcupada()) {
    throw new Error(
      `já existe algo escutando em ${BASE}. Estes testes NÃO vão rodar contra um ` +
        "servidor que eles não subiram — seria aprovar código que não é o deste " +
        "checkout. Derrube-o (Windows: `netstat -ano | findstr :" +
        `${PORTA}\` e \`taskkill /PID <pid> /F\`) e rode de novo.`
    )
  }

  // String única com `shell: true`: com lista de argumentos o Node 24 emite
  // DEP0190 (argumentos concatenados sem escape), e sem shell o `npx.cmd` do
  // Windows dá EINVAL. A porta é uma constante deste arquivo, não entrada.
  servidor = spawn(`npx next dev --port ${PORTA}`, {
    cwd: process.cwd(),
    shell: true,
    stdio: "ignore",
    detached: process.platform !== "win32",
    env: { ...process.env },
  })
  const subiu = await esperarSubir()
  if (!subiu) {
    matarArvore(servidor)
    throw new Error("o Next não subiu a tempo")
  }
}, 120_000)

afterAll(() => {
  matarArvore(servidor)
})

describe.skipIf(!TEM_BANCO)("rotas sem sessão", () => {
  /** As 4 rotas do vault, com o método que cada uma expõe. */
  const protegidas: Array<[string, string, unknown?]> = [
    ["GET", "/api/vault"],
    ["POST", "/api/vault", { encryptedData: "v1.aaaa.bbbb" }],
    ["PUT", "/api/vault/qualquer-id", { encryptedData: "v1.aaaa.bbbb" }],
    ["DELETE", "/api/vault/qualquer-id"],
  ]

  it.each(protegidas)(
    "⛔ %s %s devolve 401 sem cookie",
    async (metodo, caminho, corpo) => {
      const res = await fetch(BASE + caminho, {
        method: metodo,
        headers: corpo ? { "Content-Type": "application/json" } : undefined,
        body: corpo ? JSON.stringify(corpo) : undefined,
      })
      expect(res.status).toBe(401)

      // E o corpo não pode trazer dado nenhum junto do 401.
      const texto = await res.text()
      expect(texto).not.toMatch(/encryptedData/)
    }
  )

  it("a rota de config responde SEM autenticação, e isso é correto", async () => {
    // O cliente precisa do salt antes de ter qualquer chave. O que ela não pode
    // fazer é vazar o que abre o vault.
    const res = await fetch(`${BASE}/api/vault/config`)
    expect(res.status).toBe(200)

    const cfg = await res.json()
    expect(cfg).not.toHaveProperty("authHash")
    expect(cfg).not.toHaveProperty("failedAttempts")
    expect(cfg).not.toHaveProperty("lockedUntil")
  })

  it("⛔ sem sessão, /config NÃO entrega wrappedVaultKey nem keyCheck", async () => {
    // Esta é a diferença entre "o salt é público" e "o oráculo de quebra é
    // público". Com salt + iterações + `wrappedVaultKey`, um estranho faz UM
    // `GET`, vai embora e testa dicionário offline: `PBKDF2 → HKDF →
    // AES-GCM.decrypt`, e a tag do GCM diz se acertou. Medido em 22/09/2026:
    // 96 ms por palpite, sem banco roubado, sem login, sem tocar no rate limit
    // e sem rastro no log.
    const cfg = await (await fetch(`${BASE}/api/vault/config`)).json()

    expect(cfg).not.toHaveProperty("wrappedVaultKey")
    expect(cfg).not.toHaveProperty("keyCheck")
    // O que PODE sair sem autenticação, porque o cliente precisa antes de ter
    // qualquer chave:
    expect(Object.keys(cfg).sort()).toEqual(
      cfg.initialized ? ["initialized", "kdfIterations", "salt"] : ["initialized"]
    )
  })

  it("⛔ NÃO existe POST em /api/vault/config", async () => {
    // Uma rota pública de inicialização era takeover remoto: qualquer um
    // inicializava o vault com o próprio salt entre o deploy e o primeiro
    // acesso do dono, e o "recusa se já existir" trancava o dono para fora.
    const res = await fetch(`${BASE}/api/vault/config`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ salt: "do-atacante", kdfIterations: 1 }),
    })
    expect(res.status).toBe(405)
  })
})

describe.skipIf(!TEM_BANCO)("login", () => {
  it("⛔ authValue malformado é recusado — e rápido, sem chegar no argon2id", async () => {
    // O custo é a questão: argon2id aloca 64 MB por verificação. Se bytes
    // aleatórios chegassem lá, algumas dezenas de requisições derrubariam o
    // processo sem nenhuma credencial.
    const inicio = Date.now()
    const res = await fetch(`${BASE}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ authValue: "lixo" }),
    })
    const decorrido = Date.now() - inicio

    expect(res.status).toBe(401)
    // Um argon2id com m=65536 não termina em 200ms. Se terminou, a validação
    // de formato não barrou antes.
    expect(decorrido).toBeLessThan(2000)
  })

  it("recusa corpo que não é JSON", async () => {
    const res = await fetch(`${BASE}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "nao-e-json",
    })
    expect(res.status).toBe(400)
  })

  it("⛔ recusa requisição de outra origem", async () => {
    const res = await fetch(`${BASE}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://malicioso.com" },
      body: JSON.stringify({ authValue: "A".repeat(43) + "=" }),
    })
    expect(res.status).toBe(403)
  })
})

describe.skipIf(!TEM_BANCO)("atraso de login", () => {
  /**
   * ⛔ **O defeito que este bloco fixa: o atraso punia o DONO.**
   *
   * `failedAttempts` é global — o vault tem um usuário só. A versão anterior
   * pagava `atrasoDe(failedAttempts)` **antes** do `verify`, então 9 palpites
   * errados de um estranho colocavam o atraso no teto e o dono, digitando a
   * senha **certa**, esperava 30 s antes de qualquer verificação acontecer.
   * O comentário na rota afirmava o contrário, e nenhum teste olhava.
   *
   * A prova precisa das duas metades: o atacante continua pagando, o dono não.
   * Um teste só da metade "o dono entra rápido" passaria se alguém removesse o
   * atraso inteiro.
   */
  const SENHA = "Senha-Do-Teste-De-Atraso-#2026"
  /** `atrasoDe(6)` = 250 × 2⁴ = 4000 ms. Grande o bastante para ser inequívoco. */
  const TENTATIVAS = 6
  const ATRASO_ESPERADO = 4000

  let authValue = ""

  beforeAll(async () => {
    const salt = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64")
    const derivado = await derivarChaves(SENHA, salt, MIN_KDF_ITERATIONS)
    const vault = await criarVault(derivado.chaveEnvelope)
    authValue = derivado.authValue

    await prisma.session.deleteMany({})
    await prisma.vaultConfig.deleteMany({})
    await prisma.vaultConfig.create({
      data: {
        salt,
        kdfIterations: MIN_KDF_ITERATIONS,
        authHash: await hash(authValue, { memoryCost: 65536, timeCost: 3, parallelism: 4 }),
        wrappedVaultKey: vault.wrappedVaultKey,
        keyCheck: vault.keyCheck,
      },
    })
  }, 60_000)

  afterAll(async () => {
    await prisma.$disconnect()
  })

  async function tentar(valor: string) {
    const inicio = Date.now()
    const res = await fetch(`${BASE}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ authValue: valor }),
    })
    return { status: res.status, decorrido: Date.now() - inicio }
  }

  it("quem ERRA paga o atraso acumulado", async () => {
    await prisma.vaultConfig.update({
      where: { id: 1 },
      data: { failedAttempts: TENTATIVAS },
    })
    // base64 válido de 32 bytes, e errado: passa o guard de formato e morre no
    // argon2id, que é exatamente o caminho que deve custar caro.
    const errado = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64")

    const r = await tentar(errado)
    expect(r.status).toBe(401)
    // margem de 10% para o relógio; o ponto é que os 4 s foram pagos.
    expect(r.decorrido).toBeGreaterThanOrEqual(ATRASO_ESPERADO * 0.9)
  }, 30_000)

  it("⛔ o DONO, com a senha certa, NÃO paga o atraso do estranho", async () => {
    await prisma.vaultConfig.update({
      where: { id: 1 },
      data: { failedAttempts: TENTATIVAS },
    })

    const r = await tentar(authValue)
    expect(r.status).toBe(200)
    // argon2id com m=65536 leva ~25 ms. 1,5 s é folga larga e ainda assim muito
    // abaixo dos 4 s — se o atraso voltar para antes do `verify`, isto cai.
    expect(r.decorrido).toBeLessThan(1500)

    // E o contador zera no acerto, senão o próximo login herdaria a punição.
    const cfg = await prisma.vaultConfig.findUnique({ where: { id: 1 } })
    expect(cfg?.failedAttempts).toBe(0)
  }, 30_000)
})

describe.skipIf(!TEM_BANCO)("cabeçalhos", () => {
  it("a CSP está presente e proíbe enquadramento e script inline", async () => {
    const res = await fetch(`${BASE}/`)
    const csp = res.headers.get("content-security-policy") ?? ""

    expect(csp).toContain("frame-ancestors 'none'")
    expect(csp).toContain("object-src 'none'")
    expect(csp).toContain("connect-src 'self'")
    // `unsafe-inline` em script-src anularia a proteção contra XSS.
    expect(csp).not.toMatch(/script-src[^;]*unsafe-inline/)
  })

  it("⛔ TODO script inline da página carrega nonce — senão o site não hidrata", async () => {
    // Este teste existe porque a versão anterior da CSP QUEBRAVA o produto e
    // nenhum teste pegou. O que havia conferia só o CABEÇALHO, e passava: ele
    // nunca carregava a página.
    //
    // O Next 16 emite três `<script>` inline em toda página (`self.__next_r` e
    // dois `self.__next_f.push(...)`, que é o payload RSC). Com
    // `script-src 'self'` sem nonce, o browser bloqueia os três, o React não
    // hidrata, e como `page.tsx` é "use client" sobra um cartão estático: o
    // `GET /api/vault/config` nunca acontece e "Destrancar" não faz nada.
    const res = await fetch(`${BASE}/`)
    const html = await res.text()
    const csp = res.headers.get("content-security-policy") ?? ""

    const nonceDoCabecalho = csp.match(/'nonce-([^']+)'/)?.[1]
    expect(nonceDoCabecalho, "a CSP precisa trazer um nonce").toBeTruthy()

    // Todo <script> sem `src` é inline e precisa do nonce.
    const inline = [...html.matchAll(/<script(?![^>]*\ssrc=)([^>]*)>/gi)].map((m) => m[1])
    expect(inline.length, "o Next emite inline; se não emitir, revise o teste").toBeGreaterThan(0)

    for (const atributos of inline) {
      expect(atributos, `<script${atributos}> está sem nonce`).toContain(
        `nonce="${nonceDoCabecalho}"`
      )
    }
  })

  it("as respostas da API não podem ser cacheadas", async () => {
    const res = await fetch(`${BASE}/api/vault/config`)
    expect(res.headers.get("cache-control")).toContain("no-store")
  })
})
