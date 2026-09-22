/**
 * Prova de ponta a ponta contra o Postgres REAL: init → login → destrancar →
 * gravar → ler. Nada aqui é mock.
 *
 * O que ela pega que `tsc`, `eslint`, `vitest` e `next build` NÃO pegam:
 * o adapter conecta mesmo, o schema bate com o código, o argon2id do servidor
 * aceita o authValue do cliente, e o envelope reabre depois de ir ao banco.
 */

import { hash, verify } from "@node-rs/argon2"
import { PrismaPg } from "@prisma/adapter-pg"

import { PrismaClient } from "../src/generated/prisma/client.ts"

const ARGON = { memoryCost: 65536, timeCost: 3, parallelism: 4 }
const SENHA = "Senha-Mestra-De-Teste-#2026"

const prisma = new PrismaClient({
  adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL! }),
})

function ok(rotulo: string, condicao: boolean) {
  console.log(`${condicao ? "  ok  " : " FALHA"} │ ${rotulo}`)
  if (!condicao) process.exitCode = 1
}

const cripto = await import(
  "../src/lib/crypto.ts"
)

try {
  // limpeza, para a prova ser repetível
  await prisma.credential.deleteMany({})
  await prisma.session.deleteMany({})
  await prisma.vaultConfig.deleteMany({})

  // --- 1. init ------------------------------------------------------------
  const salt = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64")
  const criacao = await cripto.derivarChaves(SENHA, salt, cripto.MIN_KDF_ITERATIONS)
  const novo = await cripto.criarVault(criacao.chaveEnvelope)

  await prisma.vaultConfig.create({
    data: {
      salt,
      kdfIterations: cripto.MIN_KDF_ITERATIONS,
      authHash: await hash(criacao.authValue, ARGON),
      wrappedVaultKey: novo.wrappedVaultKey,
      keyCheck: novo.keyCheck,
    },
  })
  ok("init grava VaultConfig no Postgres", true)

  // --- 2. o que a rota /config serviria -----------------------------------
  const cfg = await prisma.vaultConfig.findUnique({ where: { id: 1 } })
  ok("VaultConfig é singleton (id = 1)", cfg?.id === 1)
  ok("authHash NÃO é o authValue", cfg!.authHash !== criacao.authValue)
  ok("authHash tem formato argon2id", cfg!.authHash.startsWith("$argon2id$"))

  // --- 3. login: derivar de novo e conferir contra o hash -----------------
  const entrada = await cripto.derivarChaves(SENHA, cfg!.salt, cfg!.kdfIterations)
  ok("senha certa produz authValue aceito", await verify(cfg!.authHash, entrada.authValue, ARGON))

  const errada = await cripto.derivarChaves("senha-errada", cfg!.salt, cfg!.kdfIterations)
  ok("senha errada é recusada", !(await verify(cfg!.authHash, errada.authValue, ARGON)))

  // --- 4. sessão ----------------------------------------------------------
  const { createHash, randomBytes } = await import("node:crypto")
  const token = randomBytes(32).toString("base64url")
  const id = createHash("sha256").update(token).digest("hex")
  await prisma.session.create({
    data: {
      id,
      expiresAt: new Date(Date.now() + 900_000),
      absoluteExpiresAt: new Date(Date.now() + 28_800_000),
    },
  })
  const sessaoNoBanco = await prisma.session.findUnique({ where: { id } })
  ok("sessão grava o SHA-256, NUNCA o token", sessaoNoBanco !== null && sessaoNoBanco.id !== token)

  // --- 5. destrancar e gravar --------------------------------------------
  const chaveVault = await cripto.abrirVault(entrada.chaveEnvelope, cfg!.wrappedVaultKey)
  ok("envelope reabre depois de passar pelo banco", true)
  ok("keyCheck confere", await cripto.conferirChave(chaveVault, cfg!.keyCheck))

  const segredo = { serviceName: "GitHub", login: "fedeandrade", password: "s3nh4-real" }
  const blob = await cripto.cifrarPayload(chaveVault, segredo)
  const gravado = await prisma.credential.create({ data: { encryptedData: blob } })
  ok("blob gravado começa com v1.", gravado.encryptedData.startsWith("v1."))
  ok("version nasce em 1", gravado.version === 1)

  // --- 6. o banco é ilegível para quem não tem a chave --------------------
  const cru = await prisma.$queryRawUnsafe<{ encryptedData: string }[]>(
    'SELECT "encryptedData" FROM "Credential"'
  )
  const textoCru = JSON.stringify(cru)
  ok("nome do serviço NÃO aparece em claro no banco", !textoCru.includes("GitHub"))
  ok("login NÃO aparece em claro no banco", !textoCru.includes("fedeandrade"))
  ok("senha NÃO aparece em claro no banco", !textoCru.includes("s3nh4-real"))

  // --- 7. ler de volta ----------------------------------------------------
  const lido = await cripto.decifrarPayload<typeof segredo>(chaveVault, gravado.encryptedData)
  ok("o payload volta idêntico", JSON.stringify(lido) === JSON.stringify(segredo))

  // --- 8. chave errada não abre o que está no banco ----------------------
  let recusou = false
  try {
    await cripto.decifrarPayload(errada.chaveEnvelope, gravado.encryptedData)
  } catch {
    recusou = true
  }
  ok("chave errada é recusada no dado REAL do banco", recusou)

  // --- 9. troca de senha: UM blob, e os registros continuam abrindo -------
  //
  // ⛔ A versão anterior desta seção chamava `criarVault` e comentava
  // "re-envelopa a MESMA vaultKey". **Era falso**: `criarVault` sorteia uma
  // vaultKey nova, e gravá-la por cima apagava a única cópia da chave que
  // cifrou os registros — vault destruído para sempre, com o `keyCheck`
  // regravado junto dizendo que estava tudo bem.
  //
  // E a asserção era `count === 1`: contava LINHAS e nunca tentava decifrá-las,
  // então passava alegremente sobre um vault ilegível. Esta é a diferença entre
  // uma prova e um teste que dá verde.
  const nova = await cripto.derivarChaves("Outra-Senha-Mestra-#2026", cfg!.salt, cfg!.kdfIterations)
  const envelopeNovo = await cripto.reenvelopar(
    entrada.chaveEnvelope,
    nova.chaveEnvelope,
    cfg!.wrappedVaultKey
  )
  await prisma.vaultConfig.update({
    where: { id: 1 },
    // `keyCheck` NÃO é regravado: a vaultKey não mudou, então a sentinela antiga
    // continua correta. Regravá-la é justamente o que mascarava o erro.
    data: { authHash: await hash(nova.authValue, ARGON), wrappedVaultKey: envelopeNovo },
  })

  ok("troca de senha não reescreveu registro nenhum", (await prisma.credential.count()) === 1)

  const cfgDepois = await prisma.vaultConfig.findUnique({ where: { id: 1 } })
  const chaveDepois = await cripto.abrirVault(nova.chaveEnvelope, cfgDepois!.wrappedVaultKey)
  ok(
    "keyCheck ORIGINAL ainda confere depois da troca",
    await cripto.conferirChave(chaveDepois, cfgDepois!.keyCheck)
  )

  // A prova que faltava, e a única que pega o vault destruído:
  const depois = await cripto.decifrarPayload<typeof segredo>(
    chaveDepois,
    gravado.encryptedData
  )
  ok("o registro ANTIGO ainda abre com a senha NOVA", JSON.stringify(depois) === JSON.stringify(segredo))

  // E a senha velha deixa de abrir.
  let velhaRecusada = false
  try {
    await cripto.abrirVault(entrada.chaveEnvelope, cfgDepois!.wrappedVaultKey)
  } catch {
    velhaRecusada = true
  }
  ok("a senha VELHA deixa de abrir o vault", velhaRecusada)
} finally {
  await prisma.$disconnect()
}

console.log(process.exitCode ? "\nPROVA REPROVOU" : "\nPROVA APROVADA")
