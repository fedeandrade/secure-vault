#!/usr/bin/env node
/**
 * Cria o vault do site. **Roda local, nunca por HTTP.**
 *
 *     npm run vault:init
 *
 * Por que não é uma rota: `POST /api/vault/config` sem autenticação era takeover
 * remoto. Entre o deploy e o primeiro acesso do dono, qualquer um que achasse a
 * URL inicializava o vault com o próprio salt e trancava o dono para fora.
 *
 * ⚠️ **A derivação aqui TEM de ser idêntica à do browser.** O cliente fixa
 * `{salt, kdfIterations}` no primeiro unlock; se este script derivasse diferente,
 * o vault nasceria impossível de abrir. Por isso ele importa o **mesmo módulo**
 * que a tela usa, em vez de reimplementar — divergência entre duas cópias de um
 * KDF é o tipo de defeito que só aparece quando já há dado dentro.
 */

import { createInterface } from "node:readline"
import { Writable } from "node:stream"

import { hash } from "@node-rs/argon2"
import { PrismaClient } from "../src/generated/prisma/client.ts"
import { PrismaPg } from "@prisma/adapter-pg"

import { criarVault, derivarChaves, MIN_KDF_ITERATIONS } from "../src/lib/crypto.ts"

/** Mesmos parâmetros do lado Python (`.env.example`), RFC 9106 para uso interativo. */
const ARGON = { memoryCost: 65536, timeCost: 3, parallelism: 4 }

/** Lê sem ecoar. Senha em `process.argv` apareceria na lista de processos. */
function perguntarSenha(rotulo: string): Promise<string> {
  const mudo = new Writable({
    write(_pedaco, _cod, cb) {
      cb()
    },
  })
  const rl = createInterface({ input: process.stdin, output: mudo, terminal: true })
  process.stdout.write(rotulo)
  return new Promise<string>((resolve) => {
    rl.question("", (resposta) => {
      process.stdout.write("\n")
      rl.close()
      resolve(resposta)
    })
  })
}

/**
 * Piso de força da senha mestra.
 *
 * Por que isto não é enfeite: vazar o banco dá um **oráculo de verificação
 * offline** ao mesmo custo de atacar os ciphertexts. Depois de um vazamento, a
 * única coisa entre o atacante e o vault é a entropia desta senha.
 *
 * Client-side por natureza — o único que burla é o dono, e o vault é dele.
 */
function avaliarSenha(senha: string): string[] {
  const problemas: string[] = []
  if (senha.length < 12) problemas.push("menos de 12 caracteres")
  if (!/[a-z]/.test(senha) || !/[A-Z]/.test(senha)) problemas.push("sem maiúscula e minúscula")
  if (!/[0-9]/.test(senha)) problemas.push("sem dígito")
  if (!/[^A-Za-z0-9]/.test(senha)) problemas.push("sem símbolo")
  if (new Set(senha).size < 8) problemas.push("poucos caracteres distintos")
  return problemas
}

async function principal() {
  if (!process.env.DATABASE_URL) {
    console.error("DATABASE_URL não está definida. Copie web/.env.example para web/.env.")
    process.exit(1)
  }

  const prisma = new PrismaClient({
    adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL }),
  })

  try {
    const existente = await prisma.vaultConfig.findUnique({ where: { id: 1 } })
    if (existente) {
      console.error(
        "Este banco JÁ tem um vault. Reinicializar apagaria a chave e tornaria\n" +
          "todas as credenciais existentes ilegíveis para sempre. Se é isso mesmo\n" +
          "que você quer, apague a linha de VaultConfig à mão, de propósito."
      )
      process.exit(1)
    }

    const senha = await perguntarSenha("Senha mestra do vault web: ")
    const problemas = avaliarSenha(senha)
    if (problemas.length > 0) {
      console.error("\nSenha fraca — " + problemas.join(", ") + ".")
      console.error(
        "Depois de um vazamento do banco, é só a entropia desta senha que separa\n" +
          "o atacante do vault. Escolha outra."
      )
      process.exit(1)
    }
    const confirmacao = await perguntarSenha("Repita a senha mestra:  ")
    if (senha !== confirmacao) {
      console.error("\nAs senhas não conferem. Nada foi criado.")
      process.exit(1)
    }

    // Salt POR VAULT, aleatório. O global fixo que estava no `page.tsx` fazia
    // uma única rainbow table servir para qualquer instalação.
    const salt = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64")

    const { authValue, chaveEnvelope } = await derivarChaves(senha, salt, MIN_KDF_ITERATIONS)
    const { wrappedVaultKey, keyCheck } = await criarVault(chaveEnvelope)

    await prisma.vaultConfig.create({
      data: {
        salt,
        kdfIterations: MIN_KDF_ITERATIONS,
        // O servidor guarda o argon2id do authValue, nunca o authValue.
        authHash: await hash(authValue, ARGON),
        wrappedVaultKey,
        keyCheck,
      },
    })

    console.log("\nVault criado.")
    console.log(`  salt           : ${salt}`)
    console.log(`  kdfIterations  : ${MIN_KDF_ITERATIONS}`)
    console.log("\nA senha mestra não foi gravada em lugar nenhum. Perdê-la é perder o vault.")
  } finally {
    await prisma.$disconnect()
  }
}

principal().catch((erro) => {
  console.error(erro)
  process.exit(1)
})
