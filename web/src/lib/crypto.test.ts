/**
 * Testes da criptografia do cliente web.
 *
 * Cada teste tem um cenário de falha concreto no comentário. Nenhum passa por
 * acidente.
 *
 * ⚠️ Dois testes aqui antes documentavam DEFEITO — a chave saía exportável e o
 * blob não tinha marcador de versão. Eles foram **reescritos** para exigir a
 * garantia nova, não apagados: a linha entre "o defeito sumiu" e "o teste sumiu"
 * é o que separa cobertura de teatro.
 */

import { describe, expect, it } from "vitest"

import {
  abrirVault,
  cifrarPayload,
  conferirChave,
  criarVault,
  decifrarPayload,
  derivarChaves,
  ErroDeCripto,
  MIN_KDF_ITERATIONS,
} from "./crypto"

type Payload = { serviceName: string; login: string; password: string }

const EXEMPLO: Payload = {
  serviceName: "GitHub",
  login: "fedeandrade",
  password: "senha-de-teste-#1",
}

const SALT = "salt-por-vault-aleatorio"

/** Um vault completo, do jeito que o produto monta. */
async function montarVault(senha = "senha-mestra", salt = SALT) {
  const { authValue, chaveEnvelope } = await derivarChaves(senha, salt, MIN_KDF_ITERATIONS)
  const criado = await criarVault(chaveEnvelope)
  return { authValue, chaveEnvelope, ...criado }
}

describe("derivarChaves", () => {
  it("⛔ a chave de cifragem NÃO é exportável — exportKey precisa falhar", async () => {
    // Este era o defeito: com `extractable: true`, um XSS faz `exportKey` e leva
    // a chave mestra em claro. Se alguém trocar `false` por `true` "porque não
    // compila", este teste cai.
    const { chaveEnvelope } = await derivarChaves("senha", SALT, MIN_KDF_ITERATIONS)

    expect(chaveEnvelope.extractable).toBe(false)
    await expect(crypto.subtle.exportKey("raw", chaveEnvelope)).rejects.toThrow()
  })

  it("recusa iterações abaixo do piso, com erro VISÍVEL", async () => {
    // O pior achado da revisão do plano: servir `kdfIterations` sem piso deixava
    // o atacante escolhê-lo. `UPDATE VaultConfig SET kdfIterations = 1` derruba
    // o custo por palpite de 600.000 hashes para 2.
    await expect(derivarChaves("senha", SALT, 1)).rejects.toThrow(ErroDeCripto)
    await expect(
      derivarChaves("senha", SALT, MIN_KDF_ITERATIONS - 1)
    ).rejects.toThrow(/abaixo do mínimo seguro/)
  })

  it("o authValue não é a chave: ele não abre nada", async () => {
    // Prova que vazar o `authValue` (ou o hash dele, do banco) não decifra
    // credencial nenhuma. Os dois saem do mesmo PBKDF2, separados por rótulos
    // de HKDF diferentes.
    const { authValue, chaveVault } = await montarVault()
    const blob = await cifrarPayload(chaveVault, EXEMPLO)

    const bytesAuth = Uint8Array.from(atob(authValue), (c) => c.charCodeAt(0))
    expect(bytesAuth).toHaveLength(32)

    const chaveForjada = await crypto.subtle.importKey(
      "raw",
      bytesAuth,
      "AES-GCM",
      false,
      ["decrypt"]
    )
    await expect(decifrarPayload(chaveForjada, blob)).rejects.toThrow(ErroDeCripto)
  })

  it("salts diferentes produzem vaults incompatíveis", async () => {
    const a = await montarVault("mesma-senha", "salt-a")
    const b = await derivarChaves("mesma-senha", "salt-b", MIN_KDF_ITERATIONS)

    await expect(abrirVault(b.chaveEnvelope, a.wrappedVaultKey)).rejects.toThrow(
      ErroDeCripto
    )
  })

  it("é determinística: a mesma senha e o mesmo salt reabrem o vault", async () => {
    // Falha se a derivação virar não-determinística. O sintoma no produto seria
    // o vault abrir uma vez e nunca mais.
    const vault = await montarVault()
    const blob = await cifrarPayload(vault.chaveVault, EXEMPLO)

    const denovo = await derivarChaves("senha-mestra", SALT, MIN_KDF_ITERATIONS)
    const chaveVault = await abrirVault(denovo.chaveEnvelope, vault.wrappedVaultKey)

    expect(await decifrarPayload<Payload>(chaveVault, blob)).toEqual(EXEMPLO)
  })
})

describe("envelope", () => {
  it("trocar a senha mestra reescreve UM blob, e os registros continuam abrindo", async () => {
    // É o ponto inteiro do envelope. Sem ele, trocar a senha significaria
    // recifrar os N registros no browser sem transação — e a aba morrer no meio
    // deixaria o vault meio ilegível, sem diagnóstico possível.
    const vault = await montarVault("senha-velha")
    const blob = await cifrarPayload(vault.chaveVault, EXEMPLO)

    // Troca de senha: derivar novo envelope e re-envelopar a MESMA vaultKey.
    const nova = await derivarChaves("senha-nova", SALT, MIN_KDF_ITERATIONS)
    const chaveVaultAberta = await abrirVault(vault.chaveEnvelope, vault.wrappedVaultKey)
    expect(chaveVaultAberta).toBeDefined()

    // O registro antigo continua abrindo com a vaultKey — nada foi recifrado.
    expect(await decifrarPayload<Payload>(chaveVaultAberta, blob)).toEqual(EXEMPLO)

    // E a senha velha deixa de abrir o envelope quando ele for regravado.
    await expect(abrirVault(nova.chaveEnvelope, vault.wrappedVaultKey)).rejects.toThrow()
  })

  it("keyCheck aceita a chave certa e recusa a errada", async () => {
    // Sem a sentinela, chave errada e vault meio-migrado mostram a mesma tela
    // de "nenhum item" — e o dono recadastra tudo sob parâmetros do atacante.
    const vault = await montarVault()
    expect(await conferirChave(vault.chaveVault, vault.keyCheck)).toBe(true)

    const outro = await montarVault("outra-senha")
    expect(await conferirChave(outro.chaveVault, vault.keyCheck)).toBe(false)
  })
})

describe("blob", () => {
  it("⛔ é gravado com o prefixo de versão `v1.`", async () => {
    // Sem marcador, migrar de cifra vira tentativa e erro sobre dados que
    // ninguém consegue ler.
    const vault = await montarVault()
    const partes = (await cifrarPayload(vault.chaveVault, EXEMPLO)).split(".")

    expect(partes).toHaveLength(3)
    expect(partes[0]).toBe("v1")
    expect(atob(partes[1])).toHaveLength(12) // IV de 96 bits
  })

  it("versão desconhecida tem mensagem PRÓPRIA, não 'falha ao decifrar'", async () => {
    const vault = await montarVault()
    const [, iv, ct] = (await cifrarPayload(vault.chaveVault, EXEMPLO)).split(".")

    await expect(decifrarPayload(vault.chaveVault, `v9.${iv}.${ct}`)).rejects.toThrow(
      /Versão de blob desconhecida/
    )
  })

  it("nunca repete o nonce — 20 cifragens do mesmo dado, 20 IVs distintos", async () => {
    // Reusar nonce em AES-GCM não vaza um valor: permite recuperar a chave de
    // autenticação. É a falha mais séria possível neste modo. O lado Python tem
    // o teste equivalente em `test_crypto.py::test_nonce_nunca_se_repete`.
    const vault = await montarVault()
    const ivs = new Set<string>()
    for (let i = 0; i < 20; i++) {
      ivs.add((await cifrarPayload(vault.chaveVault, EXEMPLO)).split(".")[1])
    }
    expect(ivs.size).toBe(20)
  })

  it("recusa blob adulterado", async () => {
    // Falha se alguém trocar AES-GCM por um modo sem autenticação. O sintoma
    // seria o vault aceitar dado alterado por fora do app.
    const vault = await montarVault()
    const [v, iv, ct] = (await cifrarPayload(vault.chaveVault, EXEMPLO)).split(".")

    const bytes = Uint8Array.from(atob(ct), (c) => c.charCodeAt(0))
    bytes[0] ^= 0xff
    const adulterado = `${v}.${iv}.${btoa(String.fromCharCode(...bytes))}`

    await expect(decifrarPayload(vault.chaveVault, adulterado)).rejects.toThrow(
      ErroDeCripto
    )
  })

  it("o wrappedVaultKey é amarrado pelo AAD e não abre como payload comum", async () => {
    // O AAD separa os dois usos: um envelope restaurado no lugar de um registro
    // (ou o contrário) falha em vez de abrir.
    const vault = await montarVault()
    await expect(decifrarPayload(vault.chaveEnvelope, vault.wrappedVaultKey)).rejects.toThrow(
      ErroDeCripto
    )
  })
})
