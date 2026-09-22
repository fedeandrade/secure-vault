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
  reenvelopar,
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
  it("⛔ trocar a senha mestra reescreve UM blob e o registro ANTIGO continua abrindo", async () => {
    // ⚠️ A versão anterior deste teste passava sem provar nada: ela derivava a
    // chave nova, NÃO a usava, abria o envelope velho com a chave velha e
    // afirmava que a chave nova não abre o envelope velho — trivialmente
    // verdadeiro, e o oposto do requisito. Enquanto isso o único procedimento de
    // troca que existia no repo chamava `criarVault` de novo, sorteava uma
    // vaultKey NOVA e destruía o vault inteiro, com o `keyCheck` dizendo `true`.
    //
    // O que este teste exige agora: decifrar o registro gravado ANTES da troca,
    // usando a chave reaberta DEPOIS dela. Se alguém trocar `reenvelopar` por
    // `criarVault`, esta linha cai.
    const vault = await montarVault("senha-velha")
    const blobAntigo = await cifrarPayload(vault.chaveVault, EXEMPLO)

    const nova = await derivarChaves("senha-nova", SALT, MIN_KDF_ITERATIONS)
    const envelopeNovo = await reenvelopar(
      vault.chaveEnvelope,
      nova.chaveEnvelope,
      vault.wrappedVaultKey
    )

    // O envelope mudou...
    expect(envelopeNovo).not.toBe(vault.wrappedVaultKey)
    // ...mas a vaultKey dentro dele é a MESMA.
    const chaveDepois = await abrirVault(nova.chaveEnvelope, envelopeNovo)
    expect(await decifrarPayload<Payload>(chaveDepois, blobAntigo)).toEqual(EXEMPLO)

    // E o keyCheck original continua valendo, porque a vaultKey não mudou.
    expect(await conferirChave(chaveDepois, vault.keyCheck)).toBe(true)

    // A senha velha deixa de abrir o envelope novo.
    await expect(abrirVault(vault.chaveEnvelope, envelopeNovo)).rejects.toThrow(
      ErroDeCripto
    )
  })

  it("⛔ `criarVault` no lugar de `reenvelopar` DESTRÓI o vault — e o keyCheck aprova", async () => {
    // Este teste fixa o defeito para que ele não volte disfarçado. Ele não
    // verifica um comportamento desejado: verifica que o caminho errado é
    // detectavelmente errado, e que a sentinela NÃO é quem o detecta.
    const vault = await montarVault("senha-velha")
    const blobAntigo = await cifrarPayload(vault.chaveVault, EXEMPLO)

    const nova = await derivarChaves("senha-nova", SALT, MIN_KDF_ITERATIONS)
    const errado = await criarVault(nova.chaveEnvelope) // ⛔ vaultKey nova

    const chaveErrada = await abrirVault(nova.chaveEnvelope, errado.wrappedVaultKey)

    // A sentinela regravada junto APROVA o vault destruído. É por isso que ela
    // não pode ser a única verificação antes de renderizar.
    expect(await conferirChave(chaveErrada, errado.keyCheck)).toBe(true)

    // E o dado real não abre.
    await expect(decifrarPayload(chaveErrada, blobAntigo)).rejects.toThrow(ErroDeCripto)
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
