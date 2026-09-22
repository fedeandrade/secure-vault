/**
 * Testes da criptografia do cliente web.
 *
 * O que estes testes existem para pegar: mudança silenciosa no formato do blob
 * ou na derivação. Nenhum deles passa por acidente — cada um tem um cenário de
 * falha concreto escrito no comentário.
 *
 * ⚠️ Vários testes aqui documentam o estado de HOJE, que a Fase 1 do plano vai
 * mudar de propósito (`docs/planos/2026-09-22-web-seguro-e-tui-completa.md`).
 * Eles estão marcados. Quando a Fase 1 quebrá-los, é sinal de progresso — mas o
 * teste tem de ser REESCRITO para a garantia nova, nunca apagado.
 */

import { describe, expect, it } from "vitest"

import { decryptPayload, deriveKey, encryptPayload } from "./crypto"

type Payload = { serviceName: string; login: string; password: string }

const EXEMPLO: Payload = {
  serviceName: "GitHub",
  login: "fedeandrade",
  password: "senha-de-teste-#1",
}

describe("deriveKey", () => {
  it("deriva chaves DIFERENTES para salts diferentes", async () => {
    // Falha se: alguém ignorar o salt na derivação. Hoje o `page.tsx` usa um
    // salt global fixo (`secure-vault-global-salt`), o que é o defeito que a
    // Fase 1 conserta — mas a FUNÇÃO já respeita o salt, e é isso que este
    // teste prende. Se ela parar de respeitar, o conserto da Fase 1 seria
    // cosmético e ninguém perceberia.
    const a = await deriveKey("mesma-senha", "salt-a")
    const b = await deriveKey("mesma-senha", "salt-b")

    const blob = await encryptPayload(a, EXEMPLO)
    await expect(decryptPayload<Payload>(b, blob)).rejects.toThrow()
  })

  it("deriva a MESMA chave para a mesma senha e o mesmo salt", async () => {
    // Falha se: a derivação virar não-determinística (nonce dentro do KDF, por
    // exemplo). O sintoma no produto seria o vault abrir uma vez e nunca mais.
    const a = await deriveKey("senha", "salt")
    const b = await deriveKey("senha", "salt")

    const blob = await encryptPayload(a, EXEMPLO)
    expect(await decryptPayload<Payload>(b, blob)).toEqual(EXEMPLO)
  })

  it("⚠️ HOJE devolve uma chave EXPORTÁVEL — a Fase 1 tem de derrubar isto", async () => {
    // Este teste passa porque o código está ERRADO, e existe para que a
    // correção seja visível: `crypto.ts` pede `extractable = true`, então um XSS
    // faz `exportKey` e leva a chave mestra em claro.
    //
    // Quando a Fase 1 entrar, este teste PRECISA virar
    // `await expect(crypto.subtle.exportKey(...)).rejects.toThrow()`.
    const chave = await deriveKey("senha", "salt")
    expect(chave.extractable).toBe(true)

    const bruta = await crypto.subtle.exportKey("raw", chave)
    expect(bruta.byteLength).toBe(32)
  })
})

describe("encryptPayload / decryptPayload", () => {
  it("fecha o ciclo: o que entra cifrado sai igual", async () => {
    const chave = await deriveKey("senha", "salt")
    const blob = await encryptPayload(chave, EXEMPLO)

    expect(await decryptPayload<Payload>(chave, blob)).toEqual(EXEMPLO)
  })

  it("nunca repete o nonce — dois blobs do MESMO dado são diferentes", async () => {
    // Falha se: o IV virar constante. Em AES-GCM reusar nonce não vaza só um
    // valor, permite recuperar a chave de autenticação. É a falha mais séria
    // possível neste modo, e o lado Python já tem o teste equivalente
    // (`test_crypto.py::test_nonce_nunca_se_repete`).
    const chave = await deriveKey("senha", "salt")
    const blobs = new Set<string>()
    for (let i = 0; i < 20; i++) {
      blobs.add((await encryptPayload(chave, EXEMPLO)).split(".")[0])
    }
    expect(blobs.size).toBe(20)
  })

  it("recusa blob adulterado", async () => {
    // Falha se: alguém trocar AES-GCM por um modo sem autenticação. O sintoma
    // seria o vault aceitar dado alterado por fora do app.
    const chave = await deriveKey("senha", "salt")
    const [iv, ct] = (await encryptPayload(chave, EXEMPLO)).split(".")

    const bytes = Uint8Array.from(atob(ct), (c) => c.charCodeAt(0))
    bytes[0] ^= 0xff
    const adulterado = iv + "." + btoa(String.fromCharCode(...bytes))

    await expect(decryptPayload<Payload>(chave, adulterado)).rejects.toThrow()
  })

  it("⚠️ HOJE grava `iv.ct` SEM marcador de versão — a Decisão 1.6 muda para `v1.`", async () => {
    // Prende o formato atual para que a migração de formato seja deliberada.
    // Sem marcador de versão, trocar de cifra vira tentativa e erro sobre dados
    // que ninguém consegue ler — o lado Python resolveu isso de propósito
    // (`crypto.py`, `BLOB_VERSION`).
    const chave = await deriveKey("senha", "salt")
    const partes = (await encryptPayload(chave, EXEMPLO)).split(".")

    expect(partes).toHaveLength(2)
    expect(atob(partes[0])).toHaveLength(12) // IV de 96 bits
  })
})
