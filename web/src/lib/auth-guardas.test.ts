import { describe, expect, it } from "vitest"

import { atrasoDe, authValueValido, origemConfere } from "./auth-guardas"
import { derivarChaves, MIN_KDF_ITERATIONS } from "./crypto"

describe("authValueValido", () => {
  it("aceita o que o cliente realmente produz", async () => {
    // Não um valor inventado: o authValue de verdade, saído do KDF. Se o formato
    // do cliente e o da guarda divergirem, ninguém consegue logar — e este é o
    // teste que pega isso.
    const { authValue } = await derivarChaves("senha", "salt", MIN_KDF_ITERATIONS)
    expect(authValueValido(authValue)).toBe(true)
  })

  it("⛔ recusa tudo que não seja base64 de exatamente 32 bytes", () => {
    // Cada um destes, se passasse, custaria 64 MB de argon2id ao servidor. É a
    // assimetria que transforma a rota de login em amplificador de DoS.
    const lixo = [
      "",
      "curto",
      // ⚠️ `"a".repeat(43) + "="` esteve nesta lista e o teste reprovou —
      // corretamente, porque aquilo É base64 válido de 32 bytes. O caso errado
      // era o meu. Ficou registrado porque "inventar entrada inválida" é
      // exatamente como se escreve um teste que aprova o código errado.
      "A".repeat(44), // 44 chars sem padding -> 33 bytes
      Buffer.alloc(16).toString("base64"), // 16 bytes
      Buffer.alloc(64).toString("base64"), // 64 bytes
      Buffer.alloc(32).toString("base64url"), // variante url-safe, não é o formato
      null,
      undefined,
      42,
      { toString: () => Buffer.alloc(32).toString("base64") }, // objeto disfarçado
      ["x"],
      Buffer.alloc(32).toString("base64") + " ", // espaço no fim
    ]
    for (const valor of lixo) {
      expect(authValueValido(valor), `deveria recusar: ${JSON.stringify(valor)}`).toBe(
        false
      )
    }
  })

  it("aceita qualquer base64 legítimo de 32 bytes, não só o do KDF", () => {
    for (let i = 0; i < 20; i++) {
      const bytes = crypto.getRandomValues(new Uint8Array(32))
      expect(authValueValido(Buffer.from(bytes).toString("base64"))).toBe(true)
    }
  })
})

describe("atrasoDe", () => {
  it("não pune a primeira tentativa errada", () => {
    // Lockout na primeira falha só irrita o dono. Errar a senha uma vez é humano.
    expect(atrasoDe(0)).toBe(0)
    expect(atrasoDe(1)).toBe(0)
  })

  it("cresce exponencialmente", () => {
    expect(atrasoDe(2)).toBe(250)
    expect(atrasoDe(3)).toBe(500)
    expect(atrasoDe(4)).toBe(1000)
    expect(atrasoDe(8)).toBe(16000)
  })

  it("⛔ tem teto — senão o próprio atraso vira DoS", () => {
    // Sem teto, 40 tentativas dariam um atraso de ~35 anos, e o dono ficaria
    // trancado para fora por alguém que só errou a senha de propósito.
    expect(atrasoDe(20)).toBe(30_000)
    expect(atrasoDe(1000)).toBe(30_000)
    expect(atrasoDe(Number.MAX_SAFE_INTEGER)).toBe(30_000)
  })
})

describe("origemConfere", () => {
  it("aceita mesma origem", () => {
    expect(origemConfere("https://vault.exemplo.com", "vault.exemplo.com")).toBe(true)
    expect(origemConfere("http://localhost:3000", "localhost:3000")).toBe(true)
  })

  it("⛔ recusa origem diferente, inclusive as parecidas", () => {
    expect(origemConfere("https://malicioso.com", "vault.exemplo.com")).toBe(false)
    // Subdomínio NÃO é a mesma origem.
    expect(origemConfere("https://x.vault.exemplo.com", "vault.exemplo.com")).toBe(false)
    // Prefixo que engana comparação por `startsWith`.
    expect(origemConfere("https://vault.exemplo.com.malicioso.com", "vault.exemplo.com")).toBe(
      false
    )
    // Porta diferente é origem diferente.
    expect(origemConfere("http://localhost:3001", "localhost:3000")).toBe(false)
    // Origin malformado não vira exceção nem passa.
    expect(origemConfere("nao-e-url", "vault.exemplo.com")).toBe(false)
  })

  it("deixa passar requisição sem Origin, e isso é deliberado", () => {
    // Browser SEMPRE manda Origin em requisição cross-origin que muda estado.
    // Quem omite não é browser — e aí não há CSRF a explorar.
    expect(origemConfere(null, "vault.exemplo.com")).toBe(true)
  })
})
