/**
 * Criptografia do cliente web — tudo acontece no browser.
 *
 * O servidor guarda bytes opacos e nunca vê a senha mestra, a chave derivada nem
 * a chave do vault. As decisões abaixo estão detalhadas em
 * `docs/planos/2026-09-22-web-seguro-e-tui-completa.md` (Fase 1) e o contrato que
 * elas cumprem, em `docs/SPEC.md` seção 3.
 *
 * ⚠️ O que ZK no browser **não** protege: o operador do servidor. É ele quem
 * serve este JavaScript. "O servidor nunca vê a senha" é verdade deste código,
 * não de qualquer código que a mesma origem venha a servir amanhã.
 */

const enc = new TextEncoder()
const dec = new TextDecoder()

/**
 * Piso de iterações, **constante no bundle**. Nunca aceite este valor do
 * servidor: com escrita no banco, `UPDATE VaultConfig SET kdfIterations = 1`
 * derrubaria o custo por palpite de 600.000 hashes para 2 — fator ~300.000x.
 *
 * 600k é o piso do OWASP para PBKDF2-SHA256, o mesmo que o Bitwarden usa.
 *
 * ⚠️ Medido em 22/09/2026 nesta máquina: 600k iterações custam **~98 ms**, não
 * "~1 s" como o plano afirmava. A defesa contra força bruta *online* é o rate
 * limit do servidor, não o custo do KDF — quem escrever a rota de login não pode
 * se apoiar nesse número.
 */
export const MIN_KDF_ITERATIONS = 600_000

/** Prefixo de versão do blob. Ver `decifrar` para por que ele existe. */
const VERSAO_BLOB = "v1"

/**
 * Rótulos de HKDF. Seguem o estilo do lado Python (`src/vault/core/kdf.py`),
 * de propósito: se a Fase 4 unificar os dois vaults, isso vira troca de
 * parâmetro em vez de segunda reescrita.
 *
 * ⛔ **Nunca reaproveite um `:v1` com significado novo — crie `:v2`.** Trocar o
 * sentido de um rótulo torna indecifrável todo dado derivado sob ele.
 */
const ROTULO_AUTH = "secure-vault:web.auth:v1"
const ROTULO_ENC = "secure-vault:web.enc:v1"
const AAD_VAULTKEY = "secure-vault:web.vaultkey:v1"

/** Texto-sentinela do `keyCheck`. Mesmo papel do `KEY_CHECK_PLAINTEXT` do Python. */
const SENTINELA = "secure-vault-web-key-check"

export class ErroDeCripto extends Error {}

// ---------------------------------------------------------------------------
// base64 — sem depender de Buffer (isto roda no browser)
// ---------------------------------------------------------------------------

function paraBase64(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let s = ""
  // Em pedaços: `String.fromCharCode(...u8)` estoura a pilha com entrada grande.
  for (let i = 0; i < u8.length; i += 0x8000) {
    s += String.fromCharCode(...u8.subarray(i, i + 0x8000))
  }
  return btoa(s)
}

function deBase64(texto: string): Uint8Array<ArrayBuffer> {
  const bruto = atob(texto)
  const u8 = new Uint8Array(bruto.length)
  for (let i = 0; i < bruto.length; i++) u8[i] = bruto.charCodeAt(i)
  return u8
}

/**
 * Zera um buffer depois do uso.
 *
 * Honestidade sobre o alcance disto: reduz a janela de exposição, **não**
 * garante que os bytes sumiram. O motor de JavaScript pode ter feito cópias
 * (realocação de heap, GC movendo objeto) fora do nosso alcance. É a mesma
 * limitação declarada no `wipe()` do lado Python.
 */
function zerar(buffer: Uint8Array<ArrayBuffer>): void {
  buffer.fill(0)
}

// ---------------------------------------------------------------------------
// Derivação
// ---------------------------------------------------------------------------

export type ChavesDerivadas = {
  /** Vai para o servidor, que guarda só o argon2id disto. Não abre nada. */
  authValue: string
  /** Abre o `wrappedVaultKey`. **Não exportável.** */
  chaveEnvelope: CryptoKey
}

/**
 * Deriva, a partir da senha mestra, um valor de autenticação e uma chave de
 * envelope — separados por HKDF com rótulo fixo.
 *
 * ⚠️ **`deriveBits` + HKDF, e não `deriveKey`.** Parece rodeio e não é: uma
 * `CryptoKey` AES não-exportável **não pode** alimentar outro KDF, então só há
 * como ter as duas coisas (chave não-exportável *e* `authValue`) passando pelos
 * bytes crus uma vez e importando o resultado com `extractable: false`.
 *
 * ⛔ **Quem trocar `false` por `true` "porque não compila" reabre o buraco
 * inteiro:** com a chave exportável, um XSS faz `crypto.subtle.exportKey` e leva
 * a chave mestra em claro. Coberto por teste.
 */
export async function derivarChaves(
  senhaMestra: string,
  salt: string,
  iteracoes: number
): Promise<ChavesDerivadas> {
  if (!Number.isInteger(iteracoes) || iteracoes < MIN_KDF_ITERATIONS) {
    // Erro VISÍVEL, nunca degradação silenciosa: este é o ponto exato onde um
    // rebaixamento de KDF seria aceito sem ninguém notar.
    throw new ErroDeCripto(
      `Parâmetro de KDF abaixo do mínimo seguro (${iteracoes} < ${MIN_KDF_ITERATIONS}). ` +
        "O vault não será aberto. Se você não mudou isso, o banco pode ter sido adulterado."
    )
  }

  const material = await crypto.subtle.importKey(
    "raw",
    enc.encode(senhaMestra),
    "PBKDF2",
    false,
    ["deriveBits"]
  )

  const bruta = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: iteracoes, hash: "SHA-256" },
    material,
    256
  )

  const chaveHkdf = await crypto.subtle.importKey("raw", bruta, "HKDF", false, [
    "deriveBits",
  ])

  const expandir = (rotulo: string) =>
    crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: enc.encode(rotulo),
      },
      chaveHkdf,
      256
    )

  const authBits = await expandir(ROTULO_AUTH)
  const encBits = await expandir(ROTULO_ENC)

  const chaveEnvelope = await crypto.subtle.importKey(
    "raw",
    encBits,
    "AES-GCM",
    false, // ⛔ não mexer — ver o aviso acima
    ["encrypt", "decrypt"]
  )

  const authValue = paraBase64(authBits)
  zerar(new Uint8Array(encBits))

  return { authValue, chaveEnvelope }
}

// ---------------------------------------------------------------------------
// Envelope: a chave do vault não é a chave derivada da senha
// ---------------------------------------------------------------------------

export type VaultRecemCriado = {
  chaveVault: CryptoKey
  wrappedVaultKey: string
  keyCheck: string
}

/**
 * Cria a `vaultKey` aleatória e a devolve **envelopada** sob a chave derivada.
 *
 * Por que envelope e não cifrar os registros direto com a chave da senha: sem
 * ele, trocar a senha mestra significa redecifrar e recifrar os N registros no
 * browser, **sem transação**. A aba morrer no registro 40 de 200 deixa 40 blobs
 * sob a chave nova e 160 sob a velha — e o cliente não tem como saber qual é
 * qual, porque a falha de decifragem é idêntica nos dois casos. Vault meio
 * ilegível, sem diagnóstico. Com envelope, trocar a senha reescreve **um** blob.
 */
export async function criarVault(chaveEnvelope: CryptoKey): Promise<VaultRecemCriado> {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  try {
    const chaveVault = await crypto.subtle.importKey("raw", bytes, "AES-GCM", false, [
      "encrypt",
      "decrypt",
    ])
    const wrappedVaultKey = await cifrarBytes(chaveEnvelope, bytes, AAD_VAULTKEY)
    const keyCheck = await cifrarTexto(chaveVault, SENTINELA)
    return { chaveVault, wrappedVaultKey, keyCheck }
  } finally {
    // `wrapKey` do WebCrypto exigiria a chave exportável, que é justamente o que
    // não queremos — por isso passamos pelos bytes crus e os zeramos aqui.
    zerar(bytes)
  }
}

/** Abre o `wrappedVaultKey`. Falha aqui significa senha errada ou blob adulterado. */
export async function abrirVault(
  chaveEnvelope: CryptoKey,
  wrappedVaultKey: string
): Promise<CryptoKey> {
  const bytes = await decifrarBytes(chaveEnvelope, wrappedVaultKey, AAD_VAULTKEY)
  try {
    if (bytes.length !== 32) {
      throw new ErroDeCripto("wrappedVaultKey com tamanho inesperado.")
    }
    return await crypto.subtle.importKey("raw", bytes, "AES-GCM", false, [
      "encrypt",
      "decrypt",
    ])
  } finally {
    zerar(bytes)
  }
}

/**
 * Confere que a chave abre os dados **antes** de renderizar qualquer coisa.
 *
 * Por que isto não é redundante com o `abrirVault`: sem a sentinela, chave
 * errada, rebaixamento de KDF e vault meio-migrado produzem todos a **mesma
 * tela** — "nenhum item". O desfecho realista é o dono recadastrar tudo, agora
 * sob parâmetros que o atacante escolheu.
 */
export async function conferirChave(
  chaveVault: CryptoKey,
  keyCheck: string
): Promise<boolean> {
  try {
    return (await decifrarTexto(chaveVault, keyCheck)) === SENTINELA
  } catch {
    return false
  }
}

// ---------------------------------------------------------------------------
// Blob
// ---------------------------------------------------------------------------

async function cifrarBytes(
  chave: CryptoKey,
  claro: Uint8Array<ArrayBuffer>,
  aad?: string
): Promise<string> {
  // Nonce novo a CADA cifragem, nunca reaproveitado. Reusar nonce em GCM não
  // vaza só um valor: permite recuperar a chave de autenticação. É a falha mais
  // séria possível neste modo, e por isso ela é verificada por teste.
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const parametros: AesGcmParams = { name: "AES-GCM", iv }
  if (aad) parametros.additionalData = enc.encode(aad)

  const ct = await crypto.subtle.encrypt(parametros, chave, claro)
  return `${VERSAO_BLOB}.${paraBase64(iv)}.${paraBase64(ct)}`
}

async function decifrarBytes(
  chave: CryptoKey,
  blob: string,
  aad?: string
): Promise<Uint8Array<ArrayBuffer>> {
  const partes = blob.split(".")
  if (partes.length !== 3) {
    throw new ErroDeCripto("Formato de blob irreconhecível.")
  }
  const [versao, ivB64, ctB64] = partes
  if (versao !== VERSAO_BLOB) {
    // Mensagem própria, e não "falha ao decifrar": sem marcador de versão,
    // migrar de cifra vira tentativa e erro sobre dados que ninguém lê. O lado
    // Python resolveu isso de propósito (`crypto.py`, `BLOB_VERSION`).
    throw new ErroDeCripto(
      `Versão de blob desconhecida: "${versao}". Esta build entende "${VERSAO_BLOB}". ` +
        "O dado foi escrito por uma versão mais nova do Secure Vault?"
    )
  }

  const parametros: AesGcmParams = { name: "AES-GCM", iv: deBase64(ivB64) }
  if (aad) parametros.additionalData = enc.encode(aad)

  try {
    const claro = await crypto.subtle.decrypt(parametros, chave, deBase64(ctB64))
    return new Uint8Array(claro)
  } catch {
    // Não diferencia "chave errada" de "dado adulterado" para quem observa.
    throw new ErroDeCripto(
      "Não foi possível decifrar: a chave não corresponde a este dado, " +
        "ou o registro foi alterado por fora da aplicação."
    )
  }
}

async function cifrarTexto(chave: CryptoKey, texto: string): Promise<string> {
  return cifrarBytes(chave, enc.encode(texto))
}

async function decifrarTexto(chave: CryptoKey, blob: string): Promise<string> {
  return dec.decode(await decifrarBytes(chave, blob))
}

/** Cifra o payload de uma credencial sob a chave do vault. */
export async function cifrarPayload<T>(chave: CryptoKey, payload: T): Promise<string> {
  return cifrarTexto(chave, JSON.stringify(payload))
}

/** Abre um payload de credencial. Lança `ErroDeCripto` — nunca devolve `null`. */
export async function decifrarPayload<T>(chave: CryptoKey, blob: string): Promise<T> {
  return JSON.parse(await decifrarTexto(chave, blob)) as T
}
