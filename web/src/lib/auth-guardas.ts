/**
 * Guardas da rota de login, separadas dela para poderem ser testadas.
 *
 * Elas não são detalhe de validação: a ORDEM em que a rota as aplica é o que
 * impede o login de virar amplificador de DoS. Ver `login/route.ts`.
 */

/** Quanto o `authValue` ocupa em base64: 32 bytes viram 44 caracteres. */
const TAMANHO_BASE64_DE_32_BYTES = 44

/**
 * `authValue` tem de ser base64 de **exatamente** 32 bytes.
 *
 * ⚠️ Esta é a PRIMEIRA coisa que a rota faz, antes de tocar no banco e antes do
 * argon2id. O motivo é assimetria de custo: mandar bytes aleatórios não custa
 * nada ao atacante e custa 64 MB de RAM por verificação ao servidor. Algumas
 * dezenas de requisições concorrentes derrubam o processo — **sem credencial
 * nenhuma**.
 */
export function authValueValido(valor: unknown): valor is string {
  if (typeof valor !== "string") return false
  if (valor.length !== TAMANHO_BASE64_DE_32_BYTES) return false
  // Base64 padrão, sem variante url-safe: o cliente produz com `btoa`.
  if (!/^[A-Za-z0-9+/]{43}=$/.test(valor)) return false
  try {
    return Buffer.from(valor, "base64").length === 32
  } catch {
    return false
  }
}

/**
 * Atraso exponencial depois de tentativas erradas — **não** bloqueio duro.
 *
 * Com um usuário só, lockout duro é auto-DoS: qualquer um que erre a senha de
 * propósito algumas vezes tranca o dono para fora do próprio vault. O atraso
 * encarece o ataque sem dar esse poder a um estranho.
 *
 * As duas primeiras tentativas não sofrem atraso: errar a senha uma vez é
 * humano, e punir isso só irrita o dono.
 */
export function atrasoDe(tentativas: number): number {
  if (tentativas <= 1) return 0
  // Teto de 30s para o atraso não virar DoS por outro caminho.
  return Math.min(30_000, 250 * 2 ** (tentativas - 2))
}

/**
 * Compara `Origin` com `Host` nos métodos que mudam estado.
 *
 * `sameSite: "strict"` já cobre a maior parte do CSRF; isto fecha o resto sem
 * custo e continua valendo se alguém afrouxar o `sameSite` no futuro.
 *
 * Requisição **sem** `Origin` passa de propósito: navegação direta e clientes
 * antigos não mandam o cabeçalho, e recusá-las quebraria uso legítimo sem
 * fechar ataque nenhum — um atacante sempre pode omitir o cabeçalho? Não: o
 * browser o envia obrigatoriamente em requisição cross-origin com método que
 * muda estado. Quem omite é quem não é browser, e aí o CSRF não se aplica.
 */
export function origemConfere(origem: string | null, host: string | null): boolean {
  if (!origem) return true
  if (!host) return false
  try {
    return new URL(origem).host === host
  } catch {
    return false
  }
}
