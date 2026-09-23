#!/usr/bin/env node
/**
 * Gate de qualidade do secure-vault — os dois lados, num comando só.
 *
 * Quem chama: o hook `Stop` do Claude Code, por `.claude/gate.json`. Gate
 * vermelho bloqueia o encerramento do turno. Também serve para rodar à mão:
 *
 *     node scripts/gate.mjs
 *
 * Por que um script e não `a && b && c` no `gate.json`: o hook executa com
 * `shell: true`, que no Windows é `cmd.exe`. Encadear seis comandos com um `cd`
 * no meio é frágil (basta uma aspa) e, pior, o primeiro `&&` que falha esconde
 * tudo que vinha depois — você conserta o lint e descobre o teste quebrado só
 * no turno seguinte. Aqui TODOS os passos rodam e o resumo mostra os dois lados.
 *
 * Medido em 22/09/2026 nesta máquina: ~35s no total (Python 15s, web 20s), bem
 * abaixo dos 150s declarados no `gate.json` — que por sua vez ficam abaixo dos
 * 180s do próprio hook.
 */

import { spawnSync } from "node:child_process"
import { readFileSync, statSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const RAIZ = dirname(dirname(fileURLToPath(import.meta.url)))
const WEB = join(RAIZ, "web")

/**
 * O comando vai como STRING ÚNICA, com `shell: true` — e as duas coisas juntas
 * são obrigatórias, não preferência:
 *
 * - sem `shell`, `spawnSync("npx.cmd", …)` devolve **EINVAL** no Node 24: desde
 *   a correção da CVE-2024-27980 o Node recusa executar `.cmd` sem shell;
 * - com `shell: true` E lista de argumentos, o Node 24 emite **DEP0190**,
 *   avisando que os argumentos são concatenados sem escape. Num gerenciador de
 *   senhas não se ignora aviso de injeção.
 *
 * String única com `shell: true` não dispara nenhum dos dois. É seguro aqui
 * porque **todo comando neste arquivo é literal** — nada vem de fora. Se um dia
 * alguém montar um comando com valor vindo de arquivo, argumento ou ambiente,
 * esta escolha deixa de valer e vira injeção de verdade.
 */
function rodar(rotulo, comando, cwd) {
  const inicio = Date.now()
  const r = spawnSync(comando, { cwd, stdio: "inherit", shell: true })
  return {
    rotulo,
    ok: r.status === 0,
    ms: Date.now() - inicio,
    detalhe: r.error ? String(r.error.message) : "",
  }
}

const resultados = []

// ---------------------------------------------------------------------------
// Python — CLI e TUI. `uv run --no-sync` porque ruff e pytest vivem no `.venv`
// e não no PATH; `--no-sync` para o gate não tentar resolver dependência pela
// rede no meio de um turno.
//
// SEM `-q` de propósito: o `addopts` do pyproject já tem um, e um segundo vira
// `-qq`, que ESCONDE a linha de total. Foi assim que uma medição deste projeto
// leu "58 testes" onde havia 130.
// ---------------------------------------------------------------------------
resultados.push(rodar("python · ruff", "uv run --no-sync ruff check .", RAIZ))
// ⚠️ Mesmo buraco do `DATABASE_URL` do site, do outro lado: sem
// `TEST_DATABASE_URL` os 12 testes de `test_migrations.py` são PULADOS e o
// total continua verde. São justamente os que provam que a migration recusa
// vault populado — a guarda que impede corromper credencial em silêncio.
if (!process.env.TEST_DATABASE_URL) {
  console.warn(
    "\n[gate] ⚠️  TEST_DATABASE_URL ausente — os 12 testes de MIGRATION foram\n" +
      "[gate]     PULADOS, não aprovados. Eles só rodam contra Postgres real.\n"
  )
}
resultados.push(rodar("python · pytest", "uv run --no-sync pytest", RAIZ))

// ---------------------------------------------------------------------------
// Web — o site.
//
// Sem `node_modules` o gate LIBERA em vez de reprovar: falha de instalação não é
// falha de qualidade. Mas isso é buraco de cobertura, não aprovação — por isso o
// aviso é ruidoso e aparece no resumo.
// ---------------------------------------------------------------------------
/**
 * ⚠️ NÃO use `existsSync` aqui. Ele engole qualquer erro do `stat` e devolve
 * `false` — então "não existe" e "existe mas eu não consigo ler" chegam
 * idênticos. Medido nesta máquina em 22/09/2026: `existsSync("C:/Users/felip/
 * .ssh")` devolve `false` numa pasta que existe e que o `statSync` abre.
 *
 * Por que isso importa num gate: falso negativo aqui faz o gate **pular o site
 * inteiro** e dizer "sem node_modules" — que se lê como "não é problema meu" —
 * quando na verdade ele não conseguiu olhar. Gate que não sabe se mediu precisa
 * falhar alto, não seguir em frente.
 *
 * ENOENT é a única ausência legítima: aí sim pular, porque falha de instalação
 * não é falha de qualidade.
 */
function temNodeModules() {
  try {
    statSync(join(WEB, "node_modules"))
    return true
  } catch (erro) {
    if (erro.code === "ENOENT") return false
    throw new Error(
      `não consegui verificar web/node_modules (${erro.code}). ` +
        "O gate NÃO vai fingir que o site está aprovado."
    )
  }
}

const temDeps = temNodeModules()
if (!temDeps) {
  console.warn(
    "\n[gate] ⚠️  web/node_modules ausente — a parte web foi PULADA, não aprovada.\n" +
      "[gate]     Rode `npm ci` em web/ para que o gate volte a medir o site.\n"
  )
} else {
  // ⛔ `next typegen` ANTES do tsc, e isto não é ordem arbitrária.
  //
  // O Next 16 GERA tipos (`LayoutProps`, `PageProps`) em `.next/types/`, e o
  // `layout.tsx` os usa. Rodar o tsc primeiro só funcionava aqui porque sobrava
  // um `.next/` de um build anterior — em clone limpo, e no CI, o tsc falhava
  // com `TS2304: Cannot find name 'LayoutProps'`.
  //
  // Medido em 22/09/2026: o CI do fork estava VERMELHO por isto enquanto o gate
  // local dizia verde. Gate que depende de artefato de build anterior não é gate,
  // é sorte. Reproduzível com `rm -rf .next && npx tsc --noEmit`.
  resultados.push(rodar("web · typegen", "npx next typegen", WEB))
  resultados.push(rodar("web · tsc", "npx tsc --noEmit", WEB))
  resultados.push(rodar("web · eslint", "npx eslint", WEB))
  // ⚠️ `DATABASE_URL` decide se os testes de rota rodam ou são PULADOS.
  //
  // Eles sobem o Next de verdade e batem nas 4 rotas do vault — é o único lugar
  // que prova que o 401 está LIGADO em cada uma, e não só que a função que
  // decide funciona. Sem banco eles somem em silêncio no meio de um "21 passed",
  // e "pulado" lido como "verde" foi exatamente o buraco que deixou a CSP
  // quebrar o site sem ninguém notar.
  // O gate roda da RAIZ; o `.env` do site mora em `web/`. Ler aqui é só para o
  // aviso abaixo dizer a verdade — quem de fato carrega a variável para os
  // testes é o `import "dotenv/config"` do `vitest.config.mts`. Sem isto o gate
  // anunciava "PULADOS" numa rodada em que eles rodaram, que é o tipo de aviso
  // que ensina a ignorar aviso.
  const temBancoNoEnvDoWeb = (() => {
    if (process.env.DATABASE_URL) return true
    try {
      return /^\s*DATABASE_URL\s*=\s*\S/m.test(readFileSync(join(WEB, ".env"), "utf8"))
    } catch {
      return false
    }
  })()
  if (!temBancoNoEnvDoWeb) {
    console.warn(
      "\n[gate] ⚠️  DATABASE_URL ausente — os testes de ROTA (401, CSP, nonce)\n" +
        "[gate]     foram PULADOS, não aprovados. Eles sobem o Next e são os\n" +
        "[gate]     únicos que provam a camada HTTP. Defina DATABASE_URL para medi-los.\n"
    )
  }
  resultados.push(rodar("web · vitest", "npx vitest run", WEB))
  // `next build` entra porque é o que pega erro que o tsc não vê: rota que não
  // resolve, import de módulo só-servidor no cliente, config inválida.
  resultados.push(rodar("web · next build", "npx next build", WEB))

  // ⛔ Trava mecânica contra uma regressão que NENHUM teste daqui enxerga.
  //
  // A CSP com nonce (`web/src/proxy.ts`) só vale para página renderizada por
  // requisição. Se `/` voltar a ser prerenderizada, o HTML é gerado no build —
  // quando não existe requisição nem cabeçalho — e sai **sem nonce**. Com
  // `'strict-dynamic'` no `script-src`, o `'self'` passa a ser ignorado pelo
  // browser e **nenhum** script executa: nem os inline, nem os 7 com `src`.
  //
  // Medido em 22/09/2026: foi exatamente isso que aconteceu. Em `next start`,
  // 9 `<script>` e 0 `nonce=`. Os testes de rota não viram porque sobem
  // `next dev`, onde tudo é dinâmico. Basta alguém remover o `await connection()`
  // de `src/app/page.tsx` para o buraco voltar, calado.
  resultados.push({
    rotulo: "web · '/' fora do prerender",
    ...(() => {
      const inicio = Date.now()
      try {
        const manifesto = JSON.parse(
          readFileSync(join(WEB, ".next", "prerender-manifest.json"), "utf8")
        )
        const estaticas = Object.keys(manifesto.routes ?? {})
        const ok = !estaticas.includes("/")
        return {
          ok,
          ms: Date.now() - inicio,
          detalhe: ok
            ? ""
            : "'/' voltou a ser estática: a CSP com nonce não se aplica e NENHUM script executa em produção. Falta `await connection()` em src/app/page.tsx?",
        }
      } catch (erro) {
        return { ok: false, ms: Date.now() - inicio, detalhe: `não li o prerender-manifest: ${erro.code ?? erro.message}` }
      }
    })(),
  })
}

// ---------------------------------------------------------------------------

const falhas = resultados.filter((r) => !r.ok)

console.log("\n" + "=".repeat(60))
console.log("GATE secure-vault")
console.log("=".repeat(60))
for (const r of resultados) {
  console.log(`${r.ok ? "  ok  " : " FALHA"} │ ${String(r.ms).padStart(6)}ms │ ${r.rotulo}${r.detalhe ? " — " + r.detalhe : ""}`)
}
if (!temDeps) console.log("  pulado │        │ web (sem node_modules)")
console.log("=".repeat(60))

if (falhas.length > 0) {
  console.error(`\nGATE VERMELHO: ${falhas.map((f) => f.rotulo).join(", ")}\n`)
  process.exit(1)
}
console.log("\nGATE VERDE\n")
