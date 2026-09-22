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
import { existsSync } from "node:fs"
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
resultados.push(rodar("python · pytest", "uv run --no-sync pytest", RAIZ))

// ---------------------------------------------------------------------------
// Web — o site.
//
// Sem `node_modules` o gate LIBERA em vez de reprovar: falha de instalação não é
// falha de qualidade. Mas isso é buraco de cobertura, não aprovação — por isso o
// aviso é ruidoso e aparece no resumo.
// ---------------------------------------------------------------------------
const temDeps = existsSync(join(WEB, "node_modules"))
if (!temDeps) {
  console.warn(
    "\n[gate] ⚠️  web/node_modules ausente — a parte web foi PULADA, não aprovada.\n" +
      "[gate]     Rode `npm ci` em web/ para que o gate volte a medir o site.\n"
  )
} else {
  resultados.push(rodar("web · tsc", "npx tsc --noEmit", WEB))
  resultados.push(rodar("web · eslint", "npx eslint", WEB))
  resultados.push(rodar("web · vitest", "npx vitest run", WEB))
  // `next build` entra porque é o que pega erro que o tsc não vê: rota que não
  // resolve, import de módulo só-servidor no cliente, config inválida.
  resultados.push(rodar("web · next build", "npx next build", WEB))
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
