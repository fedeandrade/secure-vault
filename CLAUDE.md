# secure-vault — instruções do projeto

**Perfil: PROFESSIONAL APP.** Gerenciador de senhas. Pense como software architect,
não como creative developer — aqui nenhuma escolha estética compensa uma garantia
criptográfica frouxa.

Este arquivo tem só o que **não dá para deduzir** lendo o repositório. Estrutura,
comandos e stack estão no [`README.md`](README.md); o contrato de segurança em
[`docs/SPEC.md`](docs/SPEC.md); o estado de cada frente em
[`docs/ROADMAP.md`](docs/ROADMAP.md); o histórico medido em [`MEMORIA.md`](MEMORIA.md).

## Quem escreve aqui

**O repositório é do Renan Croffi** (`ReCroffi/secure-vault`). O Felipe tem
**somente `pull`** — medido em 22/09/2026 via `gh api`. Consequências que não são
óbvias:

- **`git push origin` falha com 403.** O trabalho vai para o fork
  `fedeandrade/secure-vault` (remote `fork`), e de lá por PR.
- **Nenhum PR contra `ReCroffi` pode ser mesclado daqui.** Só o Renan mescla.
- ⛔ **O CI nunca roda em PR vindo do fork** sem o Renan aprovar: todas as
  execuções ficam `action_required` com duração **0s**. "Adicionei um job ao CI"
  não é o mesmo que "o CI passou". Confira com `gh run list` antes de afirmar.
- `origin/develop` **foi apagado** no remoto. A única base viva é `origin/main`.

## O gate

```bash
node scripts/gate.mjs
```

Roda os dois lados — Python (`ruff` + `pytest`) e web (`tsc` + `eslint` +
`vitest` + `next build`) — e é o mesmo comando que o hook `Stop` executa por
`.claude/gate.json`. ~29s.

- **Não encadeie `a && b` no `gate.json`.** O script existe porque o primeiro
  `&&` que falha esconde todo o resto; aqui todos os passos rodam e o resumo
  mostra os dois lados.
- **Sem `web/node_modules` o gate PULA o web** e diz isso em voz alta. Verde
  nessa condição não prova nada sobre o site.
- **Nunca passe `-q` extra ao pytest.** O `addopts` do `pyproject.toml` já tem um;
  o segundo vira `-qq` e **esconde a linha de total**. Uma medição deste projeto
  já leu "58 testes" onde havia 130.

## Armadilhas medidas neste repositório

| Sintoma | Causa real |
|---|---|
| Teste passa no shell e falha sob o gate | O `Console` do Rich liga cor pela **presença** de `FORCE_COLOR`, não pelo valor. Corrigido no **topo** de `tests/conftest.py` — fixture chega tarde, o `Console` nasce no import de `vault.cli.main` |
| `Module '"@prisma/client"' has no exported member` | Prisma 7 trocou o gerador: `prisma-client` exige `output` e **não escreve em `node_modules`**. O import é o caminho gerado |
| `PrismaConfigEnvError` no CI | `env("DATABASE_URL")` do `prisma/config` **não é preguiçoso**. Use `process.env["DATABASE_URL"]` — o job `web` roda sem a variável de propósito |
| `%` na senha do banco quebra o Alembic | O `alembic.ini` passa por interpolação de `configparser` |
| Heredoc do Bash comendo `\` mesmo com delimitador citado | Escreva JSON e conteúdo com `\` pelo `node -e` ou pela ferramenta Write, nunca por heredoc |

## Limites

- **Não reescrever histórico já publicado.** O alerta do GitGuardian vem de
  strings de placeholder que estão na história, inclusive em commits do próprio
  `main` do Renan. Corrigir para a frente; não `filter-branch`, não force push.
- **Não subir `web/` para lugar nenhum** enquanto a Fase 1 do
  [`ROADMAP`](docs/ROADMAP.md) não fechar: o site tem salt global fixo e API sem
  autenticação. Publicar hoje é expor o vault.
- **Migration que toca credencial recusa vault populado**, de propósito. Se
  precisar converter dados, o caminho é `export`/`import` pela chave — não
  afrouxar a guarda.
