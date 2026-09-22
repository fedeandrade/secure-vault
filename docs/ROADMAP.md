# Roadmap — secure-vault

Estado medido em **22/09/2026**. Cada linha tem prova ou diz que não tem.

As dez fases originais do projeto (setup → TUI → 2FA) estão fechadas e listadas
no [`README.md`](../README.md). Este documento cobre o que veio depois.

## Onde cada frente está

| Frente | Estado | Bloqueio |
|---|---|---|
| **Zero-Knowledge no CLI/TUI** | ✅ fechado | — |
| **Fase 1** — site deixa de expor senha | ⛔ **não implementado** (replanejado, schema pronto) | é o portão de "publicável" |
| **Fase 2** — site compila | ✅ fechado | — |
| **Fase 3** — CRUD na TUI | ⏳ não começado | — |
| **Fase 4** — site e CLI, mesmo vault? | 🔶 metade decidida | falta o formato |

O desenho detalhado de cada fase, com as decisões e o porquê de cada uma, está em
[`planos/2026-09-22-web-seguro-e-tui-completa.md`](planos/2026-09-22-web-seguro-e-tui-completa.md).
O contrato que nenhuma delas pode quebrar está em [`SPEC.md`](SPEC.md).

---

## ✅ Zero-Knowledge no CLI/TUI

A credencial inteira virou um blob opaco: o banco não guarda mais nem o nome do
serviço. **Prova:** a suíte saiu de *41 failed / 195 passed / 14 errors* para
**255 passed / 12 skipped**, `ruff` limpo.

Três defeitos foram achados por revisão adversarial e consertados **com um teste
que discrimina cada um**:

1. A migration corrompia vault populado em silêncio → agora **recusa**, no
   `upgrade` e no `downgrade`.
2. Soft delete mantinha a senha vazada viva para sempre, e o `vault passwd` a
   re-cifrava sob a chave nova → exclusão voltou a ser **física**.
3. Senha de 100 caracteres quebrava em 3 linhas no terminal, sem o valor completo
   em nenhuma → console dedicado com `soft_wrap`.

⚠️ **Limite conhecido:** vault criado antes desta mudança **não tem caminho
automático** de migração. É limitação declarada, não descuido — ou se escreve
`export`/`import` pela chave, ou a migração é manual.

---

## ⛔ Fase 1 — o site deixa de expor senha

**É o portão. Enquanto não fechar, `web/` não vai a lugar nenhum.**

Hoje o site tem salt global fixo (`"secure-vault-global-salt"`), **zero**
autenticação nas rotas e chave de cifragem exportável. Qualquer um que abra a URL
lê o vault inteiro.

⚠️ **A primeira versão desta fase foi REPROVADA por revisão adversarial —
54/100.** Ela criava dois caminhos de ataque que não existiam: rebaixamento de KDF
servido pelo servidor, e inicialização por HTTP público que permitia trancar o
dono para fora. O desenho atual é o revisado.

### Já está no lugar

- `VaultConfig` e `Session` no schema e na migration, com as decisões de
  segurança gravadas em comentário no próprio `schema.prisma`.
- `Credential.version`, para o AAD `v2` não custar uma segunda migration.
- **Harness de teste**: `vitest` instalado e rodando, 7 testes de cripto. Sem ele
  a fase não conseguia fechar pelos próprios critérios de aceite.

### Falta — tudo que é código

- [ ] Derivação HKDF com `deriveBits`, chave `extractable: false`
- [ ] `wrappedVaultKey` (envelope) e `keyCheck`
- [ ] Autenticação real nas 4 rotas; sessão em banco; cookie `__Host-`
- [ ] Piso `MIN_KDF_ITERATIONS` + pin de `{salt, iterações}`
- [ ] `npm run vault:init` local (a inicialização sai do HTTP)
- [ ] Blob `v1.`; erro explícito em vez de lista vazia
- [ ] Rate limit e validação de `authValue` **antes** do argon2id
- [ ] CSP, `Referrer-Policy`, `X-Content-Type-Options`, checagem de `Origin`
- [ ] `SESSION_SECRET` ≥32 bytes, validado preguiçosamente

Critérios de aceite completos: no plano, seção "Fase 1".

---

## ✅ Fase 2 — o site compila

| Medida | Antes | Agora |
|---|---|---|
| `tsc --noEmit` | 1 erro | **0** |
| `eslint` | 5 erros, 9 avisos | **0 / 0** |
| `next build` | quebrado | verde, 5 rotas |
| runner de teste | **nenhum** | vitest, 7 testes |

O bloqueio era o driver adapter do Prisma 7 — e escolher adapter é escolher
banco, que era a decisão da Fase 4.

---

## ⏳ Fase 3 — CRUD na TUI

`src/vault/tui/app.py` é **só leitura**. Faltam adicionar, editar e apagar.

As 6 telas em `origin/main:src/vault/tui/screens/` são **referência de UX, não
código a portar**: elas falam com uma API que não existe mais
(`crypto.encrypt_password`, `db.credentials`).

Invariante que não pode cair junto: a senha **não** aparece ao navegar. O painel
de detalhe usa `CredentialMetadata`, nunca `reveal()`.

---

## 🔶 Fase 4 — site e CLI viram o mesmo vault?

### Decidido: o banco do site é próprio

Postgres dedicado, separado do banco do CLI (decisão do Felipe, 22/09/2026).
Isso destravou as Fases 1 e 2 e tirou o site da dependência de filesystem — o
schema fixava `file:./dev.db`, que em host serverless é efêmero ou somente-leitura.

### Em aberto: o formato

Banco separado **não** decide se os dois compartilham formato de vault. Hoje não
compartilham (ver [`SPEC.md`](SPEC.md), seção 4).

| Caminho | Custo | Ganha | Perde |
|---|---|---|---|
| **A — site vira cliente do formato Python** | alto: Argon2id no browser (WASM), AAD, migration | um vault só | reescrever a cripto do site |
| **B — seguem separados** | zero | nada a fazer | dois produtos com o mesmo nome, e o usuário não entende por que um não abre o outro |
| **C — servidor traduz** | médio | site sem WASM | ⛔ **mata o Zero-Knowledge** |

**Recomendação: A**, depois das fases 1 a 3. **C está descartado.**

A Fase 1 foi desenhada para não encarecer o A: HKDF com rótulo fixo é a mesma
política do `core/kdf.py`, então unificar vira troca de parâmetro em vez de
segunda reescrita.

---

## O que depende de gente, não de código

| Pendência | De quem |
|---|---|
| Aprovar a execução do CI em PR vindo de fork — hoje tudo fica `action_required`, 0s | **Renan** |
| Mesclar o PR #19 em `ReCroffi/secure-vault` | **Renan** (o Felipe só tem `pull`) |
| Dois TODOs pessoais do README: Motivação, LinkedIn/contato | **Renan** |
| Aplicar a migration do site contra um Postgres real — ela foi gerada offline e nunca rodou | qualquer um com Docker |
| Decidir a metade restante da Fase 4 | **Felipe** |
