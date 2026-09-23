# Roadmap — secure-vault

Estado medido em **22/09/2026**. Cada linha tem prova ou diz que não tem.

As dez fases originais do projeto (setup → TUI → 2FA) estão fechadas e listadas
no [`README.md`](../README.md). Este documento cobre o que veio depois.

## Onde cada frente está

| Frente | Estado | Bloqueio |
|---|---|---|
| **Zero-Knowledge no CLI/TUI** | ✅ fechado | — |
| **Fase 1** — site deixa de expor senha | 🔶 **duas revisões adversariais (48/100 e 45/100), todos os achados corrigidos, aguarda a terceira** | falta uma revisão que aprove |
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

## 🔶 Fase 1 — o site deixa de expor senha

**Implementada em 22/09/2026, e provada contra um PostgreSQL 18.6 de verdade.**

```
npm run prova:e2e      # 17/17 — PROVA APROVADA
```

`scripts/prova-e2e.ts` roda init → login → destrancar → gravar → ler contra o
banco, sem mock nenhum. O que ela pega e que `tsc`/`eslint`/`vitest`/
`next build` **não pegam**: o adapter conectar de fato, o schema bater com o
código, o argon2id do servidor aceitar o `authValue` do cliente, e o envelope
reabrir depois de ir e voltar do banco.

As três provas que mais importam, porque falham se o Zero-Knowledge for só
conversa — ela lê a tabela com SQL cru e procura os valores em claro:

```
  ok │ nome do serviço NÃO aparece em claro no banco
  ok │ login NÃO aparece em claro no banco
  ok │ senha NÃO aparece em claro no banco
```

⚠️ ~~**O que a prova NÃO cobre: a camada HTTP.**~~ **Coberta em 22/09/2026.**
`src/app/api/rotas.test.ts` sobe o Next de verdade e bate nas rotas: 401 nas 4
do vault, `/config` sem vazar envelope, ausência de `POST`, rejeição de origem,
CSP, **nonce em todo `<script>` do HTML servido** e o atraso de login. Sem
`DATABASE_URL` eles são **pulados** — o gate avisa, e pulado não é verde.

### O que foi feito

| Item | Onde |
|---|---|
| Derivação HKDF, chave `extractable: false` | `src/lib/crypto.ts` |
| Envelope `wrappedVaultKey` + `keyCheck` | idem |
| Blob `v1.`, versão desconhecida com mensagem própria | idem |
| Piso `MIN_KDF_ITERATIONS` recusando abaixo de 600k | idem |
| Sessão em banco, SHA-256 do token, cookie `__Host-` | `src/lib/session.ts` |
| Login: formato→semáforo→argon2id→(se errou) atraso, fora do semáforo | `api/auth/login/route.ts` |
| 401 nas 4 rotas do vault; limite de 64 KB no blob | `api/vault/**` |
| `wrappedVaultKey`/`keyCheck` só com sessão; **sem `POST`** | `api/vault/config/route.ts` |
| Inicialização fora do HTTP, com piso de força de senha | `scripts/vault-init.ts` |
| CSP **com nonce por requisição**; `frame-ancestors 'none'` | `src/proxy.ts` |
| `Referrer-Policy`, `nosniff` | `next.config.ts` |
| `await connection()` tirando `/` do prerender — sem isso não há nonce | `src/app/page.tsx` |
| Pin de `{salt, kdfIterations}`; erro "N de M" em vez de lista vazia | `src/app/VaultApp.tsx` |

**37 testes** no site (eram 0 antes de hoje), dos quais 15 sobem o Next.

### Três decisões que divergem do plano, e por quê

1. ⚠️ **`SESSION_SECRET` não existe.** O plano exigia ≥32 bytes validados
   preguiçosamente — herança do desenho com JWT, que a própria Decisão 1.3
   reverteu. Com sessão em banco e token de CSPRNG **não há nada para
   assinar**. Variável de ambiente que ninguém lê faz o próximo a mexer
   acreditar que existe proteção onde não existe. Mesma razão pela qual
   `tokenVersion` saiu do schema.

2. ⛔ ~~"A CSP não usa nonce. Nonce por requisição exigiria middleware, e no
   Next 16 middleware roda no Edge — onde o `pg` não carrega."~~ **FALSO, e
   quebrava o site inteiro.** A doc da versão instalada diz o contrário
   (`proxy.md:255`: *"Proxy defaults to using the Node.js runtime"*), e um
   proxy que só gera nonce nem importa `pg`. Sem nonce, a CSP bloqueava os
   **três `<script>` inline** que o Next emite, o React não hidratava, e o
   site virava um cartão estático. Corrigido com `src/proxy.ts`.

3. ⛔ ~~"Exclusão no site continua soft, e a lápide não ressuscita segredo
   nenhum."~~ **O argumento respondia ao MECANISMO do problema do Python, não
   ao dano.** A linha ficava no Postgres, o `GET` a escondia, e como o
   envelope faz a `vaultKey` **nunca rodar**, a credencial apagada seguia
   decifrável por qualquer chave futura do dono — para sempre, e sem purga
   em lugar nenhum. Agora `DELETE` apaga a linha, e a coluna `deletedAt` saiu
   do schema.

### ⛔ Falta para a fase fechar

- [x] ~~Subir o Postgres e rodar o fluxo de ponta a ponta.~~ **Feito** —
      `npm run prova:e2e`, 20/20 contra PostgreSQL 18.6.
- [x] ~~Teste de integração provando 401 sem cookie nas 4 rotas.~~ **Feito** —
      `src/app/api/rotas.test.ts` sobe o Next e mede as 4.
- [x] ~~Revisão adversarial independente do código.~~ **Duas**, ambas REPROVA
      (48/100 e 45/100). Os achados estão corrigidos; ver abaixo.
- [ ] Teste provando que a senha mestra não aparece em nenhum corpo de
      requisição.
- [ ] **Uma terceira revisão que APROVE.** Duas seguidas acharam defeito
      crítico — inclusive uma regressão introduzida pelo conserto da anterior.
      Enquanto não houver revisão sem achado crítico, a fase não fecha e o
      `web/` não sobe.

### O que as duas revisões acharam, e onde cada coisa foi parar

| Achado | Estado |
|---|---|
| CSP sem nonce bloqueava os inline do Next → site não hidratava | ✅ `src/proxy.ts` |
| **Regressão do conserto acima:** `/` prerenderizada → HTML de produção com 9 scripts e **0 nonce** | ✅ `await connection()` + trava no gate lendo `prerender-manifest.json` |
| Troca de senha chamava `criarVault` → sorteava vaultKey nova e **destruía o vault**, com o `keyCheck` aprovando | ✅ `reenvelopar()` + teste que decifra registro anterior à troca |
| `/config` servia o envelope sem sessão → oráculo de quebra offline a 96 ms/palpite | ✅ só com sessão |
| `lockedUntil` global deixava um estranho trancar o dono | ✅ coluna **removida** (migration `20260923010000`) |
| Atraso pago **antes** do `verify`: o dono com a senha certa esperava 30 s | ✅ pago depois, e fora do semáforo. **Medido:** atacante 4086 ms, dono **98 ms** |
| `failedAttempts` em read-modify-write contava N falhas concorrentes como 1 | ✅ `{ increment: 1 }` |
| Soft delete sem purga em lugar nenhum | ✅ `DELETE` físico, `deletedAt` fora do schema |
| `SESSION_SECRET` declarado como invariante e inexistente no código | ✅ `SPEC.md` 3.14 invertida |
| `x-nonce` descrito como o que carimba o nonce (é o cabeçalho CSP) | ✅ comentário corrigido contra a doc |
| `'unsafe-inline'` em `style-src` com comentário dizendo que não estava lá | ✅ removido — a CSP3 já o ignorava por haver nonce |
| Servidor de teste sobrevivendo ao `afterAll` → suíte aprova código velho | ✅ `taskkill /T` e recusa de porta ocupada |

⚠️ **Medição que derrubou uma afirmação do plano:** 600k iterações de
PBKDF2-SHA256 custam **~98 ms** nesta máquina, não "~1 s". A defesa contra
força bruta online é o rate limit, não o custo do KDF — quem raciocinar com
o número antigo superestima a barreira em 10x.

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
