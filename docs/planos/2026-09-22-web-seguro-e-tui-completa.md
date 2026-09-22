# Plano — site seguro e TUI completa

**Aberto em** 22/09/2026 · **Branch** `feature/completar-fases-04-10` · **Base** `f46a85c`

Ordem dos itens é por **o que expõe senha de usuário**, não por o que é interessante
de fazer. Cada fase tem critério de aceite verificável; nenhuma fecha por "parece
funcionar".

---

## Estado medido em 22/09/2026 (não é suposição)

| Superfície | Estado | Prova |
|---|---|---|
| CLI (`vault`) | **pronta** — 18 comandos | 255 passed, 12 skipped, ruff limpo |
| TUI (`vault tui`) | **parcial** — só leitura | os `BINDINGS` são revelar, copiar, TOTP, esconder, trancar, sair |
| Site (`web/`) | **não compila e é inseguro** | `next build` → `Can't resolve 'tw-animate-css'` |
| App mobile | **não existe** | não há `mobile/`, `ios/` nem `android/` no repositório |

### Os três defeitos do site, medidos

1. **Salt de KDF fixo no código.** `web/src/app/page.tsx:21`:
   `const SALT = "secure-vault-global-salt"; // Hardcoded for this simple MVP`.
   A mesma senha mestra gera **a mesma chave para todo mundo**. Uma tabela
   pré-computada quebra todos os vaults de uma vez, e dois usuários com a mesma
   senha conseguem abrir o dado um do outro.
2. **Nenhuma rota de API tem autenticação.** `GET /api/vault` devolve todos os
   registros para quem pedir. Não existe `middleware.ts`, sessão nem cookie
   (`grep` por `auth|session|cookie|jwt` em `web/src/` não acha nada). Combinado
   com o item 1, qualquer um baixa o vault inteiro e ataca offline com salt conhecido.
3. **Não compila.** `globals.css` importa `tw-animate-css` e `shadcn/tailwind.css`;
   as dependências declaradas são só `next`, `react`, `react-dom`.

### E o site não é o mesmo vault do CLI

| | CLI (Python) | Site (`web/`) |
|---|---|---|
| banco | `DATABASE_URL` (Postgres/SQLite) | **SQLite `file:./dev.db`**, separado |
| KDF | Argon2id, parâmetros gravados por vault | PBKDF2-SHA256, 600k, salt fixo |
| blob | `[versão][nonce][ct+tag]`, AES-256-GCM **com AAD** | `iv.ct` base64, AES-256-GCM **sem AAD** |
| `id` | inteiro | `String @default(uuid())` |

Não são dois clientes do mesmo vault — são dois produtos. **Unificar é decisão
de arquitetura e está na Fase 4**, deliberadamente depois de parar o sangramento.

---

## Fase 1 — o site deixa de expor senha `[prioridade máxima]`

### Decisão 1.1 — autenticar sem quebrar Zero-Knowledge

O servidor precisa saber que quem chama é o dono do vault, **sem nunca ver a senha
mestra nem a chave de cifragem**. Mandar a senha para o servidor validar destruiria
a propriedade central do produto.

Desenho adotado (o mesmo do Bitwarden, e é padrão do setor):

```
masterKey  = PBKDF2-SHA256(senha, salt_do_vault, 600_000)   ← NUNCA sai do browser
authValue  = PBKDF2-SHA256(masterKey, senha, 1)             ← vai ao servidor
servidor guarda  argon2id(authValue)  e compara
```

`authValue` é derivado da chave, não da senha, e uma iteração extra impede que ele
seja usado para recuperar `masterKey`. O servidor guarda um **hash** dele — vazar o
banco não dá nem a senha, nem a chave, nem o `authValue`.

**Alternativa recusada:** NextAuth / provedor externo. Criaria uma segunda
identidade sem relação com o vault, e o dono do vault continua sendo quem sabe a
senha mestra. Mais peça, menos garantia.

### Decisão 1.2 — salt aleatório por vault, servido pelo servidor

Entra um modelo `VaultConfig` no Prisma, singleton, espelhando o `vault_config` do
lado Python: `salt`, `kdfIterations`, `authHash`, timestamps.

- `GET /api/vault/config` → `{ salt, kdfIterations, initialized }`. **O salt não é
  segredo** — ele é público por desenho em todo vault ZK; o que ele precisa ser é
  **aleatório e único**, para matar tabela pré-computada.
- `POST /api/vault/config` → cria o vault na primeira vez (salt aleatório de 16
  bytes + `authHash`). Recusa se já existir, como o `vault init` faz.

### Decisão 1.3 — sessão em cookie httpOnly assinado

JWT curto (`jose`), `httpOnly`, `sameSite=strict`, `secure` fora de dev, TTL de 15
min renovável. Segredo em `SESSION_SECRET`, **nunca commitado**; o app recusa
subir sem ele em produção em vez de gerar um default silencioso.

**Alternativa recusada:** sessão em banco. Uma tabela a mais para um vault de um
usuário só, sem ganho — e o cookie assinado já é revogável trocando o segredo.

### Critérios de aceite da Fase 1

- [ ] `GET /api/vault` sem cookie válido responde **401**, não 200.
- [ ] O mesmo vale para `POST /api/vault`, `PUT`/`DELETE /api/vault/[id]` e `GET /api/vault/config` na parte que não seja `salt`/`initialized`.
- [ ] Dois vaults criados com a **mesma senha** têm `salt` diferente e `encryptedData` que um não abre o do outro.
- [ ] A senha mestra **não aparece** em nenhum corpo de requisição — provado por teste que inspeciona o payload.
- [ ] Teste negativo: `authValue` roubado do banco não decifra credencial nenhuma.
- [ ] Sem `SESSION_SECRET`, o app recusa iniciar em produção.

---

## Fase 2 — o site compila

Declarar as dependências que o `globals.css` importa e que ninguém instalou.
Verificar se `shadcn/tailwind.css` é real ou resíduo de scaffold — se for resíduo,
**remover o import** em vez de instalar peso morto.

### Critérios de aceite

- [ ] `npx next build` termina com exit 0.
- [ ] `npm run lint` limpo.
- [ ] `web/package.json` declara tudo que é importado; nada de dependência fantasma.

---

## Fase 3 — CRUD na TUI

Hoje `src/vault/tui/app.py` é só leitura. Faltam **adicionar, editar e apagar**.

As 6 telas do Renan em `origin/main:src/vault/tui/screens/` são **referência de
UX**, não código a portar: elas falam com uma API que não existe mais
(`crypto.encrypt_password`, `db.credentials`). O que se aproveita é o fluxo.

### Critérios de aceite

- [ ] Adicionar, editar e apagar pela TUI, com confirmação no apagar.
- [ ] Apagar exige a senha mestra, como na CLI — a TUI não pode ser o caminho fácil.
- [ ] Teste com o harness `Pilot` do Textual (`pytest-asyncio` já está instalado).
- [ ] A senha continua sem aparecer ao navegar: o painel de detalhe usa `CredentialMetadata`, não `reveal()`.

---

## Fase 4 — decisão: site e CLI viram o mesmo vault?

**Não é implementação, é decisão.** Registrada aqui para não ser tomada por acidente.

| Caminho | Custo | O que ganha | O que perde |
|---|---|---|---|
| **A — site vira cliente do vault Python** | alto: Argon2id no browser (WASM), formato de blob com AAD, `id` inteiro, migration | um vault só, uma criptografia só | reescrever a cripto do site |
| **B — seguem separados** | zero | nada a fazer | dois produtos com o mesmo nome; o usuário não entende por que um não abre o outro |
| **C — servidor traduz** | médio | site sem WASM | o servidor passa a precisar da chave → **mata o Zero-Knowledge** |

**Recomendação: A**, depois das fases 1 a 3. **C está descartado** — qualquer desenho
em que o servidor decifra deixa de ser Zero-Knowledge, que é a premissa do produto.

---

## Fora de escopo, dito explicitamente

- **App mobile.** Não existe e não entra aqui.
- **Reescrever histórico** para limpar o alerta do GitGuardian. Ver `MEMORIA.md`.
- **Publicar o site.** Enquanto a Fase 1 não fechar, ir ao ar é expor o vault.
