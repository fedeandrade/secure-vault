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

## Fase 1 — o site deixa de expor senha `[REPLANEJADA — desbloqueada, schema pronto]`

> ⛔ **A primeira versão desta fase foi REPROVADA por revisão adversarial em
> 22/09/2026 — 54/100.** Ela **criava dois caminhos de ataque que não existiam** e
> afirmava uma garantia falsa. O desenho abaixo é o revisado.
>
> O que a revisão **confirmou** estar certo: `authValue` não é invertível (resistência
> a pré-imagem do HMAC), e servir o `salt` sem autenticação é correto e necessário —
> o cliente precisa dele antes de ter qualquer chave, e é o que todo vault ZK faz.

### O que já está no lugar (22/09/2026)

A fase estava parada esperando a decisão de banco, que saiu. **O schema já foi
escrito e migrado junto com a Fase 2** — `VaultConfig` e `Session` existem em
`web/prisma/schema.prisma` e na migration inicial, com os comentários que
prendem as decisões abaixo ao código.

Dois ajustes de desenho entraram junto com o schema, e valem ser lidos antes de
implementar:

- ⛔ **`Session.id` guarda o SHA-256 do token do cookie, nunca o token.** O
  argumento inteiro a favor de sessão em banco (Decisão 1.3) foi *"vazar o banco
  não dá acesso"*; gravar o token cru entrega todas as sessões ativas a quem ler
  uma linha, e desfaz a decisão sem que ninguém perceba.
- ⚠️ ~~`tokenVersion` em `VaultConfig`.~~ **Removido.** Com sessão em banco,
  *encerrar todas as sessões* — e a troca de senha mestra — é
  `session.deleteMany({})`. A coluna não teria leitor, e coluna sem leitor faz o
  próximo a mexer aqui acreditar que existe revogação onde não existe.

Falta implementar: tudo que é código (derivação, rotas, middleware, CSP, init
local, runner de teste).

### Decisão 1.1 — derivação com HKDF, e a chave NÃO é exportável

```
raw   = PBKDF2-deriveBits(senha, salt, iteracoes, 256)          // Uint8Array, 32B
auth  = HKDF-Expand(raw, info="secure-vault:web.auth:v1", 32)   // base64 -> servidor
encK  = importKey("raw",
          HKDF-Expand(raw, info="secure-vault:web.enc:v1", 32),
          "AES-GCM", extractable=false, ["encrypt","decrypt"])
raw.fill(0)  // e o buffer intermediário do HKDF de cifragem
```

**Por que HKDF e não `PBKDF2(masterKey, senha, 1)`, que eu tinha escrito:** a
construção do Bitwarden não está quebrada — a revisão confirmou que ela resiste a
pré-imagem. Mas ela **entrelaça senha e chave** onde HKDF separa de forma
explícita, custa o mesmo para implementar, e **contraria a política que este
projeto já escreveu**: `src/vault/core/kdf.py:14-20` diz que *"passar a saída por
um HKDF com um rótulo fixo torna a separação explícita e sobreviveria até a um
erro futuro de alguém reaproveitar o mesmo salt"*. Como a Fase 4 recomenda
unificar com o lado Python, adotar o formato Bitwarden agora garantiria uma
segunda reescrita depois. Com HKDF, a Fase 4 vira troca de parâmetro.

⚠️ **`extractable: false` é obrigatório e não é detalhe de estilo.** Hoje
`web/src/lib/crypto.ts:20` passa `extractable = true` e a chave vive no state do
React — **um XSS faz `crypto.subtle.exportKey` e leva a chave mestra em claro**.
Só com `deriveBits` + HKDF dá para ter a chave de cifragem não-exportável *e*
ainda produzir o `authValue`: uma `CryptoKey` AES não-exportável não alimenta
PBKDF2. Quem for implementar e trocar por `true` "porque não compila" está
reabrindo exatamente este buraco.

### Decisão 1.2 — chave do vault envelopada (`wrappedVaultKey`)

Os registros **não** são cifrados com a chave derivada da senha. São cifrados com
uma `vaultKey` de 32 bytes aleatórios, e a `vaultKey` é guardada cifrada:

```
vaultKey        = random(32)                                   // no init
wrappedVaultKey = AES-GCM(encK, vaultKey, aad="secure-vault:web.vaultkey:v1")
```

**Por quê:** sem isso, trocar a senha mestra significa redecifrar e recifrar os N
registros no browser, sem transação. A aba morrer no registro 40 de 200 deixa 40
blobs sob a chave nova e 160 sob a velha — e o cliente **não tem como saber qual
é qual**, porque `decryptPayload` lança a mesma exceção nos dois casos. Vault meio
ilegível, sem diagnóstico. Com envelope, trocar senha reescreve **um** blob, de
forma atômica. Endurecer o KDF depois, idem. Um segundo dispositivo ou chave de
recuperação viram "envelopar a `vaultKey` de novo".

**Custo de fazer agora: zero.** Não existe `.db` no disco (medido) e o plano
proíbe publicar antes desta fase. Depois, seria recifrar vault vivo.

### Decisão 1.3 — sessão em BANCO, não JWT `[REVERTIDA]`

⚠️ ~~"JWT em cookie httpOnly; sessão em banco seria uma tabela a mais sem ganho."~~
**Errado, e a revisão desmontou com três argumentos:**

1. **O ganho é revogação**, que o próprio plano depois admitia não ter. Cookie
   roubado + TTL deslizante renovável = acesso **indefinido**: basta uma
   requisição a cada 14 minutos. Trocar a senha mestra não invalidava nada,
   porque nada no JWT estava amarrado ao `authHash`.
2. **`alg confusion` e gerência de segredo** deixam de existir.
3. **O pior:** se `SESSION_SECRET` mora no `.env` ao lado de `prisma/dev.db`,
   quem rouba o banco rouba o segredo, **forja um cookie e lê todos os
   ciphertexts sem passar pelo argon2id**. Sessão em banco torna segredo vazado
   inútil.

Tabela `Session(id, expiresAt, absoluteExpiresAt, createdAt)`: ~6 linhas de
schema, uma leitura local por request. Mais expiração **absoluta** (8h) além do
TTL deslizante, e `tokenVersion` em `VaultConfig` incrementado a cada troca de
senha e num botão "encerrar todas as sessões".

Cookie com prefixo **`__Host-`** (força `Secure`, `Path=/`, proíbe `Domain`) —
sem ele, um subdomínio irmão comprometido sobrescreve a sessão, e
`httpOnly`/`sameSite` não impedem.

### Decisão 1.4 — o cliente tem piso de KDF e fixa os parâmetros

```
const MIN_KDF_ITERATIONS = 600_000;        // constante no bundle, não vem do servidor
if (cfg.kdfIterations < MIN_KDF_ITERATIONS) throw  // erro visível, nunca silencioso
```

**Este era o pior achado, e o desenho anterior o criou.** Servir `kdfIterations`
transformava um valor imutável (hoje `crypto.ts:15` tem `600000` fixo) em valor
**escolhido pelo atacante**. Com escrita no banco — backup exposto, volume
montado, host comprometido — bastava `UPDATE VaultConfig SET kdfIterations = 1`:
o próximo registro salvo nasce sob chave fraca, e quebrar por dicionário passa a
custar **2 hashes por palpite em vez de 600.000**. Fator ~300.000x. Com a senha
recuperada, o atacante abre também todo o resto, inclusive o que é antigo.

Além do piso, **fixar `{salt, kdfIterations}` em `localStorage`** no primeiro
unlock bem-sucedido e bloquear com aviso se mudarem.

### Decisão 1.5 — inicialização sai do HTTP

⚠️ ~~`POST /api/vault/config` cria o vault na primeira vez e recusa se já existir.~~
**Isso era takeover remoto não autenticado.** Entre o deploy e o primeiro acesso
do Felipe, qualquer um que achasse a URL via `initialized: false`, fazia o POST
com o próprio `salt`/`authHash`, e a recusa "se já existir" **trancava o dono
para fora** — recuperável só com acesso ao filesystem.

Inicialização vira script local (`npm run vault:init`). Se um dia precisar ser
rota, atrás de header casando com `SETUP_TOKEN` do ambiente.

Fechado isso, `initialized: true/false` deixa de importar: é um vault de um
usuário só, não há conta a enumerar. No login, 401 idêntico para "não existe" e
"senha errada", verificando contra hash-dummy quando não inicializado para não
vazar por tempo.

### Decisão 1.6 — blob versionado desde já

`crypto.ts:42` grava `iv.ct`, **sem marcador de versão**. O lado Python resolveu
isso de propósito (`crypto.py:16-20`, `BLOB_VERSION`): *"migrar de cifra vira
tentativa e erro sobre dados que ninguém consegue ler"*.

Passa a gravar **`v1.iv.ct`**, recusando versão desconhecida com mensagem própria.

Sobre AAD: a razão do Python (confusão entre colunas) **não transfere** — no web
há um blob por registro. O que transfere é **vínculo de identidade**, e o ataque
é concreto: com escrita no banco, o atacante restaura o `encryptedData` anterior
de uma linha; o cliente decifra **sem erro nenhum**, e o Felipe lê como atual a
senha que ele acabou de trocar justamente por ela ter vazado. O mesmo vale para
*undelete*. O AAD (`...|<id>|<version>`, com coluna `version` incrementada em cada
`PUT`) entra como `v2` — mas **só é possível depois porque o `v1.` está lá agora**.

### Decisão 1.7 — sentinela de chave, e nunca descartar em silêncio

`page.tsx:57` faz `decrypted.filter(Boolean)`: todo registro que falha vira `null`
e **some**. Com zero sobreviventes a tela diz **"No items found."** — ou seja,
chave errada, downgrade de KDF, vault meio-migrado e blob adulterado produzem
todos a mesma tela: *vault vazio*. O desfecho realista é o Felipe recadastrar
tudo, agora sob parâmetros que o atacante escolheu.

`keyCheck` em `VaultConfig`, verificado **antes** de renderizar. E erro explícito:
*"N de M registros não puderam ser abertos"*, nunca lista vazia.

O `authValue` **não** serve de key check: ele prova que o servidor aceitou você,
não que a sua chave abre os dados. Sob o ataque da Decisão 1.4 os dois discordam —
login OK, vault "vazio".

### Decisão 1.8 — o login não pode virar amplificador de DoS

Força bruta *online* já é cara para o atacante (produzir um `authValue` válido
custa 600k PBKDF2, ~1s) — isso o desenho acertou. **O furo é a assimetria:** um
`authValue` inválido não custa nada a ele e custa argon2id ao servidor, que no
lado Python roda com `memory_cost=65536` (64 MB). 30 POSTs concorrentes com bytes
aleatórios alocam ~2 GB e derrubam o processo. Zero credenciais necessárias.

Ordem obrigatória dentro da rota:

1. validar que `authValue` é base64 de **exatamente 32 bytes** — antes de tudo;
2. rate limit por IP + `failedAttempts`/`lockedUntil` persistidos;
3. semáforo de concorrência 1–2 em volta do `argon2.verify`;
4. atraso exponencial em vez de lockout duro (com um usuário só, lockout duro é
   auto-DoS).

### Decisão 1.9 — cabeçalhos de segurança

`web/next.config.ts` está vazio: **zero cabeçalhos**. E `httpOnly` protege o
cookie de ser *lido*, não de ser *usado* — um XSS faz `fetch('/api/vault')` na
mesma origem e o cookie viaja sozinho.

No mesmo `middleware.ts` da autenticação:
`default-src 'self'; script-src 'self' 'nonce-…'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`,
mais `Referrer-Policy: no-referrer` e `X-Content-Type-Options: nosniff`.
Checagem de `Origin` nos métodos que mudam estado.

### Decisão 1.10 — `SESSION_SECRET`: presença não basta

- exigir **≥32 bytes depois de decodificar**, não só "está definido"
  (`SESSION_SECRET=changeme` passa numa checagem de presença);
- validar **preguiçosamente** (no request ou em `instrumentation.ts`),
  **nunca no topo de módulo**: `next build` roda com `NODE_ENV=production`, e um
  `throw` no carregamento quebra o build em CI sem o segredo — o "conserto"
  previsível de quem estiver com pressa é pôr um default, exatamente o buraco que
  a checagem existia para fechar;
- exigir em dev também, com `npm run dev` gerando um em `.env.local`.

### ⚠️ A garantia que este plano afirmava, corrigida

~~"O servidor guarda um hash dele — vazar o banco não dá nem a senha, nem a
chave, nem o `authValue`."~~ **Literalmente verdade; na prática, engana.**

Vazar o banco dá um **oráculo de verificação offline**: para cada candidato de
senha, derive e teste com `argon2id.verify(authHash, …)`. Não se inverte o
argon2id — usa-se ele como verificador, que é para isso que ele existe. Custo por
palpite: **o mesmo** de atacar os ciphertexts, que estão no mesmo arquivo.

**A redação correta:** *vazar o banco não entrega senha nem chave diretamente,
mas permite ataque offline ao mesmo custo do ataque aos ciphertexts; depois de um
vazamento, a única coisa entre o atacante e o vault é a entropia da senha mestra.*

Por isso entra também **piso de força da senha mestra no `init`**, client-side (o
único que burla é o dono). O Python já tem `src/vault/core/strength.py`; o web não
tem equivalente.

### ⚠️ E uma honestidade que faltava sobre o que ZK protege

ZK no browser protege contra **roubo do banco** e contra **observador passivo da
rede**. **Não protege contra o operador do servidor**, porque é ele quem serve o
JavaScript que segura a chave. "O servidor nunca vê a senha" é verdade do código
atual, não de qualquer código que a mesma origem venha a servir amanhã. CSP e pin
de salt estreitam essa janela; não a fecham.

### O que a Fase 1 precisava e não tinha: harness de teste

⛔ `web/package.json` **não declara test runner nenhum** (medido: sem vitest, jest
ou playwright). Os critérios de aceite exigem teste que inspeciona payload e teste
negativo de `authValue` — **como estava escrito, a fase não conseguia fechar pelos
próprios critérios**. Instalar o runner entra no escopo da Fase 1.

### Critérios de aceite (revistos)

- [ ] `GET/POST /api/vault` e `PUT/DELETE /api/vault/[id]` sem sessão válida → **401**.
- [ ] A senha mestra não aparece em nenhum corpo de requisição — teste que inspeciona o payload.
- [ ] `authValue` roubado do banco não decifra credencial nenhuma — teste negativo.
- [ ] `kdfIterations` abaixo do piso → erro **visível**, não degradação silenciosa.
- [ ] `salt` ou `kdfIterations` mudando depois do primeiro unlock → bloqueio com aviso.
- [ ] Inicialização **não** é alcançável por HTTP sem `SETUP_TOKEN`.
- [ ] Troca de senha mestra reescreve **um** blob (`wrappedVaultKey`), não N.
- [ ] `keyCheck` inválido → erro explícito; **nunca** "No items found".
- [ ] Registro que não abre aparece como *"N de M não puderam ser abertos"*.
- [ ] Blob gravado começa com `v1.`; versão desconhecida tem mensagem própria.
- [ ] `authValue` que não seja base64 de 32 bytes é recusado **antes** do argon2id.
- [ ] Trocar a senha mestra invalida sessões existentes.
- [ ] Cookie usa prefixo `__Host-`.
- [ ] CSP presente; `crypto.subtle.exportKey` na chave de cifragem **falha**.
- [ ] Sem `SESSION_SECRET` válido (≥32 bytes) o app recusa servir — sem quebrar `next build`.
- [ ] Test runner declarado e rodando no CI.

---

## Fase 2 — o site compila `[FECHADA]`

⚠️ **Estimei "20 minutos para declarar dependência". Estava errado**, e o erro vale
ficar registrado: ao puxar o fio, o que apareceu foi que **o site nunca foi
executável**, não que faltava um pacote.

### Feito ✅

- **Andaime shadcn morto removido** — `components/ui/button.tsx`, `lib/utils.ts` e
  `components.json`. Ninguém os importava, e `lib/utils.ts` fazia
  `export { cn } from "cn"`, um pacote que não existe. Os imports
  `tw-animate-css` e `shadcn/tailwind.css` saíram do `globals.css`: nenhuma
  classe `animate-*`/`data-[state=` é usada em `src/`, e as variáveis do
  `@theme inline` são todas definidas no próprio `:root`. **Remover em vez de
  instalar 6 pacotes** — num gerenciador de senhas cada dependência é superfície
  de supply chain. `next build` passou a compilar (`✓ Compiled successfully`).
- **`@prisma/client` passou a ser declarado.** Estava em `node_modules` por
  acaso, sem entrada no `package.json`.
- **A CLI do Prisma era outro produto.** O `package.json` pedia
  `prisma@^8.0.0-rc.15` — a *Prisma Developer Platform*, que **não tem
  `prisma generate`** (medido: `CLI.UNKNOWN_COMMAND`) e cujo `prisma orm` só tem
  `init`. O código é Prisma ORM clássico. Alinhado a `^7.10.0` estável, a mesma
  versão do cliente já instalado.
- **`postinstall: prisma skills sync` removido** — comando da 8-RC. Era ele que
  criava `web/.agents/`, `.claude/`, `.cursor/` e `.devin/` sem ninguém pedir.
- **`prisma.config.ts` do Felipe** usava `definePrismaConfig`, API da 8-RC que
  **quebra a CLI 7.x inteira**. Tirado do caminho e preservado em
  [`wip-felipe/prisma.config.ts.8rc-wip`](wip-felipe/prisma.config.ts.8rc-wip).
- **Assinatura das rotas corrigida para Next 16**: `params` chega como `Promise`,
  e o tipo dizia síncrono (`PUT` e `DELETE` de `api/vault/[id]`).

### Desbloqueado ✅ — a decisão de banco saiu em 22/09/2026

⚠️ ~~"`npx tsc --noEmit` deixou **um** erro: `Module '"@prisma/client"' has no
exported member 'PrismaClient'`. Escolher o adapter é escolher o banco, e isso é
a decisão da Fase 4. **Fase 2 fecha junto com a decisão de banco.**"~~
**Superado:** o Felipe escolheu **Postgres próprio do site**. Não fica amarrado
ao vault Python enquanto os formatos forem incompatíveis, e é o que o Prisma 7
espera com driver adapter.

O erro tinha duas causas, não uma, e a segunda só apareceu ao consertar a primeira:

- `datasource` do Prisma 7 **não aceita mais `url`** — ela vai para
  `prisma.config.ts`.
- O gerador `prisma-client-js` **saiu**. O novo `prisma-client` exige `output`
  explícito e **não escreve dentro de `node_modules`** — por isso o import deixa
  de ser `@prisma/client` e passa a ser o caminho gerado
  (`@/generated/prisma/client`). Era esta a causa real da mensagem.

O que entrou:

- **`web/prisma/schema.prisma`**: `provider = "postgresql"`, sem `url`; gerador
  `prisma-client` com `output = "../src/generated/prisma"`.
- **`web/prisma.config.ts`** novo, com `import "dotenv/config"` — o CLI do
  Prisma 7 deixou de carregar `.env` sozinho.
- ⚠️ **`process.env["DATABASE_URL"]`, e não `env("DATABASE_URL")`.** Medido:
  `env()` **não é preguiçoso** — resolve ao carregar o config e aborta com
  `PrismaConfigEnvError` se a variável faltar. Isso quebraria `prisma generate`
  no CI e no build da Vercel, onde a URL do banco não precisa (nem deve) existir
  para gerar tipos. Com `process.env`, generate passa sem a variável e só
  `migrate`/`studio` reclamam. **O job `web` do CI roda sem `DATABASE_URL` de
  propósito: quem trocar de volta deixa o CI vermelho.**
- **`@prisma/adapter-pg`** instalado (`pg` vem junto, transitivo). O cliente é
  criado na **primeira consulta**, não ao carregar o módulo, e recusa subir sem
  `DATABASE_URL` — sem essa recusa o `pg` cai nos padrões dele e o app conecta em
  silêncio no banco errado, com sintoma de *"o vault está vazio"*.
- **`"build": "prisma generate && next build"`** — o `postinstall` foi removido na
  limpeza acima, então o build precisa gerar o cliente; provado apagando
  `src/generated/` e rodando o build do zero.
- **Serviço `postgres-web`** no `docker-compose.yml`, com volume e porta (5433)
  próprios. **Não** um segundo database no container existente: script de
  `initdb.d` só roda na primeira criação do volume, e `vault_pgdata` já existe —
  o database simplesmente não seria criado, em silêncio.
- **Migration inicial** em `web/prisma/migrations/20260922120000_init_postgres_zero_knowledge/`,
  gerada offline (`migrate diff --from-empty --to-schema`, porque não há Docker
  nesta máquina). Já traz `VaultConfig` e `Session` da Fase 1 — fazer a migration
  duas vezes era o desperdício que o bloqueio previa.
- **Job `web` no CI** (`npm ci` → `prisma generate` → `tsc` → `eslint` →
  `next build`), separado do job Python: uma falha de lint do TypeScript não pode
  esconder o resultado da suíte Python.
- Os cinco `any` e os bindings de `catch` sem leitor saíram, senão o job novo
  nasceria vermelho. `encryptPayload`/`decryptPayload` viraram genéricos — mesmo
  comportamento, com o tipo devolvido a quem chama.

### Critérios de aceite (revistos)

- [x] `globals.css` resolve; o build compila.
- [x] `web/package.json` declara tudo que é importado.
- [x] CLI e cliente do Prisma na mesma versão estável.
- [x] Rotas tipadas conforme o Next 16.
- [x] `npx tsc --noEmit` limpo — **0 erros** (medido em 22/09/2026).
- [x] `npx next build` exit 0.
- [x] `npm run lint` limpo — 0 erros, 0 avisos.

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

### Decidido em 22/09/2026 — o banco do site é próprio

O Felipe escolheu: **Postgres dedicado ao site**, separado do banco do CLI.
Isso é metade da Fase 4 e foi o que destravou as Fases 1 e 2.

O que essa escolha **fecha**: o site deixa de depender de filesystem (era
`file:./dev.db`, que em host serverless é efêmero ou somente-leitura), e o
adapter do Prisma 7 pôde ser escolhido.

O que essa escolha **não fecha**: banco separado não decide se os dois produtos
compartilham *formato de vault*. Hoje não compartilham — o Python cifra a
credencial inteira num blob sob AAD; o web grava `iv.ct` por registro. A tabela
abaixo continua aberta.

| Caminho | Custo | O que ganha | O que perde |
|---|---|---|---|
| **A — site vira cliente do vault Python** | alto: Argon2id no browser (WASM), formato de blob com AAD, `id` inteiro, migration | um vault só, uma criptografia só | reescrever a cripto do site |
| **B — seguem separados** | zero | nada a fazer | dois produtos com o mesmo nome; o usuário não entende por que um não abre o outro |
| **C — servidor traduz** | médio | site sem WASM | o servidor passa a precisar da chave → **mata o Zero-Knowledge** |

**Recomendação: A**, depois das fases 1 a 3. **C está descartado** — qualquer desenho
em que o servidor decifra deixa de ser Zero-Knowledge, que é a premissa do produto.

⚠️ A Fase 1 foi desenhada para **não encarecer o A**: HKDF com rótulo fixo é a
mesma política de `src/vault/core/kdf.py`, então unificar vira troca de parâmetro
em vez de segunda reescrita. Adotar o formato Bitwarden teria custado o dobro.

---

## Registrado, mas fora da Fase 1 — achados da revisão que precisam de dono

Nenhum destes expõe senha hoje. Ficam escritos para não sumirem.

1. **Área de transferência sem auto-limpeza** (`page.tsx:204`). No Windows 11 o
   histórico (Win+V) vem ligado por padrão e persiste; com sincronização, a senha
   em texto claro vai para a nuvem da Microsoft. O Python tem
   `src/vault/core/clipboard.py` com auto-clear; o web não tem nada.
2. **Todas as senhas decifradas de uma vez, e sem auto-lock de tela.** O TTL de
   sessão é do servidor, não da aba: notebook aberto expõe o vault inteiro.
   Considerar decifrar sob demanda, por registro.
3. ✅ ~~**`schema.prisma:7` fixa `file:./dev.db`, sem variável de ambiente.** Em
   qualquer host serverless o filesystem é efêmero ou somente-leitura → vault
   perdido ou não gravável.~~ **Resolvido em 22/09/2026** com a decisão de banco:
   `provider = "postgresql"`, URL por `DATABASE_URL` em `prisma.config.ts`,
   nenhum caminho de arquivo no schema. Ver Fase 2.
4. **`encryptedData` aceito sem validação de tipo nem de tamanho**
   (`api/vault/route.ts:18`). Depois da autenticação ainda permite encher o
   disco; antes dela, qualquer um.

## Fora de escopo, dito explicitamente


- **App mobile.** Não existe e não entra aqui.
- **Reescrever histórico** para limpar o alerta do GitGuardian. Ver `MEMORIA.md`.
- **Publicar o site.** Enquanto a Fase 1 não fechar, ir ao ar é expor o vault.
