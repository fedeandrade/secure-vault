# Especificação de segurança — secure-vault

Contrato normativo. O que está escrito aqui como **DEVE** é invariante do
produto: mudar exige decisão explícita registrada, não um commit de refactor.

O [`README.md`](../README.md) explica as escolhas para quem chega. Este documento
existe para o caso oposto — alguém prestes a mudar o código e precisando saber o
que não pode quebrar.

Última medição: 22/09/2026. Suíte 255 passed / 12 skipped, `ruff` limpo.

---

## 1. Modelo de ameaça

### Contra o que este produto protege

| Adversário | O que ele consegue | O que o vault garante |
|---|---|---|
| Quem rouba o arquivo/dump do banco | todos os bytes gravados | Nenhum texto claro. Nem senha, nem nome de serviço, nem login |
| Quem lê o banco em repouso (backup, volume, snapshot) | idem | idem |
| Quem observa a rede (só no web) | tráfego HTTPS | Só ciphertext sobe; a senha mestra nunca sai do browser |
| Quem tem o vault mas não a senha mestra | banco completo | Ataque offline ao custo do Argon2id por palpite |

### Contra o que **não** protege — declarado, não esquecido

1. **Memory dumping.** A chave existe em memória enquanto o processo roda.
   `wipe()` reduz a janela; não a fecha. O CPython pode ter feito cópias fora do
   nosso alcance e a página pode ir para o swap.
2. **Canal lateral fino.** Comparações críticas usam `compare_digest`; não há
   defesa contra cache timing.
3. **O operador do servidor, no lado web.** ZK no browser protege contra roubo do
   banco e observador de rede. **Não protege contra quem serve o JavaScript** —
   é ele que segura a chave. "O servidor nunca vê a senha" é verdade do código
   atual, não de qualquer código que a mesma origem venha a servir amanhã.
4. **Força bruta local no CLI.** O custo do Argon2id é a única barreira; não há
   bloqueio após N erros.
5. **Perder a senha mestra.** É perder tudo. Isso é o objetivo, e é também a
   consequência.

### A garantia que é fácil exagerar

Vazar o banco **não** entrega senha nem chave diretamente — mas entrega um
**oráculo de verificação offline**: para cada candidato de senha, derive e teste
contra o hash. Não se inverte o Argon2id; usa-se ele como verificador, que é para
isso que ele existe. Custo por palpite: **o mesmo** de atacar os ciphertexts, que
estão no mesmo arquivo.

**Redação correta:** *depois de um vazamento, a única coisa entre o atacante e o
vault é a entropia da senha mestra.* Por isso o piso de força na criação não é
enfeite.

---

## 2. Invariantes criptográficos — CLI e TUI (Python)

### 2.1 Derivação

- A senha mestra **DEVE** passar por **Argon2id**, com os parâmetros gravados
  **no vault**, nunca fixados no código.
  *Por quê:* parâmetro no código significa que subir `time_cost` torna ilegível
  todo vault existente, sem nenhuma mensagem dizendo por quê.
- A saída **DEVE** ser separada por **HKDF-Expand com rótulo fixo** antes de
  virar chave de cifragem ou valor de autenticação.
  *Por quê:* salts diferentes já bastariam, mas "não são iguais por acidente do
  salt" é garantia frágil. O rótulo torna a separação explícita e sobrevive a
  alguém reaproveitar o mesmo salt no futuro.
- A chave derivada **NÃO DEVE** tocar o disco. Nunca.

### 2.2 Cifragem

- **AES-256-GCM**, sempre com *associated data*.
- O blob gravado **DEVE** ser versionado: `[1 byte versão][12 bytes nonce][ct+tag]`.
  *Por quê:* sem marcador, migrar de cifra vira tentativa e erro sobre dados que
  ninguém consegue ler.
- O nonce **DEVE** ser sorteado por CSPRNG a **cada** operação de cifragem —
  nunca reaproveitado entre registros nem entre gravações do mesmo registro.
  *Por quê:* reusar nonce em GCM não vaza um valor, permite **recuperar a chave
  de autenticação**. É a falha mais séria possível neste modo. Coberto por
  `tests/unit/test_crypto.py::test_nonce_nunca_se_repete`.
- ⛔ Um rótulo de AAD **NUNCA DEVE** ser reaproveitado com significado novo.
  Crie `:v2`. Trocar o sentido de um rótulo torna indecifrável todo texto cifrado
  sob ele.

### 2.3 Zero-Knowledge (desde 22/09/2026)

- A credencial **inteira** — serviço, login, URL, senha, notas, segredo TOTP —
  **DEVE** ser serializada e cifrada num **único** blob, sob `AAD_CREDENTIAL`.
- O banco **NÃO DEVE** ter coluna legível de conteúdo. O que resta em claro:
  `id`, timestamps e o próprio blob.
- **Consequência aceita:** listar e buscar exigem a chave e custam O(n)
  decifragens. Não há índice possível. A varredura **DEVE** ser feita por gerador
  (um payload vivo por vez), não materializando a lista inteira — a TUI chama
  busca a cada tecla.
- A unicidade `(serviço, login)` passou a ser da aplicação. O banco **não** barra
  mais duplicata; quem confiar em constraint vai inserir duas iguais em silêncio.

### 2.4 Sentinela de chave

- `verify_key_check` **DEVE** exigir a sentinela e **NÃO DEVE** aceitar ausência
  como sucesso.
  *Por quê:* a primeira versão devolvia `True` para `blob=None`. Bastava a coluna
  sumir — e o `downgrade` do Alembic a derruba — para `unlock` passar a aceitar
  qualquer chave derivada.

### 2.5 Exclusão

- `delete_credential` **DEVE** apagar a linha fisicamente.
  *Por quê:* foi medido. Com soft delete, `list` devolvia vazio e `count` zero,
  mas a linha continuava no banco, a senha vazada continuava abrindo, e o
  `vault passwd` **re-cifrava a credencial apagada** — mantendo a senha que o
  usuário apagou justamente por ter vazado, agora sob a chave nova, para sempre.
- A re-cifragem do `vault passwd` **DEVE** varrer sem filtro de `deleted_at`, e
  isso é intencional: enquanto a coluna existir como marca de sincronização do
  vault web, ignorá-la deixaria blob órfão sob a chave velha.

### 2.6 Migration

- Migration que muda formato de blob **DEVE RECUSAR** vault com credenciais, no
  `upgrade` **e** no `downgrade`.
  *Por quê:* converter sem a chave é impossível; tentar produz banco corrompido
  sem mensagem. Recusar é a única resposta honesta. Vault vazio continua passando.

---

## 3. Invariantes do cliente web

⛔ **Estado em 22/09/2026: o site NÃO cumpre esta seção.** Ele tem salt global
fixo, API sem autenticação nenhuma e chave exportável. A Fase 1 do
[`ROADMAP`](ROADMAP.md) é o trabalho de fazê-lo cumprir. **Não publicar antes.**

O que **DEVE** valer quando a Fase 1 fechar:

| # | Invariante | Por quê |
|---|---|---|
| 3.1 | `salt` **por vault**, aleatório | O global fixo faz uma rainbow table servir para todos |
| 3.2 | Chave de cifragem com `extractable: false` | Com `true`, um XSS faz `exportKey` e leva a chave mestra em claro |
| 3.3 | Piso `MIN_KDF_ITERATIONS` **no bundle**, não vindo do servidor | Servir o parâmetro deixa o atacante escolhê-lo: `UPDATE ... SET kdfIterations = 1` derruba o custo por palpite de 600.000 hashes para 2 |
| 3.4 | `{salt, kdfIterations}` fixados no cliente após o primeiro unlock | Detecta troca posterior |
| 3.5 | `vaultKey` aleatória, guardada em `wrappedVaultKey` | Trocar a senha reescreve **um** blob, atômico. Sem envelope, a aba morrer no registro 40 de 200 deixa o vault meio ilegível **sem diagnóstico possível** |
| 3.6 | Sessão em **banco**, com expiração absoluta além do TTL deslizante | Revogação. Cookie roubado + TTL renovável = acesso indefinido |
| 3.7 | `Session.id` guarda **SHA-256 do token**, nunca o token | Senão vazar o banco entrega todas as sessões ativas — e era esse o argumento a favor de sessão em banco |
| 3.8 | Cookie com prefixo `__Host-` | Sem ele, subdomínio irmão comprometido sobrescreve a sessão |
| 3.9 | Inicialização **fora do HTTP** | `POST /api/vault/config` público era takeover remoto: qualquer um inicializava com o próprio salt e trancava o dono para fora |
| 3.10 | Blob gravado começa com `v1.` | Mesma razão do 2.2 |
| 3.11 | `keyCheck` conferido **antes** de renderizar; nunca `filter(Boolean)` | Sem isso, chave errada e vault meio-migrado mostram "nenhum item" — e o desfecho realista é o dono recadastrar tudo sob parâmetros que o atacante escolheu |
| 3.12 | `authValue` validado como base64 de 32 bytes **antes** do argon2id | Senão o login vira amplificador de DoS: 30 POSTs com bytes aleatórios alocam ~2 GB |
| 3.13 | CSP com `frame-ancestors 'none'` e `object-src 'none'` | `httpOnly` protege o cookie de ser lido, não de ser **usado**: um XSS faz `fetch` na mesma origem e o cookie viaja sozinho |
| 3.14 | `SESSION_SECRET` exigido com ≥32 bytes **decodificados**, validado preguiçosamente | `changeme` passa numa checagem de presença; validar no topo do módulo quebra `next build` no CI, e o conserto apressado previsível é pôr um default |

---

## 4. O que os dois lados ainda **não** compartilham

| | Python (CLI/TUI) | Web |
|---|---|---|
| `id` | inteiro autoincrementado | `String @id @default(uuid())` |
| blob | `LargeBinary` | `String` |
| KDF | Argon2id | PBKDF2-600k |
| formato | blob versionado **com AAD** | `iv.ct` base64, **sem AAD** |
| payload | `snake_case` | `camelCase` |
| banco | Postgres do CLI | Postgres próprio (decidido 22/09/2026) |

**Interoperabilidade é impossível hoje**, e não por acaso de implementação.
Unificar é decisão de arquitetura, registrada na Fase 4 do
[`ROADMAP`](ROADMAP.md) — e a recomendação é o site virar cliente do formato
Python, nunca o servidor decifrar (isso mataria o Zero-Knowledge).

---

## 5. Como provar que um invariante continua valendo

Regra da casa: **se você não consegue descrever o teste que reprovaria, você não
verificou — torceu.**

| Invariante | Prova executável |
|---|---|
| Nonce nunca repete (Python) | `tests/unit/test_crypto.py::test_nonce_nunca_se_repete` |
| Nonce nunca repete (web) | `web/src/lib/crypto.test.ts` — 20 cifragens do mesmo dado, 20 IVs distintos |
| AAD errado não abre | `tests/unit/test_crypto.py` |
| Blob adulterado é recusado | `web/src/lib/crypto.test.ts` |
| Salt diferente ⇒ chave diferente | `web/src/lib/crypto.test.ts` |
| Migration recusa vault populado | `tests/integration/test_migrations.py` |
| Tudo junto | `node scripts/gate.mjs` — e ele **reprova** de verdade: com o IV fixado em zeros, saiu exit 1 apontando `web · vitest` |
