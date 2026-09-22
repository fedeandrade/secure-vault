# MEMORIA — Secure Vault

Estado autoritativo do projeto. Ao entrar aqui, leia este arquivo antes do
código. Se algo divergir do sistema vivo, o sistema vence e **este arquivo é
corrigido no mesmo trabalho**.

## Estado — 22/09/2026 (o que vale hoje)

✅ **A suíte está VERDE: 255 passed, 12 skipped, `ruff check .` limpo.** Provado
pelo hook do gate, não só pelo shell — `GATE VERDE` no
`~/.claude/gate-cache/ultima-execucao.log`, 22/09/2026.

Os 12 `skipped` são **todos** de `test_migrations.py` e só rodam com
`TEST_DATABASE_URL` apontando para um Postgres real. **Postgres não foi medido
nesta rodada** — o que vale aqui é SQLite.

⛔ ~~Estava VERMELHA no começo do dia: **41 failed, 195 passed, 12 skipped, 14
errors** — 55 itens.~~ A migração Zero-Knowledge foi **terminada em 22/09/2026**
e é o que fechou os 55. O que mudou está na seção "A migração Zero-Knowledge,
terminada" abaixo.

⚠️ **A suíte quebrava conforme QUEM a rodava, e isso está consertado.** O `Console`
do Rich liga a cor pela **presença** de `FORCE_COLOR`, não pelo valor: o hook do
gate exporta `FORCE_COLOR=0` tentando desligar a cor e **ligava**. Seis testes que
passavam no shell reprovavam sob o gate. O pior nem parecia problema de cor — o
segredo TOTP saía da CLI com `\x1b[1m` no meio e o `base32decode` estourava
`binascii.Error: Non-base32 digit found`. Corrigido no **topo** do
`tests/conftest.py`, e não numa fixture: o `Console` é construído no import de
`vault.cli.main` e lê o ambiente ali, uma vez só — apagar a variável numa fixture
`autouse` chega tarde demais.

⚠️ **Cuidado ao medir:** o `addopts` do `pyproject.toml` já inclui `-q`. Passar
`-q` de novo vira `-qq` e o pytest **omite a linha de total** — foi assim que a
primeira medição deste dia leu "58 unitários" (era contagem de pontos numa linha
que quebrou) em vez de 130. Rode sem `-q` extra quando quiser o número.

## A migração Zero-Knowledge, terminada em 22/09/2026

**O que estava quebrado:** o commit `6a7c6b7` (20/09) trocou `Credential` por um
blob opaco — sobraram `id`, `encrypted_data`, `created_at`, `updated_at`,
`deleted_at` — mas `repository.py`, `cli/main.py`, `cli/shell.py`, `tui/app.py` e
`core/master_password.py` continuavam consultando `Credential.service_name` e
`encrypted_password`. Modelo, payload, migration e web foram commitados; **as
camadas que os consomem, não.** Erro exato:
`AttributeError: type object 'Credential' has no attribute 'service_name'`.

**O desenho não era dúvida — já estava commitado.** A migration
`edb62ca16834_zero_knowledge_schema` adiciona só `encrypted_data` e `deleted_at`,
derruba `service_name`, `login`, `url`, `encrypted_password`, `encrypted_notes`,
`encrypted_totp_secret` **e o índice `ix_credentials_service_name`**. Não há blind
index nem coluna de HMAC. O `web/prisma/schema.prisma` também é blob puro. Logo:
busca é **decifra-depois-filtra na aplicação**, e não havia alternativa a escolher.

⚠️ "Também é blob puro" **não** quer dizer que os dois lados sejam compatíveis —
ver "Os dois vaults não falam a mesma língua", abaixo.

**O que mudou de contrato, e por quê:**

| Antes | Agora | Motivo |
|---|---|---|
| `list_credentials(session)` | `list_credentials(session, key)` | sem chave não há nome de serviço para ordenar |
| `search_credentials(session, q)` | `search_credentials(session, key, q)` | idem; o `LIKE` virou `in` sobre texto decifrado |
| `find_by_service_login(session, s, l)` | `find_by_service_login(session, key, s, l)` | idem; devolve metadado, não a linha ORM |
| devolviam `Credential` (ORM) | devolvem `CredentialMetadata` | **sem senha, notas nem TOTP dentro** |
| `delete_credential` apagava a linha | continua apagando **de verdade** | ver abaixo: a versão com `deleted_at` foi revertida |
| — | `purge_all_credentials(session)` | exclusão física, só para `vault destroy`, e sem exigir a chave |

⚠️ **`vault list` passou a pedir a senha mestra, e não tem como não pedir.** Era
o comando que não decifrava nada; hoje serviço, login e URL vivem dentro do blob.
É o preço direto de o banco não saber de quem é a credencial. O que a lista
continua **não** fazendo é exibir segredo: `CredentialMetadata` não carrega senha.

⚠️ **A unicidade virou responsabilidade só da aplicação.** A
`UniqueConstraint(service_name, login)` sumiu com as colunas: o banco não barra
mais nada, e o `IntegrityError` que virava `DuplicateCredentialError` **nunca mais
acontece**. `_colisao_case_insensitive` é a única barreira. Se alguém a remover
"porque o banco garante", duas credenciais iguais entram em silêncio e `vault get`
fica ambíguo para sempre.

⚠️ **Custo aceito, com a saída anotada:** buscar é O(n) decifrações de AES-GCM.
Irrelevante para um vault pessoal. Se um dia doer, a saída **não** é voltar a
gravar metadado em claro — é um segundo blob por linha, só com os campos
buscáveis, para a varredura não tocar na senha. O schema atual (uma coluna
`encrypted_data`, igual no Prisma) não comporta isso sem nova migration.

**Ganho de segurança que veio junto:** o teste central
`test_credencial_e_gravada_cifrada` afirmava
`assert bruto.service_name == "github"  # metadado é legível de propósito`. Hoje
ele prova o contrário — que **senha, serviço, login, URL e notas não aparecem em
texto puro no blob**, e que a tabela não tem mais coluna onde guardar metadado
legível. A troca de senha mestra também ficou mais segura por acidente: re-cifrar
virou decifrar e cifrar o mesmo blob, então **um campo novo no `CredentialPayload`
passa a ser re-cifrado sozinho** — a versão campo-a-campo anterior exigia lembrar
de acrescentá-lo lá, e esquecer significava perder o campo na troca de senha.

## Onde o trabalho está hoje — 22/09/2026

⛔ **Você NÃO consegue empurrar para `ReCroffi/secure-vault`.** Medido:
a conta `fedeandrade` tem `{"admin": false, "push": false, "pull": true}` nesse
repositório — ele é do Renan, e é **público**. O `git push` falha com
`403 Permission to ReCroffi/secure-vault.git denied to fedeandrade`. Não adianta
tentar de novo; é permissão, não rede.

**O caminho que funciona, e que está em uso:**

| | |
|---|---|
| Fork | `fedeandrade/secure-vault` (público, criado em 22/09/2026) |
| Remote | `fork` → `https://github.com/fedeandrade/secure-vault.git` |
| Branch | `feature/completar-fases-04-10`, rastreando `fork/` |
| PR | **[#19](https://github.com/ReCroffi/secure-vault/pull/19)** → `ReCroffi/secure-vault:main` |

⚠️ **O PR #19 está em CONFLITO e não pode ser mesclado como está.** Medido com
`git merge-tree --write-tree` (a seco, sem tocar na árvore): **20 arquivos**
conflitam, entre eles `crypto.py`, `master_password.py`, `models.py`,
`tui/app.py`, `conftest.py`, `migrations/env.py` e `pyproject.toml`.

**A causa não é briga de desenho, é sobreposição:** o commit `89f3da9` do Renan
("docs: comenta o codigo do projeto pra facilitar retomada futura") comentou
**o código inteiro**, tocando quase todo arquivo que esta branch reescreveu. São
`origin/main` 5 commits à frente do merge-base `3bdf278`, e esta branch 7.

**Ao resolver, o risco é dos dois lados:** deixar cair os comentários do Renan, ou
deixar cair as correções de segurança daqui (guard da migration, exclusão física,
segredo sem quebra de linha). Resolver arquivo a arquivo, com a suíte rodando a
cada um, e `.claude/gate.json` verde no fim.

## ⛔ A migração ZK NÃO converte vault existente — e agora recusa em vez de quebrar

Achado por revisão adversarial em 22/09/2026, e é **o pior defeito que a branch
tinha**. Vinha do commit `a22042c`, não da adaptação das camadas.

`edb62ca16834` adiciona `encrypted_data` como `NOT NULL` **sem `server_default`** e
derruba as colunas antigas **sem nenhum passo de conversão de dados** — não existe
migração de dados em lugar nenhum do repositório. Medido em SQLite, vault com 1
credencial, `alembic upgrade head`:

    IntegrityError: NOT NULL constraint failed: _alembic_tmp_credentials.encrypted_data

O rollback salvava os dados, mas o usuário ficava **preso na revisão antiga para
sempre**, sem mensagem que explicasse e sem caminho de export/import.

⚠️ **E o conserto óbvio era pior que o defeito.** Pôr `server_default=b""` faz a
migration passar e **destrói tudo em silêncio**: as colunas com os blobs reais são
derrubadas logo abaixo, toda linha fica com `encrypted_data = b""`, e o `_varrer`
do repositório passa a estourar `DecryptionError` na primeira linha — derrubando
`list`, `search`, `get`, `add` e `update` de uma vez. Vault bricado sem explicação.
**Se você está prestes a fazer isso, não faça.**

**O que foi feito:** aplicado o guard `MigrationBlocked` que já existia na revisão
anterior (`b1c7d3e59f20`) e não tinha sido usado aqui. `upgrade()` e `downgrade()`
recusam rodar com a tabela `credentials` não vazia, e a mensagem diz o que fazer
(exportar → `vault destroy` → migrar → recadastrar). Converter de verdade exigiria
**decifrar** cada credencial, e a migration não tem a chave: ela só existe depois
de o usuário digitar a senha mestra. Recusar é a única resposta honesta.

**Por que ninguém tinha visto:** os testes de migration só migravam vault VAZIO, e
o único que inseria credencial inseria **depois** do upgrade. O defeito morava
exatamente nesse vão. Coberto agora por 3 testes em `test_migration_sqlite.py`
(recusa no upgrade, recusa no downgrade, e vault vazio continuando a passar).

⚠️ **Consequência prática:** quem já tiver um vault com credenciais **não tem
caminho automático** para o formato Zero-Knowledge. Isso é limitação conhecida, não
descuido — e precisa de decisão antes de a branch ir para qualquer usuário: ou se
escreve um `vault export` / `vault import` que passe pela chave, ou se assume que
a migração é manual.

## ⛔ Os dois vaults não falam a mesma língua

Achado em 22/09/2026 e **não resolvido**. Apontar os dois para o mesmo banco hoje
não funciona, e a divergência é maior do que um detalhe de tipo:

| | Python (CLI/TUI) | Web (`web/`) |
|---|---|---|
| `id` | inteiro autoincrementado | `String @id @default(uuid())` |
| blob | `LargeBinary` | `String` |
| KDF | Argon2id | PBKDF2-600k |
| formato | blob versionado **com AAD** | `iv.ct` em base64, **sem AAD** |
| payload | `snake_case` (`service_name`) | `camelCase` (`serviceName`) |

**Interoperabilidade é impossível hoje**, e não por acaso de implementação: sem
AAD, o lado web não tem como detectar um blob trocado de campo ou de registro.
Decidir qual formato vence **antes** de qualquer sincronização.

## ⛔ Exclusão: por que voltou a ser física

`delete_credential` apaga a linha. A primeira versão deste refactor marcava
`deleted_at`, e a revisão adversarial mediu o que isso significava:

    apos `vault delete`:  list -> []   count -> 0
    a linha ainda existe no banco?     -> True
    a senha antiga ainda abre?         -> 'SENHA-VAZADA-QUE-EU-QUERO-SUMIR'
    apos `vault passwd`, abre com a CHAVE NOVA? -> a mesma senha

O motivo real de alguém apagar uma credencial é a senha ter vazado. A CLI dizia
"apagada" e a senha comprometida continuava no `.db`, em todo backup, e era
**re-cifrada com a chave nova a cada rotação** — imortal, e sem comando nenhum
que a listasse. Num gerenciador de senhas, "apaguei" tem de significar apagado.

**`deleted_at` continua no modelo e não é sobra:** é o tombstone de sincronização
do vault web. As leituras filtram `_vivas()` de propósito, para o caso de os dois
lados um dia dividirem o banco. E `change_master_password` re-cifra **sem** esse
filtro, de propósito — pular uma linha marcada a tornaria indecifrável para
sempre. Isso tem teste próprio desde 22/09
(`test_troca_re_cifra_ate_a_linha_marcada_como_apagada`), porque um refactor que
"conserte" aquele select deixaria a suíte verde destruindo dado.

⚠️ ~~"Todas as 10 fases do roadmap estão implementadas e testadas." (03/09/2026)~~
**Vencido em 22/09/2026.** Era verdade no dia em que foi escrito e deixou de ser
com os commits de 20/09. Não apagado: explica por que a suíte já esteve verde e o
que exatamente a derrubou.

✅ **O gate QA passou a cobrir este projeto em 22/09/2026.** Até então ele era
cego aqui: `~/.claude/hooks/gate-qa.mjs` só reconhecia raiz de projeto por
`package.json`, e este repositório é Python — **todo turno encerrado aqui saía por
"sem package.json → nada a verificar", sem medir nada.** Havia um segundo bloqueio
logo depois: a guarda de `node_modules` ausente, que num projeto Python nunca
existe. Os dois foram corrigidos e o gate está declarado em
[`.claude/gate.json`](.claude/gate.json) (`uv run ruff check . && uv run pytest`).
Provado no mesmo dia: o hook achou a raiz, rodou e devolveu **GATE VERMELHO em 13s**
com o `AttributeError` na saída. Enquanto a suíte estiver vermelha, nenhum turno
encerra aqui dizendo "pronto".

## Estado — 03/09/2026 (histórico)

**Todas as 10 fases do roadmap estão implementadas e testadas.** Branch de
trabalho: `feature/completar-fases-04-10`, a partir de `origin/develop`.

- 250 testes passando; `ruff check .` limpo.
- Passou por **revisão adversarial** (subagente `revisor-cetico`), que reprovou a
  primeira versão com 8 achados. Todos corrigidos, cada um com teste de regressão
  em `tests/integration/test_regressao_revisao.py`. Os graves eram:
  perda total do vault por `alembic downgrade`; `vault delete` sem autenticação;
  `vault passwd` que anunciava troca sem trocar quando `VAULT_MASTER_PASSWORD`
  estava definida; e a migration apagando credencial duplicada por `MAX(id)`,
  que é a de inserção mais recente e não a atualizada por último.
- Verificado contra **PostgreSQL 16.10 real** (migrations, `CHECK`, `timestamptz`,
  ciclo upgrade→downgrade→upgrade, retrocompatibilidade de vault antigo) e contra
  SQLite (suíte padrão, sem dependência externa).
- Prova de ponta a ponta rodada com a CLI instalada: vault criado, credenciais
  gravadas cifradas, senha errada recusada, senha certa recupera, troca de senha
  mestra re-cifrou 2 credenciais e a senha original voltou intacta.

⚠️ ~~**Nada foi enviado ao GitHub.** O trabalho está apenas nesta máquina, por
instrução explícita do Felipe (03/09/2026).~~ **Vencido em 22/09/2026:** o Felipe
autorizou publicar, e a branch está no GitHub — ver "Onde o trabalho está hoje".
~~`origin/develop` continua na Fase 4.~~
⚠️ **Vencido — medido em 22/09/2026 com `git fetch --all --prune`: `origin/develop`
foi APAGADO no remoto** (junto com `origin/feature/05-crud-credenciais`). Sobrou
`origin/main`, que avançou `abfbc6a..89f3da9` por commits do Renan em 09/09. A
branch local `feature/completar-fases-04-10` não tem upstream: ela está diverging
de um ponto de partida que não existe mais. Antes de pensar em PR, decidir contra
qual base — `origin/main` é a única viva.

## Decisões que não podem ser revertidas por engano

| Decisão | Motivo | Consequência de mudar |
|---|---|---|
| Parâmetros do KDF gravados em `vault_config`, não no código | Subir o custo do Argon2 no código tornaria todo vault existente ilegível, sem erro | Se voltarem para o código, o próximo aumento de custo destrói dados |
| `_ENCRYPTION_KEY_INFO = b"secure-vault:encryption-key:v1"` | Separação de domínio entre hash de autenticação e chave de cifra | Mudar o valor torna **todos** os vaults ilegíveis |
| `AAD_PASSWORD` / `AAD_NOTES` / `AAD_TOTP` distintos | Impede blob copiado entre colunas de abrir | Mudar qualquer um invalida os dados daquele campo |
| Nonce de `secrets.token_bytes(12)` a cada gravação | Reuso de nonce em AES-GCM permite recuperar a chave de autenticação | É a falha mais grave possível neste modo |
| Blob começa com byte de versão (`BLOB_VERSION = 1`) | Permite trocar de cifra sem adivinhação | Sem ele, migração de formato vira tentativa e erro sobre dados ilegíveis |
| Sentinela `key_check` conferida no `unlock` | Detecta chave errada **antes** de tocar dado real | Sem ela, parâmetros divergentes produzem "falha ao decifrar" credencial a credencial |
| `normalize_password` faz NFC antes de codificar | "café" NFC e NFD geram chaves diferentes | Senha com acento pararia de abrir ao trocar de SO |
| Nada instanciado no nível do módulo (settings, engine, session) | Era o defeito que impedia a suíte de coletar e a CLI de rodar sem `.env` | Volta a quebrar `import vault.*` em máquina limpa |
| Funções de domínio recebem `Session`, não a criam | Uma transação por operação lógica; testes determinísticos | `login()` antigo abria duas sessões e lia o vault duas vezes |
| Sentinela `UNSET` no `update_credential` | Distingue "não mexer" de "apagar" | Sem ela, omitir um campo o apagaria |
| Suíte roda em SQLite; Postgres é opcional via `TEST_DATABASE_URL` | Suíte que só roda na máquina certa é suíte que ninguém roda | Exigir Postgres derruba a coleta em máquina limpa (foi o que acontecia) |
| Repositório usa `session.begin_nested()` (SAVEPOINT), nunca `session.rollback()` | Rollback numa função de repositório aborta a transação **inteira** do chamador e devolve a conexão suja ao pool | Volta o `PendingRollbackError` e o `deadlock detected` intermitente no Postgres |
| Atribuições do `update_credential` ficam **dentro** do savepoint | Só assim o SQLAlchemy restaura o snapshot do objeto ao reverter | Objeto em memória fica divergente do banco e o autoflush re-emite o UPDATE inválido |
| O `downgrade` da migration se recusa a rodar com vault existente | Ele derruba as colunas `kdf_*`; o `upgrade` seguinte as recria com os PADRÕES, e o vault fica ilegível com login aparentemente bem-sucedido | Perda total e silenciosa do vault |
| A migration **aborta** em vez de apagar dado ambíguo | `MAX(id)` é a inserção mais recente, não a atualizada por último | Apaga a senha em uso de quem salvou uma duplicata por engano |
| `verify_key_check` recusa sentinela `None` | Devolver `True` fazia `unlock` aceitar qualquer chave quando a coluna sumia | Reabre o buraco do downgrade |
| O login **não** reescreve o hash (`check_needs_rehash` desligado) | O PHC é a última cópia dos parâmetros originais se as colunas `kdf_*` se perderem | Destrói a única evidência que permitiria recuperar o vault |
| `delete`, `destroy` e `passwd` exigem senha mestra | Sem isso, um terminal destravado apaga o vault com um laço de shell | Achado da revisão adversarial |
| `vault passwd` lê a senha nova de `VAULT_NEW_MASTER_PASSWORD` | Com a mesma variável nas duas leituras, o comando anunciava troca sem trocar | Rotação após vazamento que não rotaciona nada |
| Todo dado do usuário sai por `rich.text.Text`, nunca em f-string com markup | `console.print` come `[...]`: senha com colchete era exibida a menos | Usuário copia da tela uma senha que não existe |
| `hmac.compare_digest` sempre com **bytes** | A sobrecarga de `str` só aceita ASCII e levanta `TypeError` | Senha com acento faz a limpeza do clipboard falhar dentro da thread, em silêncio |
| Testes em Postgres usam schema por PID (`vault_test_<pid>`) | Duas suítes no mesmo banco disputam DDL | `deadlock detected` e `pg_type_typname_nsp_index` intermitentes |

## Armadilhas medidas neste projeto

- **`importlib.reload` em teste envenena o processo.** Recarregar
  `vault.config.settings` cria um segundo `lru_cache`; `reset_settings_cache()`
  limpa só um deles e os testes seguintes leem configuração vencida. Dois testes
  falharam por causa de um terceiro. Para estado de import limpo, use subprocesso
  (`tests/unit/test_settings.py`).
- **`%` na senha do banco quebra o Alembic.** O `alembic.ini` é lido por
  `configparser` com interpolação; `%` na URL estoura `InterpolationSyntaxError`.
  Escapado em `vault.db.migrate.escape_url_for_alembic`.
- **`bytes` literal não aceita caractere acentuado** (`b"memória"` é
  `SyntaxError`). Custou uma rodada de coleta da suíte.
- **`vault db check` lê `DATABASE_URL`, não a session factory.** Configurar só a
  factory nos testes não basta para os comandos de diagnóstico.
- **O Git Bash do Windows exibe `?` no lugar de acentos** na saída da CLI. É o
  console, não o dado — o Postgres guarda e devolve UTF-8 correto. Conferir com
  `PYTHONIOENCODING=utf-8` ou consultando o banco direto antes de chamar de bug.

## Ambiente de desenvolvimento nesta máquina

- `uv` **não estava instalado**; foi instalado em 03/09/2026 via
  `py -3.12 -m pip install uv` (fica em
  `C:\Users\felip\AppData\Local\Programs\Python\Python312\Scripts\uv.exe`).
- **Não há Docker nesta máquina.** O Postgres de teste é um binário portátil do
  EnterpriseDB rodando em `localhost:55432`, com datadir no scratchpad da sessão
  — **volátil, não sobrevive a reboot nem à limpeza do scratchpad**. Para um banco
  duradouro, mover binários e datadir para um caminho estável.
- O venv do projeto fica em `.venv`; os executáveis instalados são
  `.venv/Scripts/vault.exe` e `.venv/Scripts/secure-vault.exe`.

## Pendências

- [ ] Preencher os dois TODOs pessoais do README (Motivação; LinkedIn/contato).
      São as únicas seções que só o Renan pode escrever.
- [ ] Decidir com o Felipe/Renan se esta branch vira PR para `develop`.
      **Nada foi pushado.**
