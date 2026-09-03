# MEMORIA — Secure Vault

Estado autoritativo do projeto. Ao entrar aqui, leia este arquivo antes do
código. Se algo divergir do sistema vivo, o sistema vence e **este arquivo é
corrigido no mesmo trabalho**.

## Estado — 03/09/2026

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

**Nada foi enviado ao GitHub.** O trabalho está apenas nesta máquina, por
instrução explícita do Felipe (03/09/2026). `origin/develop` continua na Fase 4.

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
