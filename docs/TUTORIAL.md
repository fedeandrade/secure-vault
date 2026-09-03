# Secure Vault — Tutorial Técnico Completo

Documentação de arquitetura e das decisões de engenharia do projeto, organizada
pelo roadmap das 10 fases.

Cada fase responde a quatro perguntas na mesma ordem:

1. **O que a fase entrega**
2. **Como foi implementado** (com o código)
3. **Que outras opções existiam**
4. **Por que esta é a melhor para este projeto**

---

## Sumário

| Fase | Entrega | Decisão central |
|---|---|---|
| [0](#fase-0--fundação-do-projeto) | Estrutura, dependências, empacotamento | `uv` + layout `src/` |
| [1](#fase-1--banco-de-dados-e-configuração) | Conexão Postgres, configuração tipada | Configuração preguiçosa, sem estado global |
| [2](#fase-2--modelagem-e-migrations) | Schema, Alembic, constraints | Integridade no banco, não só no código |
| [3](#fase-3--criação-do-vault-e-senha-mestra) | Senha mestra, salt, hash | Argon2id, parâmetros persistidos |
| [4](#fase-4--autenticação-e-derivação-de-chave) | Chave em memória | HKDF para separação de domínio |
| [5](#fase-5--crud-de-credenciais) | Guardar, ler, alterar, apagar | AES-256-GCM com AAD por campo |
| [6](#fase-6--gerador-de-senhas) | Senhas fortes configuráveis | CSPRNG + rejection sampling |
| [7](#fase-7--força-de-senha) | Avaliação realista | zxcvbn com contexto |
| [8](#fase-8--busca-e-filtro) | Localizar credenciais | Metadados legíveis, `LIKE` escapado |
| [9](#fase-9--interface-tui) | Interface visual no terminal | Textual, segredo sob demanda |
| [10](#fase-10--sessão-clipboard-e-2fa) | Timeout, auto-clear, TOTP | Relógio monotônico, RFC 6238 |

Seções transversais: [Arquitetura](#arquitetura-em-camadas) · [Estratégia de
testes](#estratégia-de-testes) · [Manutenção](#regras-de-manutenção)

---

## Fase 0 — Fundação do projeto

### O que entrega
Estrutura de diretórios, gerenciamento de dependências, empacotamento e os dois
comandos instaláveis (`vault` e `secure-vault`).

### Como foi implementado

```toml
[project]
name = "secure-vault"
version = "1.0.0"
requires-python = ">=3.12"

[project.scripts]
vault = "vault.cli.main:main"
secure-vault = "secure_vault:main"

[build-system]
requires = ["uv_build>=0.12.7,<0.13.0"]
build-backend = "uv_build"
```

Layout `src/`: o código fica em `src/vault/`, não em `vault/` na raiz.

### Alternativas

| Opção | Prós | Contras |
|---|---|---|
| **`uv`** (escolhida) | Resolução, lockfile e venv numa ferramenta; ~10× mais rápido que pip | Ferramenta recente |
| `pip` + `requirements.txt` | Universal | Sem lockfile real; `pip freeze` mistura dependência direta e transitiva |
| `poetry` | Maduro, lockfile bom | Mais lento; historicamente divergia do padrão `pyproject` |
| `pdm` | Padrões modernos | Comunidade menor |

E sobre o layout:

| Opção | Efeito |
|---|---|
| **`src/`** (escolhida) | O pacote **não** está no `sys.path` por acidente. Se o `import vault` funciona, é porque a instalação funciona |
| Pacote na raiz | Testes importam do diretório de trabalho e passam mesmo com empacotamento quebrado |

### Por que esta

O layout `src/` transforma um erro de empacotamento em falha imediata no lugar de
uma surpresa no dia da distribuição. E o `uv.lock` garante que a máquina do
desenvolvedor, a do revisor e o CI resolvem **exatamente** as mesmas versões —
inclusive das transitivas, que é onde uma atualização silenciosa de biblioteca de
criptografia doeria mais.

---

## Fase 1 — Banco de dados e configuração

### O que entrega
Conexão com PostgreSQL e configuração lida de variáveis de ambiente / `.env`,
tipada e validada.

### Como foi implementado

Configuração com `pydantic-settings`, validada e **construída sob demanda**:

```python
# src/vault/config/settings.py
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str | None = None
    kdf_time_cost: int = Field(default=3, ge=1)
    kdf_memory_cost: int = Field(default=65536, ge=8)
    session_timeout_seconds: int = Field(default=300, ge=10)

    def require_database_url(self) -> str:
        if not self.database_url:
            raise ConfigurationError(
                "DATABASE_URL não está definida.\n"
                "Copie .env.example para .env e preencha DATABASE_URL..."
            )
        return self.database_url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
```

Três propriedades importam aqui:

**A configuração não é construída no import.** É uma função com cache. O custo é
o mesmo — lê uma vez por processo — mas a leitura acontece no primeiro uso.

**`database_url` é opcional no modelo e obrigatória no uso.** `vault generate` e
`vault strength` não tocam o banco e funcionam numa máquina sem `.env`. Quem
precisa do banco chama `require_database_url()` e recebe uma instrução.

**A validação acontece no arranque.** `KDF_TIME_COST=0` falha na leitura da
configuração, não lá na frente dentro da biblioteca de criptografia.

O mesmo princípio vale para o engine e a fábrica de sessões:

```python
# src/vault/db/engine.py
_ENGINES: dict[tuple[str, bool], Engine] = {}

def get_engine(url: str | None = None, *, echo: bool = False) -> Engine:
    resolved = url or get_settings().require_database_url()
    ...
```

### Alternativas

| Opção | Consequência |
|---|---|
| **Função com cache** (escolhida) | Import puro; testes trocam a configuração; a CLI roda sem banco |
| `settings = Settings()` no módulo | Qualquer `import vault.*` exige `.env`. Quebra `--help` e a coleta de testes |
| `os.environ` direto | Sem tipos, sem validação, sem defaults; erro só aparece no uso |
| `configparser` / TOML próprio | Reimplementa o que o pydantic já faz, sem validação |

E sobre o registro de engines:

| Opção | Consequência |
|---|---|
| **Dicionário explícito** (escolhida) | Dá para iterar e chamar `dispose()` ao resetar |
| `@lru_cache` no engine | Memoiza, mas `cache_clear()` descarta as referências **sem fechar as conexões** — elas vazam |

### Por que esta

Trabalho no nível do módulo acontece no import, e o import acontece antes de você
ter chance de configurar qualquer coisa. Em teste, isso significa que a suíte não
consegue apontar para outro banco; em produção, que a aplicação não sobe sem
arquivo de configuração nem para mostrar a ajuda.

O detalhe do `lru_cache` versus dicionário parece menor mas não é: um engine
descartado sem `dispose()` deixa conexões abertas no Postgres, e a próxima
operação de DDL trava esperando lock.

---

## Fase 2 — Modelagem e migrations

### O que entrega
Schema em SQLAlchemy 2 com tipagem `Mapped[...]`, migrations versionadas em
Alembic, e as travas de integridade no banco.

### Como foi implementado

```python
# src/vault/db/models.py
class VaultConfig(Base):
    __tablename__ = "vault_config"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_vault_config_singleton"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=False)
    master_password_hash: Mapped[str] = mapped_column(String(255))
    salt: Mapped[bytes] = mapped_column(LargeBinary)
    kdf_algorithm: Mapped[str] = mapped_column(String(32), server_default="argon2id")
    kdf_time_cost: Mapped[int] = mapped_column(server_default="3")
    ...
    key_check: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)


class Credential(Base):
    __tablename__ = "credentials"
    __table_args__ = (
        UniqueConstraint("service_name", "login", name="uq_credentials_service_login"),
        Index("ix_credentials_service_name", "service_name"),
    )
```

Duas regras estruturam o schema:

**Toda coluna que guarda segredo é `LargeBinary`.** Não existe `VARCHAR` com
senha. O tipo do banco já diz que ali dentro há blob cifrado.

**Integridade é imposta pelo banco.** `CHECK (id = 1)` garante um único vault;
`UNIQUE (service_name, login)` impede credenciais duplicadas. Validação em Python
protege o caminho que passa pelo Python — um `INSERT` manual, um restore parcial
ou duas execuções concorrentes passam por fora.

### A migration e a política de dados

A migration `b1c7d3e59f20` é **puramente aditiva**: nenhuma coluna some ou muda
de nome, e toda coluna obrigatória nasce com `server_default` igual ao valor que
o código anterior usava fixo. Um vault criado na Fase 3 herda exatamente os
parâmetros com que foi criado.

Onde ela poderia destruir dados, ela **para**:

```python
def _abortar_se_houver(consulta, *, minimo, titulo, instrucao) -> None:
    """Interrompe a migration se `consulta` retornar ao menos `minimo` linhas.

    Uma migration que falha com instruções custa cinco minutos;
    uma que apaga a senha errada custa a conta.
    """
    linhas = op.get_bind().execute(sa.text(consulta)).fetchall()
    if len(linhas) < minimo:
        return
    detalhe = "\n".join(f"  - {tuple(linha)}" for linha in linhas)
    raise MigrationBlocked(f"\n\nMIGRATION INTERROMPIDA: {titulo}.\n\n{detalhe}\n\n{instrucao}")
```

Três situações acionam a trava: duas linhas em `vault_config` (só o usuário sabe
qual `salt` cifrou os dados); credenciais duplicadas (só ele sabe qual senha vale);
e o `downgrade` com um vault existente — explicado na Fase 3.

### Alternativas

| Opção | Prós | Contras |
|---|---|---|
| **SQLAlchemy 2 + Alembic** (escolhida) | Tipagem `Mapped[...]` verificável; migrations versionadas e reversíveis | Curva de aprendizado |
| SQL puro + scripts numerados | Controle total | Sem detecção de divergência; cada projeto reinventa o versionamento |
| Django ORM | Migrations excelentes | Traz o framework inteiro para uma CLI |
| SQLModel | API enxuta | Camada fina sobre SQLAlchemy; menos controle no que importa aqui |

E sobre a política da migration diante de dados que violam a nova constraint:

| Opção | Consequência |
|---|---|
| **Abortar com instruções** (escolhida) | O usuário perde cinco minutos e decide |
| `DELETE` heurístico (`MAX(id)`) | Apaga segredo por palpite. `MAX(id)` é a inserção mais recente, não a atualizada por último — apagaria justamente a senha em uso de quem salvou uma duplicata por engano |
| Renomear a tabela e recriar | Duplica o dado cifrado no disco; se falhar no meio, deixa dois estados |

### Por que esta

Em qualquer aplicação, apagar duplicata na migration é aceitável. Num gerenciador
de senhas, cada linha é um segredo irrecuperável: não existe "recriar depois". O
custo assimétrico entre errar para o lado cauteloso e errar para o lado
destrutivo decide sozinho.

---

## Fase 3 — Criação do vault e senha mestra

### O que entrega
Criação do vault com senha mestra: hash para autenticação, salt e parâmetros de
derivação persistidos.

### Como foi implementado

```python
def create_vault(session, password, *, params=None) -> VaultConfig:
    if len(password) < MIN_MASTER_PASSWORD_LENGTH:
        raise AuthenticationError(...)
    if vault_exists(session):
        raise VaultAlreadyExistsError(...)

    params = params or KdfParams.from_settings()
    salt = generate_salt()
    key = derive_encryption_key(password, salt, params)

    config = VaultConfig(
        id=VAULT_CONFIG_ID,
        master_password_hash=hash_master_password(password, params),
        salt=salt,
        kdf_algorithm=params.algorithm,
        kdf_time_cost=params.time_cost,
        kdf_memory_cost=params.memory_cost,
        kdf_parallelism=params.parallelism,
        kdf_hash_len=params.hash_len,
        key_check=crypto.build_key_check(key),
    )
```

### Decisão 1 — Argon2id para o hash

Uma função de hash rápida é péssima para senhas: uma GPU testa bilhões de
SHA-256 por segundo. Argon2id é uma **função de derivação de chave** — os
parâmetros controlam o custo de cada tentativa.

| Algoritmo | Resistente a GPU | Resistente a ASIC | Status |
|---|---|---|---|
| **Argon2id** (escolhido) | Sim (custo de memória) | Sim | Vencedor do Password Hashing Competition; RFC 9106 |
| scrypt | Sim | Parcial | Bom, anterior ao Argon2 |
| bcrypt | Parcial | Não | Maduro, mas limita a senha a 72 bytes |
| PBKDF2 | Não | Não | Só custo de CPU; aceitável apenas por exigência de conformidade |
| SHA-256 / MD5 | Não | Não | Inadequado para senhas |

Parâmetros: `time_cost=3`, `memory_cost=65536` (64 MiB), `parallelism=4` — o piso
recomendado pelo RFC 9106 para uso interativo. Na prática, ~200 ms por tentativa:
imperceptível para o usuário, e a diferença entre "quebrável numa tarde" e
"inviável" para quem tem o banco.

### Decisão 2 — Os parâmetros ficam no banco, não no código

Esta decisão evita a destruição silenciosa de dados. Considere a alternativa:

```python
# Como NÃO fazer
def derive_encryption_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(password.encode(), salt=salt,
                           time_cost=3, memory_cost=65536, parallelism=4,  # fixos
                           hash_len=32, type=Type.ID)
```

Daqui a um ano, com hardware melhor, o `time_cost` sobe para 5. É a decisão
correta de segurança. Mas a chave derivada muda, e **todo vault existente vira
ilegível** — sem erro e sem aviso. Pior: o login continua funcionando, porque o
hash Argon2 no formato PHC carrega os próprios parâmetros embutidos:

```
$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA
              └──────────────┘
              os parâmetros viajam com o hash
```

Só as credenciais falhariam, uma a uma.

| Opção | Consequência de aumentar o custo depois |
|---|---|
| **Parâmetros no `vault_config`** (escolhida) | Vault antigo abre com os parâmetros dele; vault novo nasce com os novos |
| Parâmetros no código | Todo vault existente fica ilegível, em silêncio |
| Parâmetros no `.env` | Mesmo problema: a configuração muda e o vault não sabe |
| Prefixo de versão nos dados | Funciona, mas exige tabela de versões e não resolve a granularidade por vault |

### Decisão 3 — A sentinela `key_check`

Persistir os parâmetros resolve a mudança legítima. Falta o caso em que eles são
**perdidos** — alguém edita o banco, ou um `downgrade` do Alembic derruba as
colunas. Para isso, o vault guarda um texto conhecido cifrado com a chave certa:

```python
KEY_CHECK_PLAINTEXT = "secure-vault-key-check"

def build_key_check(key: bytes) -> bytes:
    return encrypt(key, KEY_CHECK_PLAINTEXT, aad=AAD_KEY_CHECK)
```

No login, isso é conferido **antes** de tocar em qualquer dado real. O efeito é
transformar "cada credencial falha misteriosamente" em uma mensagem que diz
exatamente o que aconteceu e onde procurar os parâmetros originais.

### Decisão 4 — O login não reescreve o hash

O padrão recomendado na maioria das aplicações é atualizar o hash quando os
custos sobem, aproveitando que a senha em claro está disponível:

```python
if hasher.check_needs_rehash(config.master_password_hash):
    config.master_password_hash = hasher.hash(password)   # NÃO fazemos isto
```

Aqui isso é evitado por um motivo específico: a string PHC é a **última cópia
sobrevivente** dos parâmetros originais caso as colunas `kdf_*` sejam perdidas.
Um rehash automático nesse cenário sobrescreveria `m=16384,t=5,p=2` pelos padrões
e destruiria a evidência que ainda permitiria recuperar o vault com um `UPDATE`.

Rotacionar o custo do KDF é trabalho de `vault passwd`, que é explícito e
re-cifra o conteúdo — não efeito colateral de um login.

### Decisão 5 — O `downgrade` da migration se recusa a rodar

Consequência direta das decisões acima. O `downgrade` derruba `kdf_*` e
`key_check`; o `upgrade` seguinte as recria com os **valores padrão**. Medido num
Postgres real, num vault com `t=5 m=16384 p=2`:

```
downgrade + upgrade
  kdf gravado agora : 3 / 65536 / 4      (não são os do usuário)
  key_check         : None
  unlock            : SUCESSO             (com a chave errada)
  reveal            : DecryptionError
```

Por isso, com qualquer vault no banco, o downgrade para. Ele continua disponível
para reverter em banco vazio, que é o uso legítimo (desenvolvimento, CI).

---

## Fase 4 — Autenticação e derivação de chave

### O que entrega
Destravamento do vault: valida a senha mestra e devolve a chave de criptografia
derivada em memória.

### Como foi implementado

```python
def unlock(session: Session, password: str, *, totp_code: str | None = None) -> bytes:
    config = get_vault_config(session)

    if not _verify_against(config, password):
        raise AuthenticationError("Senha mestra incorreta.")

    key = derive_encryption_key(password, config.salt, params_of(config))

    if config.key_check is None:
        _adotar_sentinela(session, config, key)
    elif not crypto.verify_key_check(key, config.key_check):
        raise DecryptionError(...)

    if config.totp_secret_encrypted is not None:
        _require_valid_totp(config, key, totp_code)

    return key
```

### Decisão 1 — Separação de domínio por HKDF

A senha mestra alimenta dois usos que não podem coincidir: o hash de
autenticação (que vai para o banco) e a chave de criptografia (que nunca vai). Se
fossem o mesmo valor, guardar o hash seria guardar a chave.

Eles já usam salts diferentes — o `PasswordHasher` gera o seu, o KDF usa o do
`vault_config`. Mas "não colidem por causa do salt" é uma garantia frágil, que
depende de ninguém nunca reaproveitar um salt no outro caminho. A separação é
tornada explícita:

```python
_ENCRYPTION_KEY_INFO = b"secure-vault:encryption-key:v1"

def derive_encryption_key(password: str, salt: bytes, params: KdfParams) -> bytes:
    raw = hash_secret_raw(
        secret=normalize_password(password), salt=salt,
        time_cost=params.time_cost, memory_cost=params.memory_cost,
        parallelism=params.parallelism, hash_len=params.hash_len, type=Type.ID,
    )
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=_ENCRYPTION_KEY_INFO,
    ).derive(raw)
```

| Opção | Consequência |
|---|---|
| **Argon2id → HKDF com rótulo** (escolhida) | Separação explícita; sobrevive a um erro futuro que reaproveite o salt; permite derivar outras subchaves com rótulos distintos |
| Confiar só em salts diferentes | Funciona hoje; quebra silenciosamente no dia em que alguém unificar os salts |
| Dois Argon2 completos | Dobra o custo (~400 ms por login) sem ganho de segurança |
| Prefixo na senha (`"enc:" + senha`) | "Crypto artesanal": sem prova, e vulnerável a colisão de prefixo |

O HKDF custa microssegundos — todo o trabalho pesado já foi feito pelo Argon2.

### Decisão 2 — Normalização Unicode NFC

`"café"` pode ser duas sequências de bytes diferentes:

| Forma | Pontos de código | Bytes UTF-8 |
|---|---|---|
| NFC | `c a f é` (U+00E9) | `63 61 66 C3 A9` |
| NFD | `c a f e ́` (U+0065 U+0301) | `63 61 66 65 CC 81` |

São idênticas na tela e diferentes em bytes — logo, **chaves diferentes**. Um
teclado brasileiro no Windows produz NFC; um Mac, em certas configurações,
produz NFD. A mesma senha funcionaria numa máquina e não na outra, e o usuário
juraria ter digitado certo.

```python
def normalize_password(password: str) -> bytes:
    return unicodedata.normalize("NFC", password).encode("utf-8")
```

| Opção | Consequência |
|---|---|
| **NFC** (escolhida) | Forma composta, padrão na web e na maioria dos sistemas; a mais compacta |
| NFD | Funcionaria igual, mas é menos comum como forma canônica de armazenamento |
| Não normalizar | A senha para de abrir ao trocar de sistema operacional |
| Rejeitar não-ASCII | Enfraquece a senha e é hostil a quem escreve em português |

### Decisão 3 — Uma transação por operação lógica

```python
# Como NÃO fazer
def login(password: str) -> bytes:
    if verify_master_password(password):   # abre uma sessão, lê VaultConfig
        with Session() as session:          # abre OUTRA sessão, lê de novo
            vault_config = session.execute(select(VaultConfig)).scalar_one()
```

Duas conexões e duas leituras para uma operação só, com uma janela entre elas em
que o vault pode mudar. A versão atual recebe a `Session` pronta e faz tudo numa
transação.

| Opção | Consequência |
|---|---|
| **Função recebe `Session`** (escolhida) | Uma transação por operação; a borda decide o limite; testes fazem rollback e não deixam resíduo |
| Cada função abre a sua | Leituras inconsistentes; impossível compor duas operações atomicamente |
| Sessão global (`scoped_session`) | Estado escondido; problemas em thread (a TUI usa worker threads) |

---

## Fase 5 — CRUD de credenciais

### O que entrega
Guardar, ler, alterar e apagar credenciais — sempre cifradas.

### Como foi implementado

O formato do blob gravado no banco:

```
[1 byte versão][12 bytes nonce][ciphertext + tag de 16 bytes]
```

Uma senha de 20 caracteres ocupa 49 bytes: `1 + 12 + 20 + 16`.

```python
def encrypt(key: bytes, plaintext: str, *, aad: bytes) -> bytes:
    _validate_key(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = AESGCM(bytes(key)).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return bytes([BLOB_VERSION]) + nonce + ciphertext
```

### Decisão 1 — AES-256-GCM

| Modo | Autenticado | Associated data | Chave usada | Observação |
|---|---|---|---|---|
| **AES-256-GCM** (escolhido) | Sim (AEAD) | Sim | 256 bits | Padrão NIST; aceleração por hardware (AES-NI) |
| Fernet | Sim (AES-128-CBC + HMAC) | Não | 128 dos nossos 256 bits | Simples, mas desperdiça chave e não amarra o contexto |
| ChaCha20-Poly1305 | Sim (AEAD) | Sim | 256 bits | Excelente; melhor sem AES-NI. Empate técnico |
| AES-CBC sem MAC | **Não** | Não | — | Vulnerável a padding oracle. Inaceitável |

Fernet era a opção natural — a tabela original do projeto a mencionava — e foi
descartada por dois motivos concretos: usaria só metade da chave de 256 bits, e
não tem *associated data*, que é o que sustenta a decisão seguinte.

### Decisão 2 — Associated data por campo

```python
AAD_PASSWORD     = b"secure-vault:credential.password:v1"
AAD_NOTES        = b"secure-vault:credential.notes:v1"
AAD_TOTP         = b"secure-vault:credential.totp:v1"
AAD_MASTER_TOTP  = b"secure-vault:vault.totp:v1"
AAD_KEY_CHECK    = b"secure-vault:vault.key_check:v1"
```

O AAD entra no cálculo da tag de autenticação sem ser cifrado. Consequência
prática: um `UPDATE` que copie o blob da coluna `encrypted_password` para
`encrypted_notes` produz um registro que **não abre**. Sem AAD, abriria
normalmente e a nota passaria a exibir a senha.

### Decisão 3 — Nonce sorteado a cada gravação

Reusar nonce em GCM não vaza apenas um texto: permite recuperar a chave de
autenticação e forjar mensagens. É a falha mais grave possível neste modo.

| Opção | Segurança |
|---|---|
| **`secrets.token_bytes(12)` por operação** (escolhida) | Colisão desprezível em 2⁹⁶; sem estado a manter |
| Contador persistido | Seguro em teoria; um restore de backup reinicia o contador e repete nonces |
| Nonce derivado do `id` | **Quebrado**: atualizar a senha reusaria o nonce com a mesma chave |
| Nonce fixo | Catastrófico |

Isso é protegido por teste — cifrar o mesmo texto 500 vezes tem de produzir 500
nonces distintos.

### Decisão 4 — O byte de versão

Permite trocar de algoritmo no futuro sem adivinhação: um blob antigo se
identifica sozinho e uma versão desconhecida dá mensagem específica. Sem ele,
migrar de cifra vira tentativa e erro sobre dados que ninguém consegue ler.

### Decisão 5 — SAVEPOINT, não `session.rollback()`

Ao traduzir `IntegrityError` em erro de domínio, um repositório **não pode**
abortar a transação inteira do chamador:

```python
# Como NÃO fazer
except IntegrityError as exc:
    session.rollback()      # desfaz trabalho que não é desta função
    raise DuplicateCredentialError(...)
```

O rollback desfaz tudo o que estava na transação, e o `session_scope` externo
encontra a sessão em estado inválido ao comitar. A ferramenta certa é o savepoint:

```python
try:
    with session.begin_nested():          # SAVEPOINT
        session.add(credential)
        session.flush()
except IntegrityError as exc:
    raise DuplicateCredentialError(...) from exc
```

**As atribuições ficam dentro do savepoint**, e não antes dele. Ao revertê-lo, o
SQLAlchemy restaura o snapshot dos objetos — o que só funciona para mudanças
feitas dentro do bloco. Alterar o objeto fora e só depois abrir o savepoint deixa
o Python com o valor novo e o banco com o antigo.

### Decisão 6 — O sentinela `UNSET`

```python
UNSET: object = object()

def update_credential(session, key, credential, *, notes: str | None | object = UNSET, ...):
```

Sem ele, `update(notes=None)` é ambíguo: manter as notas ou apagá-las? Com ele,
**omitir preserva** e **`None` apaga**. É o bug clássico de toda função de update
com campos opcionais.

### Decisão 7 — Listar não decifra

`list_credentials` devolve metadados; `reveal` é a operação explícita que abre um
segredo. Por isso `vault list` não pede a senha mestra — não há nada para
decifrar — e nenhuma senha passa perto da tela de lista.

---

## Fase 6 — Gerador de senhas

### O que entrega
Senhas fortes com política configurável: comprimento, classes de caracteres,
exclusão de caracteres ambíguos.

### Decisão 1 — `secrets`, nunca `random`

O `random` do Python é um Mersenne Twister: observando 624 saídas consecutivas
dá para reconstruir o estado interno e prever todas as próximas. `secrets` puxa
do CSPRNG do sistema operacional.

| Fonte | Previsível | Uso correto |
|---|---|---|
| **`secrets`** (escolhida) | Não | Qualquer coisa relacionada a segurança |
| `random` | Sim | Simulação, embaralhar uma lista de exibição |
| `os.urandom` | Não | Equivalente; `secrets` é a API de alto nível sobre ela |
| `uuid4()` como senha | Não, mas | Só hexadecimal: 122 bits em 36 caracteres, contra 130 em 20 com o alfabeto completo |

### Decisão 2 — Rejection sampling em vez de embaralhamento

Para garantir "ao menos um de cada classe", a implementação comum é:

```python
# Enviesado
senha = [choice(minusculas), choice(maiusculas), choice(digitos), choice(simbolos)]
senha += [choice(alfabeto) for _ in range(tamanho - 4)]
shuffle(senha)
```

O problema não é a aleatoriedade do embaralhamento: é que a **contagem** de cada
classe fica condicionada, e o espaço de senhas possíveis encolhe. A entropia real
fica abaixo da anunciada, e o atacante que conhece a política explora isso.

```python
# Uniforme condicionado aos requisitos
for _ in range(_MAX_ATTEMPTS):
    candidata = "".join(secrets.choice(alfabeto) for _ in range(policy.length))
    if _satisfies(candidata, policy):
        return candidata
```

| Opção | Distribuição | Custo |
|---|---|---|
| **Rejection sampling** (escolhida) | Uniforme condicionada aos requisitos | ~1 tentativa; para 20 caracteres a rejeição é rara |
| Um de cada + embaralhar | Enviesada | 1 tentativa |
| Sem garantia de classes | Uniforme | 1 tentativa, mas falha em sites que exigem símbolo |

O laço tem teto (`_MAX_ATTEMPTS`) para transformar uma política impossível num
erro claro em vez de travamento.

### Decisão 3 — Entropia calculada e exibida

```python
def entropy_bits(alphabet_size: int, length: int) -> float:
    return length * math.log2(alphabet_size)
```

Com o alfabeto padrão (~85 caracteres) e 20 posições: ~128 bits. É a entropia de
**geração** — o que um atacante enfrenta conhecendo exatamente a política — e é
diferente da nota do zxcvbn, que estima o custo de adivinhar uma senha escolhida
por um humano. As duas medidas respondem perguntas diferentes e ambas aparecem
na interface.

---

## Fase 7 — Força de senha

### O que entrega
Avaliação realista da força de uma senha, com aviso e sugestões.

### Decisão 1 — zxcvbn em vez de regra de composição

`Password1!` passa em qualquer regra de "8 caracteres com maiúscula, número e
símbolo" — e está entre as primeiras senhas que qualquer dicionário tenta.

| Abordagem | O que mede | `Password1!` |
|---|---|---|
| **zxcvbn** (escolhida) | Número estimado de tentativas, contra dicionários, padrões de teclado, sequências, datas e substituições l33t | Score baixo |
| Regra de composição | Presença de classes de caracteres | Aprovada |
| Só comprimento | Tamanho | Aprovada |
| Entropia de Shannon do texto | Distribuição de caracteres | Aprovada |

### Decisão 2 — Contexto na análise

```python
resultado = zxcvbn(amostra, user_inputs=contexto)   # nome do serviço, login
```

`github` como senha do GitHub tem de pontuar zero. Sem esse contexto, o zxcvbn a
trataria como uma palavra qualquer de dicionário.

### Decisão 3 — Truncar em 72 caracteres

A análise do zxcvbn é super-linear no comprimento: uma passphrase de 200
caracteres trava a CLI por segundos. O corte é declarado no resultado, que passa
a ser reportado como piso ("no mínimo isto") — uma senha acima de 72 caracteres
já está muito além de qualquer limite útil.

| Opção | Consequência |
|---|---|
| **Truncar e declarar** (escolhida) | Rápido, honesto sobre a aproximação |
| Analisar tudo | Interface travada em senha longa |
| Recusar senha longa | Penaliza justamente a senha mais forte |

---

## Fase 8 — Busca e filtro

### O que entrega
Localizar credenciais por serviço, login ou URL.

### Decisão 1 — Metadados legíveis, segredos cifrados

Uma escolha consciente com uma troca real:

| Opção | Busca | Exposição a quem tem o banco |
|---|---|---|
| **Metadados legíveis** (escolhida) | SQL direto, indexável | Vê os serviços usados, não as senhas |
| Cifrar tudo | Exige baixar e decifrar a tabela inteira a cada tecla | Esconde também a lista de serviços |
| Índice cifrado pesquisável | Busca funciona | Complexidade alta, e vaza padrões de acesso |

Está registrado nas Limitações Conhecidas do README, em vez de ficar implícito.

### Decisão 2 — `LIKE` com curingas escapados

`%` e `_` são curingas do SQL. Sem escape, buscar `100%` retornaria tudo que
começa com `100`, e `admin_root` casaria `adminXroot`.

```python
def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
```

### Decisão 3 — `lower()` dos dois lados, não `ILIKE`

`ILIKE` seria mais direto, mas só existe no PostgreSQL — e a suíte precisa rodar
em SQLite. `func.lower()` funciona nos dois.

### Decisão 4 — Colisão de caixa barrada na aplicação

A `UniqueConstraint` do banco é *case-sensitive*: `github/renan` e `GitHub/renan`
são duas linhas legítimas para o Postgres, e ambas casam com a mesma busca
*case-insensitive*. O par é barrado na criação, e uma colisão preexistente vira
erro de domínio com os ids — nunca um `MultipleResultsFound` cru.

---

## Fase 9 — Interface TUI

### O que entrega
Interface visual no terminal: busca incremental, tabela navegável, painel de
detalhe.

### Decisão 1 — Textual

| Opção | Prós | Contras |
|---|---|---|
| **Textual** (escolhida) | Widgets modernos, CSS, layout reativo, mesmo autor do `rich` já usado na CLI | Biblioteca jovem |
| `curses` | Na biblioteca padrão | API de 1980; não funciona nativamente no Windows |
| `urwid` | Maduro | API verbosa; visual datado |
| `prompt_toolkit` | Excelente para REPL | Não é framework de layout |

### Decisão 2 — O segredo nunca aparece sozinho

É preciso apertar `r` para revelar ou `c` para copiar, e o valor some ao trocar
de linha:

```python
@on(DataTable.RowHighlighted)
def _mostrar_detalhe(self) -> None:
    self._sessao.touch()
    self.query_one("#segredo", Static).update("")   # nunca vaza ao navegar
```

Uma TUI que mostra a senha ao selecionar transforma qualquer screenshot ou
compartilhamento de tela num vazamento.

### Decisão 3 — Texto do usuário nunca vai como markup

Tanto o `rich` quanto o `textual` interpretam `[...]` como tag de estilo:

```python
>>> console.print("aB3[bold]xY9-Kq[/]Zt")
aB3xY9-KqZt          # 9 caracteres a menos
```

O alfabeto do gerador inclui `[` e `]`, e notas e nomes de serviço são texto
livre. Ou seja, o caminho normal do programa produz valores que a biblioteca de
saída mutila — e o usuário copiaria da tela uma senha que não existe.

```python
def literal(valor: str) -> Text:
    """Envolve um valor para que o rich NÃO o interprete como markup."""
    return Text(valor)
```

Todos os pontos de saída de dado do usuário — CLI, tabela, shell e TUI — passam
por `Text`.

---

## Fase 10 — Sessão, clipboard e 2FA

### O que entrega
Timeout de sessão por inatividade, área de transferência com limpeza automática,
e segundo fator TOTP na senha mestra.

### Decisão 1 — `time.monotonic()`, nunca `time.time()`

```python
def _expired_unlocked(self) -> bool:
    return (time.monotonic() - self._last_used) >= self._timeout
```

O relógio de parede pode andar para trás — ajuste de NTP, mudança de fuso,
usuário corrigindo a hora. Uma sessão que deveria expirar ficaria válida
indefinidamente. O monotônico não volta.

| Opção | Falha em |
|---|---|
| **`time.monotonic()`** (escolhida) | — |
| `time.time()` | Ajuste de relógio para trás mantém a sessão viva |
| `datetime.now()` | Idem, e ainda carrega fuso horário desnecessário |

### Decisão 2 — Trava na sessão

A TUI executa trabalho em worker threads. Sem `Lock`, uma thread pode ler a
chave no exato instante em que outra a está zerando — e receber um `bytearray`
parcialmente sobrescrito, que abriria o vault em lugar nenhum, sem erro.

### Decisão 3 — Clipboard: limpar, mas só o que é nosso

```python
if isinstance(atual, str) and hmac.compare_digest(
    atual.encode("utf-8"), expected.encode("utf-8")
):
    pyperclip.copy("")
```

Dois detalhes:

**Só limpa se o conteúdo ainda for o nosso.** Se o usuário copiou outra coisa
nesse meio-tempo, apagar destruiria o trabalho dele.

**A comparação é feita em bytes.** `hmac.compare_digest` aceita `str`, mas essa
sobrecarga **só funciona com ASCII** e levanta `TypeError` para qualquer outro
caractere. Uma senha com acento faria a limpeza estourar dentro da thread do
`Timer`, onde ninguém veria o erro — e o segredo ficaria no clipboard.

**E a limpeza é garantida na saída.** O `Timer` é daemon: se o programa termina
antes do prazo, a thread morre sem executar e o segredo permanece na área de
transferência do sistema, inclusive no histórico de gerenciadores que o mantêm.
Por isso o shell e a TUI chamam `flush_pending()` ao sair.

### Decisão 4 — TOTP, com o modelo de ameaça declarado

Implementação padrão RFC 6238, com janela de tolerância de ±30 s e verificação em
tempo constante (`pyotp` usa `hmac.compare_digest`).

O que o segundo fator faz aqui, com honestidade: o segredo TOTP é cifrado com a
chave derivada da senha mestra. Logo, **quem já tem a senha mestra pode derivar a
chave, decifrar o segredo e gerar códigos**. O TOTP protege o *acesso pela
aplicação* — barra quem descobriu a senha (por cima do ombro, keylogger, senha
reusada) mas não tem o dispositivo autenticador. Não protege a cifra.

Para o segundo fator proteger a cifra, o segredo teria de entrar na derivação da
chave — o que quebraria a recuperação e não é o que o RFC 6238 se propõe a fazer.
A limitação está no README em vez de ficar subentendida.

### Decisão 5 — Comandos destrutivos autenticam

`vault delete` e `vault destroy` exigem a senha mestra. Sem isso, quem senta num
terminal destravado — ou qualquer processo do mesmo usuário — apaga o vault
inteiro com um laço de shell, sem nunca conhecer a senha.

`vault destroy` exige, além da senha, digitar `APAGAR TUDO`. Um `[s/N]` seria
fraco demais para uma operação que destrói todos os segredos: um Enter distraído
não pode custar o vault inteiro.

### Decisão 6 — `vault passwd` usa variável de ambiente separada

`VAULT_MASTER_PASSWORD` serve para automação. Se as duas leituras do comando de
troca (senha atual e senha nova) usassem a mesma variável, o comando geraria salt
novo, re-cifraria tudo com a **mesma** senha e anunciaria "Senha mestra trocada"
— e quem estivesse rotacionando após um vazamento continuaria com a senha
vazada, sem nenhum erro. A senha nova vem de `VAULT_NEW_MASTER_PASSWORD`, e o
comando recusa senhas iguais.

### Decisão 7 — Trocar a senha re-cifra todo o vault

Trocar a senha mestra muda a chave derivada. Trocar apenas o hash e o salt
tornaria **todos os dados ilegíveis** — é o modo clássico de um gerenciador
ingênuo destruir tudo.

```python
old_key = unlock(session, current_password, totp_code=totp_code)
new_key  = derive_encryption_key(new_password, new_salt, new_params)

for credential in session.scalars(select(Credential)):
    senha = crypto.decrypt(old_key, credential.encrypted_password, aad=crypto.AAD_PASSWORD)
    credential.encrypted_password = crypto.encrypt(new_key, senha, aad=crypto.AAD_PASSWORD)
    # o mesmo para notas e segredo TOTP
```

Tudo numa transação: ou troca inteiro, ou não troca. O segredo TOTP da senha
mestra também é re-cifrado, senão o segundo fator pararia de funcionar.

---

## Arquitetura em camadas

```
cli/ , tui/          ← interface: coleta entrada, formata saída
   ↓
core/                ← domínio: criptografia, KDF, regras, sessão
   ↓
db/                  ← persistência: models, repositório, transação
```

A regra de dependência aponta sempre para dentro, e isso impõe três garantias:

**A interface não conhece criptografia.** Nenhum `AESGCM` ou `AAD` aparece em
`cli/main.py`. Se a camada de cima pudesse escolher o AAD, mais cedo ou mais
tarde alguém cifraria uma nota com o rótulo de senha, e o dado só falharia meses
depois.

**A borda decide o limite da transação.** Um comando, uma ação da TUI ou um teste
abrem a transação; as funções de domínio a recebem.

**Erro de domínio vira mensagem; bug vira traceback.** A CLI captura apenas
`VaultError`; qualquer outra exceção sobe inteira. Esconder um bug atrás de
"algo deu errado" é como se perde um dia de depuração.

### Hierarquia de erros

```python
VaultError
├── ConfigurationError          # DATABASE_URL ausente, KDF inválido
├── VaultNotInitializedError    # nenhum vault: "rode vault init"
├── VaultAlreadyExistsError     # já existe um
├── AuthenticationError         # senha incorreta, hash corrompido
├── DecryptionError             # chave errada ou dado adulterado
├── CredentialNotFoundError
├── DuplicateCredentialError
├── SessionExpiredError
└── TotpError
```

Cada mensagem carrega a ação seguinte. `VaultNotInitializedError` diz "Rode
`vault init`"; `DuplicateCredentialError` diz "Use `vault update`".

---

## Estratégia de testes

**250 testes.** A suíte roda inteira sem Docker, sem serviço e sem `.env`, em
SQLite temporário, em ~24 segundos. Os testes que só fazem sentido em Postgres
(migrations, `CHECK`, `timestamptz`) são marcados e pulados quando não há banco:

```python
def pytest_collection_modifyitems(config, items):
    if TEST_DATABASE_URL:
        return
    motivo = pytest.mark.skip(reason="TEST_DATABASE_URL não definida; ...")
    for item in items:
        if "postgres" in item.keywords:
            item.add_marker(motivo)
```

Pular é explícito no relatório. Isso é diferente de o teste **sumir**: teste que
some não falha, e ninguém percebe que a cobertura caiu.

### Isolamento por schema

Cada processo pytest cria e usa um schema Postgres próprio, nomeado pelo PID:

```python
_SCHEMA_DO_PROCESSO = f"vault_test_{os.getpid()}"
```

Sem isso, duas execuções simultâneas contra o mesmo banco — dois
desenvolvedores, duas builds de CI — disputam o `DROP TABLE` / `CREATE TABLE` que
cada teste faz, e o sintoma é intermitente e enganoso: `deadlock detected`,
`table "credentials" does not exist`, e até `duplicate key value violates unique
constraint "pg_type_typname_nsp_index"`, que é o catálogo do próprio Postgres
reclamando de dois `CREATE` concorrentes da mesma tabela. Custa um `CREATE
SCHEMA` e a suíte passa a rodar em paralelo de propósito — verificado com três
suítes simultâneas.

### Parâmetros de KDF baratos

Argon2id com 64 MiB leva ~200 ms. Multiplicado por dezenas de testes, a suíte
passaria de meio minuto e ninguém a rodaria a cada save. Os testes usam custo
mínimo; o custo de produção é exercitado num teste marcado `slow`, para que a
configuração real também tenha prova.

### Os testes que mais importam

| Teste | O que quebra se a proteção sumir |
|---|---|
| `test_nonce_nunca_se_repete` | Reuso de nonce em GCM: recuperação da chave de autenticação |
| `test_aad_diferente_nao_abre` | Blob movido entre campos passaria a abrir |
| `test_qualquer_bit_alterado_e_detectado` | Adulteração do banco passaria despercebida |
| `test_senha_mestra_nao_e_gravada_em_texto_puro` | A promessa central do projeto |
| `test_credencial_e_gravada_cifrada` | Idem, para as credenciais |
| `test_perda_dos_parametros_e_detectada_em_vez_de_aceita` | Vault ilegível com login aparentemente bem-sucedido |
| `test_login_nao_reescreve_o_hash_com_os_parametros_errados` | Última cópia dos parâmetros originais seria destruída |
| `test_downgrade_recusa_rodar_com_vault_existente` | Perda total do vault por um comando de migration |
| `test_upgrade_recusa_apagar_credenciais_duplicadas` | Migration apagaria a senha em uso |
| `test_delete_exige_a_senha_mestra_correta` | Qualquer um apagaria o vault de um terminal destravado |
| `test_passwd_recusa_senha_nova_igual_a_atual` | Rotação de senha que não rotaciona nada |
| `test_normalizacao_nfc_iguala_formas_unicode` | Senha com acento não abriria em outro sistema |
| `test_troca_de_senha_re_cifra_tudo` | Trocar a senha destruiria os dados |
| `test_senha_com_colchetes_e_exibida_integra` | Senha exibida a menos do que foi guardada |
| `test_curinga_do_like_e_escapado` | Buscar `%` retornaria tudo |
| `test_update_preserva_o_que_nao_foi_informado` | Omitir um campo o apagaria |
| `test_lock_concorrente_nunca_entrega_chave_pela_metade` | Chave parcialmente zerada vazaria para a TUI |
| `test_flush_pending_limpa_o_que_estava_agendado` | Senha ficaria no clipboard indefinidamente |
| `test_migration_preserva_dados_de_um_vault_antigo` | O upgrade quebraria vaults existentes |
| `test_importar_sem_env_nao_estoura` | O pacote voltaria a exigir `.env` para ser importado |

### Como um teste é validado

O critério para cada teste de garantia: **desative a proteção e o teste tem de
ficar vermelho**. Um teste que passa nos dois estados não prova nada — só ocupa
espaço no relatório e dá falsa confiança.

---

## Verificação executada

Contra PostgreSQL 16.10 real:

```
250 passed in 23.80s
ruff check .  →  All checks passed!
```

Fluxo completo com a CLI instalada, em banco criado do zero:

```
vault db upgrade    → migrations aplicadas
vault init          → Vault criado. KDF: argon2id (t=3, m=65536 KiB, p=4)
vault add github renan --generate --show
                    → Credencial #1 guardada. Senha: C}71@hc7],,Zrles}&;C
vault get github --login renan --show
                    → Senha: C}71@hc7],,Zrles}&;C     (íntegra, com os colchetes)
```

O que o banco guardou de fato:

```
#1 'github' / 'renan'
    bytes: 0144ba1ebe3b84c2488c98fc8776a7d06784ffcebb06b3e1ca6ce914...  (49 bytes)
hash da senha mestra: $argon2id$v=19$m=65536,t=3,p=4$j1JROXvCgeVwb6lDXmRrnQ$5dZ...
senha mestra em claro?      NÃO
senha da credencial no blob? NÃO
```

Comportamento sob erro:

```
senha mestra errada          → erro: Senha mestra incorreta.              exit 1
delete com senha errada      → erro: Senha mestra incorreta.              exit 1
passwd sem VAULT_NEW_...     → erro: variável não definida                exit 1
downgrade com vault dentro   → MIGRATION INTERROMPIDA                     exit 1
troca de senha mestra        → 2 credenciais re-cifradas; senha antiga recusada,
                               senha nova devolve o conteúdo original intacto
```

---

## Regras de manutenção

Cinco travas que protegem os dados de quem usa o programa. Valem para qualquer
alteração futura.

**1. Nunca mude `_ENCRYPTION_KEY_INFO` nem os `AAD_*`.** Alterar qualquer um
desses rótulos torna todos os vaults existentes ilegíveis. Se for realmente
necessário, faça com um número de versão novo e uma rotina de rotação.

**2. Nunca torne o nonce determinístico.** Nada de derivar do `id`, de contador
persistido ou de timestamp. É a falha mais grave possível em AES-GCM.

**3. Subir o custo do KDF é seguro** — os parâmetros ficam gravados no vault. Mas
rode a suíte antes: `test_parametros_diferentes_dao_chaves_diferentes` mostra
exatamente por que a persistência importa.

**4. Não instancie nada no nível do módulo** que dependa de configuração.
Configuração, engine e sessão são construídos sob demanda.

**5. Antes de mudar uma condição ou guarda que pareça redundante**, rode
`git log -S "<a expressão exata>"` e descubra por que ela existe. Várias das
verificações neste código parecem excessivas até se saber qual perda de dados
elas evitam.

---

## Referência rápida

```bash
# Instalação
uv sync --all-groups
cp .env.example .env          # preencher DATABASE_URL
docker compose up -d
uv run vault db upgrade
uv run vault init

# Uso
vault add github renan -g       # guarda com senha gerada
vault list                      # não pede senha mestra: nada é decifrado
vault search git                # busca por serviço, login ou URL
vault get github --login renan  # copia com auto-clear
vault update 1 --generate       # troca a senha
vault delete 1                  # apaga (exige senha mestra)
vault passwd                    # troca a senha mestra, re-cifra tudo
vault generate -l 32 -n 5       # gera senhas (não precisa de banco)
vault strength 'senha'          # avalia a força (não precisa de banco)
vault totp enable               # segundo fator na senha mestra
vault shell                     # sessão interativa com timeout
vault tui                       # interface visual
vault destroy                   # apaga o vault (senha + APAGAR TUDO)

# Testes
uv run pytest
uv run ruff check .
TEST_DATABASE_URL=postgresql+psycopg://... uv run pytest   # inclui Postgres
```

---

*Programado e executado pelo programador sênior Felipe Andrade, com 28 anos de
experiência em informática.*
