"""Fixtures compartilhadas.

Três decisões que fazem a suíte ser rápida, determinística e ainda assim honesta:

1. **SQLite por padrão, Postgres quando disponível.** A suíte roda inteira sem
   Docker e sem serviço nenhum. Se `TEST_DATABASE_URL` apontar para um Postgres,
   os testes marcados `@pytest.mark.postgres` também rodam — são os que exercitam
   o que só o Postgres tem (as migrations reais, `timestamptz`, a CHECK constraint).
   A alternativa (exigir Postgres para tudo) foi descartada: uma suíte que só roda
   na máquina certa é uma suíte que ninguém roda.

2. **Parâmetros de KDF baratos nos testes.** Argon2id com 64 MiB e t=3 leva
   ~200 ms. Multiplicado por dezenas de testes, a suíte passaria de meio minuto e
   ninguém a rodaria a cada save. `KDF_TESTE` usa custo mínimo. O custo real é
   exercitado num único teste marcado `slow`, para que a configuração de produção
   também tenha prova.

3. **Cada teste ganha um schema vazio.** Em SQLite, um arquivo por teste em
   `tmp_path`. Em Postgres, o schema exclusivo deste processo (ver
   `schema_isolado`), com as tabelas recriadas a cada teste. Não é um *banco*
   por teste — recriar banco no Postgres é lento demais para uma suíte que se
   quer rodar a cada save — mas o isolamento entre testes e entre processos é
   o mesmo.
"""

from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# ANTES de qualquer import de `vault`, e não numa fixture: o `Console` do Rich é
# construído no import de `vault.cli.main` e lê o ambiente ali, uma vez só.
# Apagar a variável depois, numa fixture autouse, chega tarde demais.
#
# Rich liga a cor pela PRESENÇA de `FORCE_COLOR`, não pelo valor — `FORCE_COLOR=0`
# LIGA a cor. Medido em 22/09/2026: o hook Stop do gate exporta `FORCE_COLOR=0`
# tentando desligá-la, e derrubava 6 testes que passavam no shell. O pior deles
# não parecia problema de cor: o segredo TOTP saía da CLI com `\x1b[1m` no meio e
# o `base32decode` estourava `binascii.Error: Non-base32 digit found`.
#
# A suíte não pode depender de quem a executa.
# ---------------------------------------------------------------------------
for _forca_cor in ("FORCE_COLOR", "CLICOLOR_FORCE"):
    os.environ.pop(_forca_cor, None)
os.environ["NO_COLOR"] = "1"
os.environ.setdefault("TERM", "dumb")

from collections.abc import Iterator  # noqa: E402

import pytest  # noqa: E402
import sqlalchemy as sa  # noqa: E402
from sqlalchemy import Engine  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from vault.config.settings import get_settings, reset_settings_cache  # noqa: E402
from vault.core.kdf import KdfParams  # noqa: E402
from vault.db.base import Base  # noqa: E402
from vault.db.engine import create_engine_for, reset_engine_cache  # noqa: E402
from vault.db.session import configure_session_factory, reset_session_factory  # noqa: E402

#: Custo mínimo aceito pelo Argon2. Só para os testes — ver decisão 2.
KDF_TESTE = KdfParams(time_cost=1, memory_cost=8, parallelism=1, hash_len=32)

SENHA_MESTRA = "senha-mestra-de-teste-123"

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Pula os testes de Postgres quando não há Postgres configurado.

    Pular é explícito no relatório (`s` no output, motivo no `-rs`). Isso é o
    oposto de deixar de gerar o teste: um teste que some não falha e ninguém
    percebe que a cobertura caiu.
    """
    if TEST_DATABASE_URL:
        return
    motivo = pytest.mark.skip(
        reason="TEST_DATABASE_URL não definida; testes de Postgres não rodam."
    )
    for item in items:
        if "postgres" in item.keywords:
            item.add_marker(motivo)


@pytest.fixture(autouse=True)
def _ambiente_limpo(monkeypatch: pytest.MonkeyPatch, tmp_path) -> Iterator[None]:
    """Isola cada teste de `.env`, variáveis herdadas e caches de módulo."""
    for variavel in (
        "DATABASE_URL",
        "KDF_ALGORITHM",
        "KDF_TIME_COST",
        "KDF_MEMORY_COST",
        "KDF_PARALLELISM",
        "SESSION_TIMEOUT_SECONDS",
        "CLIPBOARD_CLEAR_SECONDS",
        "VAULT_MASTER_PASSWORD",
        "VAULT_TOTP_CODE",
        # Rich decide colorir pela PRESENÇA de `FORCE_COLOR`, não pelo valor:
        # `FORCE_COLOR=0` LIGA a cor. Quem herdasse essa variável via ANSI para
        # dentro da saída da CLI, e todo teste que lê `resultado.output`
        # quebrava — inclusive de um jeito cruel, porque o segredo TOTP saía com
        # `\x1b[1m` no meio e o `base32decode` estourava
        # `binascii.Error: Non-base32 digit found`, que não parece problema de cor.
        # Medido em 22/09/2026: o hook Stop do gate exporta `FORCE_COLOR=0`
        # justamente tentando DESLIGAR a cor, e derrubava 6 testes que passavam
        # no shell. A suíte não pode depender de quem a executa.
        "FORCE_COLOR",
        "CLICOLOR_FORCE",
    ):
        monkeypatch.delenv(variavel, raising=False)

    # `Settings` lê `.env` do diretório corrente. Rodar a suíte na raiz do
    # projeto com um `.env` de verdade contaminaria os testes — e, pior, poderia
    # apontá-los para o banco real do desenvolvedor.
    monkeypatch.chdir(tmp_path)

    reset_settings_cache()
    reset_engine_cache()
    reset_session_factory()
    yield
    reset_settings_cache()
    reset_engine_cache()
    reset_session_factory()


#: Schema exclusivo deste processo pytest, quando os testes rodam em Postgres.
#: Ver `schema_isolado`.
_SCHEMA_DO_PROCESSO = f"vault_test_{os.getpid()}"


@pytest.fixture(scope="session")
def schema_isolado() -> Iterator[str | None]:
    """Cria um schema Postgres exclusivo deste processo e o remove ao fim.

    Sem isso, duas execuções simultâneas da suíte contra o mesmo banco (dois
    desenvolvedores, duas builds de CI, um agente rodando os testes em paralelo)
    disputam o `DROP TABLE` / `CREATE TABLE` que cada teste faz. O sintoma é
    intermitente e enganoso — `deadlock detected`, `table "credentials" does not
    exist` e até `duplicate key value violates unique constraint
    "pg_type_typname_nsp_index"`, que é o catálogo do próprio Postgres reclamando
    de dois CREATE concorrentes da mesma tabela.

    Passei um bom tempo procurando estado sujo dentro do processo antes de medir
    e ver que havia **outro** processo escrevendo no mesmo banco. Um schema por
    PID elimina a classe inteira de problema, custa um `CREATE SCHEMA` e ainda
    deixa a suíte apta a rodar em paralelo de propósito.

    Em SQLite não há nada a fazer: cada teste já tem seu arquivo em `tmp_path`.
    """
    if not TEST_DATABASE_URL:
        yield None
        return

    admin = sa.create_engine(TEST_DATABASE_URL, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(sa.text(f'DROP SCHEMA IF EXISTS "{_SCHEMA_DO_PROCESSO}" CASCADE'))
        conn.execute(sa.text(f'CREATE SCHEMA "{_SCHEMA_DO_PROCESSO}"'))
    try:
        yield _SCHEMA_DO_PROCESSO
    finally:
        with admin.connect() as conn:
            conn.execute(
                sa.text(f'DROP SCHEMA IF EXISTS "{_SCHEMA_DO_PROCESSO}" CASCADE')
            )
        admin.dispose()


@pytest.fixture
def database_url(tmp_path, schema_isolado: str | None) -> str:
    """URL do banco de teste: `TEST_DATABASE_URL` se houver, senão SQLite em arquivo.

    Em Postgres, a URL carrega o `search_path` do schema exclusivo do processo,
    de modo que todo DDL e DML dos testes acontece lá dentro.
    """
    if TEST_DATABASE_URL:
        separador = "&" if "?" in TEST_DATABASE_URL else "?"
        return f"{TEST_DATABASE_URL}{separador}options=-csearch_path%3D{schema_isolado}"
    return f"sqlite+pysqlite:///{tmp_path / 'vault-teste.db'}"


@pytest.fixture
def engine(database_url: str) -> Iterator[Engine]:
    """Engine com o schema criado do zero e derrubado ao fim.

    A ordem do teardown importa e não é óbvia. Comandos como `vault db check`
    chamam `get_engine()`, que registra um **segundo** engine no cache global de
    `vault.db.engine` — com pool próprio e conexões que sobrevivem ao comando.
    No Postgres, `DROP TABLE` exige lock ACCESS EXCLUSIVE: se uma dessas conexões
    ainda estiver segurando a tabela, o drop trava ou falha, e o teste seguinte
    encontra um banco em estado indefinido ("relation vault_config does not
    exist").

    O sintoma era intermitente — a suíte passava numa execução e errava na
    seguinte. Por isso o cache global é descartado **antes** do drop, e não no
    teardown do fixture de ambiente, que só roda depois deste.
    """
    reset_engine_cache()
    reset_session_factory()

    motor = create_engine_for(database_url)
    Base.metadata.drop_all(motor)
    Base.metadata.create_all(motor)
    configure_session_factory(motor)

    yield motor

    reset_session_factory()
    reset_engine_cache()  # fecha os engines criados pelos comandos durante o teste
    Base.metadata.drop_all(motor)
    motor.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    """Sessão de banco para o teste, comitada ao final se ainda estiver sã.

    O `commit()` é condicional de propósito. Um teste que verifica um erro de
    integridade deixa a sessão marcada para rollback; comitar às cegas levantaria
    `PendingRollbackError` no teardown, a conexão voltaria ao pool com transação
    aberta e o `DROP TABLE` do teste seguinte entraria em deadlock. Foi
    exatamente esse o sintoma intermitente contra Postgres.
    """
    factory = configure_session_factory(engine)
    with factory() as sessao:
        yield sessao
        try:
            sessao.commit()
        except Exception:
            sessao.rollback()
            raise
        finally:
            sessao.close()


@pytest.fixture
def kdf_rapido(monkeypatch: pytest.MonkeyPatch) -> KdfParams:
    """Faz `KdfParams.from_settings()` devolver os parâmetros baratos."""
    monkeypatch.setattr(KdfParams, "from_settings", classmethod(lambda cls: KDF_TESTE))
    return KDF_TESTE


@pytest.fixture
def vault_criado(session: Session, kdf_rapido: KdfParams):
    """Um vault pronto, com senha mestra conhecida."""
    from vault.core.master_password import create_vault

    config = create_vault(session, SENHA_MESTRA, params=kdf_rapido)
    session.commit()
    return config


@pytest.fixture
def chave(session: Session, vault_criado) -> bytes:
    """A chave de criptografia deste vault de teste."""
    from vault.core.master_password import unlock

    return unlock(session, SENHA_MESTRA)


@pytest.fixture
def settings_padrao():
    """Objeto de configuração com os valores padrão (sem `.env`)."""
    return get_settings()
