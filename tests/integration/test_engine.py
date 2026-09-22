"""Testes da camada de conexão.

Substitui o teste da Fase 1, que dependia de um Postgres vivo e de um `.env`
presente — e que por isso derrubava a coleta inteira da suíte numa máquina limpa.
"""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, text

from vault.db.engine import create_engine_for, get_engine, reset_engine_cache
from vault.db.session import session_scope
from vault.exceptions import ConfigurationError


def test_engine_conecta(engine: Engine) -> None:
    with engine.connect() as conn:
        assert conn.execute(text("SELECT 1")).scalar() == 1


def test_engine_sem_database_url_da_erro_de_dominio() -> None:
    reset_engine_cache()
    with pytest.raises(ConfigurationError, match="DATABASE_URL"):
        get_engine()


def test_engine_e_memoizado_por_url(tmp_path) -> None:
    url = f"sqlite+pysqlite:///{tmp_path / 'a.db'}"
    assert get_engine(url) is get_engine(url)


def test_sqlite_em_memoria_compartilha_a_conexao() -> None:
    """Sem StaticPool, cada sessão veria um banco vazio diferente."""
    motor = create_engine_for("sqlite+pysqlite:///:memory:")
    with motor.connect() as conn:
        conn.execute(text("CREATE TABLE t (x int)"))
        conn.commit()
    with motor.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM t")).scalar() == 0


def test_session_scope_comita_no_sucesso(engine: Engine) -> None:
    from tests.conftest import KDF_TESTE, SENHA_MESTRA
    from vault.core.master_password import create_vault, vault_exists

    with session_scope() as s:
        create_vault(s, SENHA_MESTRA, params=KDF_TESTE)

    with session_scope() as s:
        assert vault_exists(s)


def test_session_scope_faz_rollback_no_erro(engine: Engine) -> None:
    from tests.conftest import KDF_TESTE, SENHA_MESTRA
    from vault.core.master_password import create_vault, vault_exists

    with pytest.raises(RuntimeError), session_scope() as s:
        create_vault(s, SENHA_MESTRA, params=KDF_TESTE)
        raise RuntimeError("falha depois de escrever")

    with session_scope() as s:
        assert not vault_exists(s)
