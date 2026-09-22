"""Testes de migração do Alembic usando SQLite local."""

from __future__ import annotations

from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy import inspect, text

from vault.db.migrate import downgrade_to, upgrade_to, upgrade_to_head


def test_alembic_upgrade_head_sqlite(tmp_path: Path) -> None:
    """Verifica se o upgrade completo (head) roda com sucesso no SQLite."""
    db_path = tmp_path / "test_vault_mig.db"
    db_url = f"sqlite:///{db_path}"

    upgrade_to_head(db_url)

    engine = sa.create_engine(db_url)
    insp = inspect(engine)

    assert set(insp.get_table_names()) >= {"vault_config", "credentials", "alembic_version"}

    colunas_config = {c["name"] for c in insp.get_columns("vault_config")}
    assert colunas_config == {
        "id",
        "master_password_hash",
        "salt",
        "kdf_algorithm",
        "kdf_time_cost",
        "kdf_memory_cost",
        "kdf_parallelism",
        "kdf_hash_len",
        "key_check",
        "totp_secret_encrypted",
        "created_at",
        "updated_at",
    }

    colunas_cred = {c["name"] for c in insp.get_columns("credentials")}
    assert colunas_cred == {
        "id",
        "encrypted_data",
        "deleted_at",
        "created_at",
        "updated_at",
    }
    engine.dispose()


def test_alembic_downgrade_and_reupgrade_sqlite(tmp_path: Path) -> None:
    """Verifica ciclo de downgrade e upgrade da migração Zero-Knowledge no SQLite."""
    db_path = tmp_path / "test_vault_cycle.db"
    db_url = f"sqlite:///{db_path}"

    # 1. Upgrade para head (edb62ca16834)
    upgrade_to_head(db_url)
    engine = sa.create_engine(db_url)
    insp = inspect(engine)
    colunas_zk = {c["name"] for c in insp.get_columns("credentials")}
    assert "encrypted_data" in colunas_zk
    assert "service_name" not in colunas_zk
    engine.dispose()

    # 2. Downgrade para b1c7d3e59f20
    downgrade_to("b1c7d3e59f20", db_url)
    engine = sa.create_engine(db_url)
    insp = inspect(engine)
    colunas_legacy = {c["name"] for c in insp.get_columns("credentials")}
    assert "encrypted_data" not in colunas_legacy
    assert "service_name" in colunas_legacy
    assert "login" in colunas_legacy
    assert "encrypted_password" in colunas_legacy
    engine.dispose()

    # 3. Upgrade de volta para head
    upgrade_to_head(db_url)
    engine = sa.create_engine(db_url)
    insp = inspect(engine)
    colunas_reup = {c["name"] for c in insp.get_columns("credentials")}
    assert "encrypted_data" in colunas_reup
    assert "deleted_at" in colunas_reup
    assert "service_name" not in colunas_reup
    engine.dispose()


def test_alembic_insert_zk_credential(tmp_path: Path) -> None:
    """Garante que a tabela migrada aceita inserção e persistência do blob ZK."""
    db_path = tmp_path / "test_vault_insert.db"
    db_url = f"sqlite:///{db_path}"

    upgrade_to_head(db_url)

    engine = sa.create_engine(db_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO credentials (encrypted_data, deleted_at, created_at, updated_at) "
                "VALUES (:data, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            {"data": b"opaque_zk_ciphertext"},
        )

    with engine.connect() as conn:
        row = conn.execute(text("SELECT id, encrypted_data, deleted_at FROM credentials")).one()
        assert row.id == 1
        assert bytes(row.encrypted_data) == b"opaque_zk_ciphertext"
        assert row.deleted_at is None
    engine.dispose()


# ---------------------------------------------------------------------------
# A migração Zero-Knowledge com vault POPULADO
# ---------------------------------------------------------------------------
#
# Este era o vão exato da cobertura, achado por revisão adversarial em
# 22/09/2026: os três testes acima só migram vault VAZIO, e o único que insere
# credencial (`test_alembic_insert_zk_credential`) insere DEPOIS do upgrade.
#
# No vão morava o defeito: com uma credencial na tabela, `alembic upgrade head`
# estourava `IntegrityError: NOT NULL constraint failed:
# _alembic_tmp_credentials.encrypted_data`. O rollback salvava os dados, mas o
# usuário ficava preso na revisão antiga, sem mensagem que dissesse o motivo.


def _popular_credencial_no_schema_antigo(db_url: str) -> None:
    """Insere uma credencial no formato pré-Zero-Knowledge (colunas separadas)."""
    engine = sa.create_engine(db_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO credentials "
                "(service_name, login, encrypted_password, created_at, updated_at) "
                "VALUES ('github', 'renan', :blob, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            {"blob": b"\x01\x02\x03"},
        )
    engine.dispose()


def test_upgrade_zk_recusa_vault_com_credencial(tmp_path: Path) -> None:
    """Com credencial na tabela, o upgrade tem de PARAR com instrução — não estourar.

    Converter exigiria decifrar cada credencial, e a migration não tem a chave:
    ela só existe depois de o usuário digitar a senha mestra. Recusar é a única
    resposta honesta. O que não pode acontecer é o `IntegrityError` cru, que não
    diz o que fazer, nem um `server_default=b""` que faria a migration passar
    destruindo todo o segredo em silêncio.
    """
    db_path = tmp_path / "vault_populado.db"
    db_url = f"sqlite:///{db_path}"

    upgrade_to("b1c7d3e59f20", db_url)
    _popular_credencial_no_schema_antigo(db_url)

    with pytest.raises(Exception) as erro:
        upgrade_to_head(db_url)

    mensagem = str(erro.value)
    assert "MIGRATION INTERROMPIDA" in mensagem
    assert "1 credencial" in mensagem
    assert "O QUE FAZER" in mensagem

    # E o vault continua íntegro e utilizável na revisão anterior.
    engine = sa.create_engine(db_url)
    insp = inspect(engine)
    colunas = {c["name"] for c in insp.get_columns("credentials")}
    assert "service_name" in colunas, "a tabela antiga tem de continuar de pé"
    assert "encrypted_data" not in colunas, "nada da revisão nova pode ter entrado"
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM credentials")).scalar() == 1
    engine.dispose()


def test_upgrade_zk_passa_em_vault_vazio(tmp_path: Path) -> None:
    """O guard não pode atrapalhar o caminho normal: vault vazio migra."""
    db_path = tmp_path / "vault_vazio.db"
    db_url = f"sqlite:///{db_path}"

    upgrade_to("b1c7d3e59f20", db_url)
    upgrade_to_head(db_url)

    engine = sa.create_engine(db_url)
    colunas = {c["name"] for c in inspect(engine).get_columns("credentials")}
    assert colunas == {"id", "encrypted_data", "created_at", "updated_at", "deleted_at"}
    engine.dispose()


def test_downgrade_zk_recusa_vault_com_credencial(tmp_path: Path) -> None:
    """O problema é espelhado na volta, e a recusa também tem de ser."""
    db_path = tmp_path / "vault_zk_populado.db"
    db_url = f"sqlite:///{db_path}"

    upgrade_to_head(db_url)
    engine = sa.create_engine(db_url)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO credentials (encrypted_data, created_at, updated_at) "
                "VALUES (:blob, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            {"blob": b"\x09\x08\x07"},
        )
    engine.dispose()

    with pytest.raises(Exception) as erro:
        downgrade_to("b1c7d3e59f20", db_url)

    assert "MIGRATION INTERROMPIDA" in str(erro.value)

    engine = sa.create_engine(db_url)
    colunas = {c["name"] for c in inspect(engine).get_columns("credentials")}
    assert "encrypted_data" in colunas, "o segredo não pode ter sido derrubado"
    engine.dispose()
