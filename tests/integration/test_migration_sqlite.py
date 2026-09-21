"""Testes de migração do Alembic usando SQLite local."""

from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa
from sqlalchemy import inspect, text

from vault.db.migrate import downgrade_to, upgrade_to_head


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
