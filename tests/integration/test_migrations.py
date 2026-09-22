"""Testes das migrations do Alembic, contra um PostgreSQL real.

Por que isto não pode ser testado em SQLite: as duas garantias que mais importam
aqui — a `CHECK (id = 1)` e o `UNIQUE (service_name, login)` — dependem de o
banco realmente aplicá-las, e `timestamptz` nem existe no SQLite. Um teste de
migration que roda em SQLite prova pouco além de "o script não tem erro de
sintaxe Python".

Cada teste trabalha num **banco descartável** criado na hora. Rodar migrations no
mesmo banco das outras fixtures deixaria `alembic_version` para trás e os testes
passariam a depender da ordem de execução.
"""

from __future__ import annotations

import os
import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy import inspect, make_url, text

from vault.db.migrate import downgrade_to, upgrade_to_head

pytestmark = pytest.mark.postgres

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")


@pytest.fixture
def banco_descartavel() -> str:
    """Cria um banco vazio só para este teste e o remove ao final."""
    if not TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL não definida")

    url = make_url(TEST_DATABASE_URL)
    nome = f"sv_mig_{uuid.uuid4().hex[:12]}"
    # ⚠️ A conexão administrativa usa o banco da própria `TEST_DATABASE_URL`, e
    # **não** o banco `postgres`.
    #
    # `CREATE DATABASE` e `DROP DATABASE` funcionam de qualquer banco — a única
    # regra é não estar conectado ao banco que se cria ou apaga. Apontar para
    # `postgres` acrescentava um requisito que ninguém declarou: o usuário
    # precisar de acesso a um banco que a configuração de teste nem menciona.
    #
    # Medido em 22/09/2026, e quebrou em dois ambientes diferentes pelo mesmo
    # motivo com mensagens que não se parecem:
    #   - num Postgres com `pg_hba.conf` por banco: *"no pg_hba.conf entry for
    #     host …, database \"postgres\""*;
    #   - no CI: *"password authentication failed"* — que parece senha errada e
    #     não é.
    admin = sa.create_engine(url, isolation_level="AUTOCOMMIT")

    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{nome}"'))
    try:
        # ⛔ `str(url)` MASCARA a senha como `***`. O teste entregava uma URL com
        # a senha literal `***`, e o Postgres respondia *"password authentication
        # failed"* — que parece credencial errada no ambiente e é bug daqui.
        #
        # Escondeu-se por muito tempo porque estes testes só rodam com
        # `TEST_DATABASE_URL` definida: na máquina de quem desenvolve eles são
        # pulados, e no CI ninguém lia o log até 22/09/2026.
        yield url.set(database=nome).render_as_string(hide_password=False)
    finally:
        with admin.connect() as conn:
            conn.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :nome AND pid <> pg_backend_pid()"
                ),
                {"nome": nome},
            )
            conn.execute(text(f'DROP DATABASE IF EXISTS "{nome}"'))
        admin.dispose()


def test_upgrade_do_zero_cria_o_schema_completo(banco_descartavel: str) -> None:
    upgrade_to_head(banco_descartavel)

    motor = sa.create_engine(banco_descartavel)
    inspetor = inspect(motor)

    assert set(inspetor.get_table_names()) >= {"vault_config", "credentials"}

    colunas_config = {c["name"] for c in inspetor.get_columns("vault_config")}
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

    colunas_cred = {c["name"] for c in inspetor.get_columns("credentials")}
    assert colunas_cred == {
        "id",
        "encrypted_data",
        "deleted_at",
        "created_at",
        "updated_at",
    }
    motor.dispose()


def test_timestamps_tem_fuso(banco_descartavel: str) -> None:
    upgrade_to_head(banco_descartavel)
    motor = sa.create_engine(banco_descartavel)
    for coluna in inspect(motor).get_columns("credentials"):
        if coluna["name"] in {"created_at", "updated_at"}:
            assert coluna["type"].timezone is True, coluna["name"]
    motor.dispose()


def test_check_impede_um_segundo_vault(banco_descartavel: str) -> None:
    """A trava contra dois vaults é do banco, não da aplicação."""
    upgrade_to_head(banco_descartavel)
    motor = sa.create_engine(banco_descartavel)

    with motor.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO vault_config (id, master_password_hash, salt) "
                "VALUES (1, 'hash', '\\x00')"
            )
        )

    with pytest.raises(sa.exc.IntegrityError), motor.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO vault_config (id, master_password_hash, salt) "
                "VALUES (2, 'hash', '\\x00')"
            )
        )
    motor.dispose()


def test_unique_impede_credencial_duplicada(banco_descartavel: str) -> None:
    from alembic import command

    from vault.db.migrate import alembic_config

    config = alembic_config(banco_descartavel)
    command.upgrade(config, "b1c7d3e59f20")
    motor = sa.create_engine(banco_descartavel)

    inserir = text(
        "INSERT INTO credentials (service_name, login, encrypted_password) "
        "VALUES ('github', 'renan', '\\x00')"
    )
    with motor.begin() as conn:
        conn.execute(inserir)
    with pytest.raises(sa.exc.IntegrityError), motor.begin() as conn:
        conn.execute(inserir)
    motor.dispose()


def test_migration_preserva_dados_de_um_vault_antigo(banco_descartavel: str) -> None:
    """O teste que garante retrocompatibilidade.

    Sobe apenas a migration da Fase 2, grava um vault "antigo" (sem nenhuma das
    colunas novas), aplica o restante e confere que os dados continuam lá com os
    parâmetros de KDF corretos — que são exatamente os que o código antigo tinha
    hardcoded. Sem isto, o upgrade seria uma aposta.
    """
    from alembic import command

    from vault.db.migrate import alembic_config

    config = alembic_config(banco_descartavel)
    command.upgrade(config, "0a4b27000a5b")

    motor = sa.create_engine(banco_descartavel)
    with motor.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO vault_config (id, master_password_hash, salt) VALUES (7, :hash, :salt)"
            ),
            {"hash": "$argon2id$v=19$m=65536,t=3,p=4$abc$def", "salt": b"0123456789abcdef"},
        )
        conn.execute(
            text(
                "INSERT INTO credentials (service_name, login, encrypted_password) "
                "VALUES ('github', 'renan', :blob)"
            ),
            {"blob": b"\x01blob-cifrado-antigo"},
        )

    command.upgrade(config, "b1c7d3e59f20")

    with motor.connect() as conn:
        linha = conn.execute(
            text(
                "SELECT id, master_password_hash, salt, kdf_algorithm, kdf_time_cost, "
                "kdf_memory_cost, kdf_parallelism, key_check FROM vault_config"
            )
        ).one()
        assert linha.id == 1  # normalizado pelo singleton
        assert linha.master_password_hash.startswith("$argon2id$")
        assert bytes(linha.salt) == b"0123456789abcdef"
        assert (linha.kdf_algorithm, linha.kdf_time_cost) == ("argon2id", 3)
        assert (linha.kdf_memory_cost, linha.kdf_parallelism) == (65536, 4)
        assert linha.key_check is None  # preenchido no primeiro login

        credencial = conn.execute(
            text("SELECT service_name, encrypted_password, url FROM credentials")
        ).one()
        assert credencial.service_name == "github"
        assert bytes(credencial.encrypted_password) == b"\x01blob-cifrado-antigo"
        assert credencial.url is None
    motor.dispose()


def test_downgrade_volta_ao_schema_anterior(banco_descartavel: str) -> None:
    """Em banco vazio, o downgrade reverte a estrutura normalmente."""
    upgrade_to_head(banco_descartavel)
    downgrade_to("0a4b27000a5b", banco_descartavel)

    motor = sa.create_engine(banco_descartavel)
    colunas = {c["name"] for c in inspect(motor).get_columns("vault_config")}
    assert "kdf_algorithm" not in colunas
    assert "key_check" not in colunas
    assert colunas == {"id", "master_password_hash", "salt", "created_at"}
    motor.dispose()


def test_ciclo_upgrade_downgrade_upgrade(banco_descartavel: str) -> None:
    """Migration que não sobrevive ao ciclo completo quebra em produção.

    Só vale em banco **vazio** — com um vault dentro, o downgrade se recusa a
    rodar de propósito (ver `test_downgrade_recusa_rodar_com_vault_existente`).
    """
    upgrade_to_head(banco_descartavel)
    downgrade_to("base", banco_descartavel)
    upgrade_to_head(banco_descartavel)

    motor = sa.create_engine(banco_descartavel)
    assert "kdf_algorithm" in {c["name"] for c in inspect(motor).get_columns("vault_config")}
    motor.dispose()


def test_url_com_porcento_e_escapada() -> None:
    """Senha com `%` quebraria o ConfigParser do Alembic sem o escape."""
    from vault.db.migrate import escape_url_for_alembic

    # O `%` no lugar da senha e o ponto do teste: o ConfigParser do Alembic
    # interpreta `%` como interpolacao e estoura se ele nao for escapado.
    url = "postgresql+psycopg://<USUARIO>:<SEN%HA>@localhost:5432/db"
    assert (
        escape_url_for_alembic(url)
        == "postgresql+psycopg://<USUARIO>:<SEN%%HA>@localhost:5432/db"
    )


# ---------------------------------------------------------------------------
# Travas de segurança da migration
# ---------------------------------------------------------------------------
#
# Estes testes cobrem os três caminhos em que a migration destruía dados sozinha.
# Todos exigem Postgres real: são as constraints do banco que forçam a situação.


def test_downgrade_recusa_rodar_com_vault_existente(banco_descartavel: str) -> None:
    """O downgrade tornava o vault ilegível para sempre.

    Ele derruba as colunas kdf_*, e o upgrade seguinte as recria com os valores
    PADRÃO. Como o hash Argon2 (PHC) carrega os próprios parâmetros, a senha
    continuava sendo aceita — e nenhuma credencial abria mais.
    """
    upgrade_to_head(banco_descartavel)
    motor = sa.create_engine(banco_descartavel)
    with motor.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO vault_config (id, master_password_hash, salt, "
                "kdf_time_cost, kdf_memory_cost) VALUES (1, 'h', :salt, 5, 16384)"
            ),
            {"salt": b"salt-do-usuario0"},
        )

    with pytest.raises(Exception, match="MIGRATION INTERROMPIDA"):
        downgrade_to("0a4b27000a5b", banco_descartavel)

    # E o vault continua intacto, com os parâmetros dele.
    with motor.connect() as conn:
        linha = conn.execute(text("SELECT kdf_time_cost, kdf_memory_cost FROM vault_config")).one()
        assert (linha.kdf_time_cost, linha.kdf_memory_cost) == (5, 16384)
    motor.dispose()


def test_downgrade_ainda_funciona_em_banco_vazio(banco_descartavel: str) -> None:
    """A trava não pode inutilizar o uso legítimo: reverter em dev/CI."""
    upgrade_to_head(banco_descartavel)
    downgrade_to("0a4b27000a5b", banco_descartavel)

    motor = sa.create_engine(banco_descartavel)
    colunas = {c["name"] for c in inspect(motor).get_columns("vault_config")}
    assert "kdf_algorithm" not in colunas
    motor.dispose()


def test_upgrade_recusa_apagar_credenciais_duplicadas(banco_descartavel: str) -> None:
    """A versão anterior apagava sozinha, mantendo MAX(id).

    MAX(id) é a de inserção mais recente, não a atualizada por último. Quem salvou
    por engano uma segunda vez e continuou usando a primeira perderia justamente a
    senha em uso — irrecuperável, em silêncio, no meio de um `vault db upgrade`.
    """
    from alembic import command

    from vault.db.migrate import alembic_config

    command.upgrade(alembic_config(banco_descartavel), "0a4b27000a5b")

    motor = sa.create_engine(banco_descartavel)
    with motor.begin() as conn:
        for blob in (b"\x01senha-de-janeiro", b"\x01senha-de-marco"):
            conn.execute(
                text(
                    "INSERT INTO credentials (service_name, login, encrypted_password) "
                    "VALUES ('github', 'renan', :b)"
                ),
                {"b": blob},
            )

    with pytest.raises(Exception, match="MIGRATION INTERROMPIDA"):
        upgrade_to_head(banco_descartavel)

    # Nenhuma das duas foi apagada: o usuário decide qual vale.
    with motor.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM credentials")).scalar() == 2
    motor.dispose()


def test_upgrade_recusa_escolher_entre_dois_vault_config(banco_descartavel: str) -> None:
    """Apagar a linha errada apaga o `salt` que abre todas as credenciais."""
    from alembic import command

    from vault.db.migrate import alembic_config

    command.upgrade(alembic_config(banco_descartavel), "0a4b27000a5b")

    motor = sa.create_engine(banco_descartavel)
    with motor.begin() as conn:
        for salt in (b"salt-da-linha-1", b"salt-da-linha-2"):
            conn.execute(
                text("INSERT INTO vault_config (master_password_hash, salt) VALUES ('h', :s)"),
                {"s": salt},
            )

    with pytest.raises(Exception, match="MIGRATION INTERROMPIDA"):
        upgrade_to_head(banco_descartavel)

    with motor.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM vault_config")).scalar() == 2
    motor.dispose()
