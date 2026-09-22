"""zero_knowledge_schema

Revision ID: edb62ca16834
Revises: b1c7d3e59f20
Create Date: 2026-09-20 20:25:05.107283

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "edb62ca16834"
down_revision: str | Sequence[str] | None = "b1c7d3e59f20"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


class MigrationBlocked(RuntimeError):
    """A migration parou porque continuar apagaria dado que só o usuário pode julgar."""


def _abortar_se_houver_credencial(*, sentido: str, instrucao: str) -> None:
    """Recusa a migration quando a tabela `credentials` não está vazia.

    **Por que recusar em vez de converter:** esta migration troca colunas cifradas
    campo a campo por um blob único, e os dois formatos usam AAD diferente. Converter
    exigiria DECIFRAR cada credencial e cifrar de novo — e a migration não tem a
    chave, que só existe depois de o usuário digitar a senha mestra. Não há como
    fazer isso aqui, nem com um palpite.

    **Por que não bastava deixar como estava:** medido em 22/09/2026, num vault SQLite
    com 1 credencial, `alembic upgrade head` já falhava sozinho, com
    `IntegrityError: NOT NULL constraint failed: _alembic_tmp_credentials.encrypted_data`
    — `encrypted_data` entra `NOT NULL` sem `server_default`. O rollback salvava os
    dados, mas o usuário ficava **preso na revisão antiga para sempre**, sem mensagem
    que explicasse o motivo e sem caminho de saída.

    **E o conserto óbvio era pior que o defeito:** pôr `server_default=b""` faz a
    migration passar e **destrói tudo em silêncio** — as colunas com os blobs reais
    são derrubadas logo abaixo, toda linha fica com `encrypted_data = b""`, e o
    `_varrer` do repositório passa a estourar `DecryptionError` na primeira linha,
    derrubando `list`, `search`, `get`, `add` e `update` de uma vez. Vault bricado,
    sem nada na tela dizendo por quê.

    Uma migration que para com instruções custa cinco minutos. Uma que apaga a senha
    errada custa a conta. Mesmo critério de `_abortar_se_houver` na revisão anterior.
    """
    total = op.get_bind().execute(sa.text("SELECT count(*) FROM credentials")).scalar()
    if not total:
        return

    raise MigrationBlocked(
        f"\n\nMIGRATION INTERROMPIDA: este vault tem {total} credencial(is) e "
        f"{sentido} não sabe convertê-las.\n\n"
        "Os dois formatos guardam o segredo de maneiras diferentes, e converter "
        "exige a chave derivada da sua senha mestra — que esta migration não tem "
        "e não pode pedir.\n\n"
        f"{instrucao}\n\n"
        "Nada foi alterado: a transação da migration será revertida.\n"
    )


def upgrade() -> None:
    """Upgrade schema."""
    _abortar_se_houver_credencial(
        sentido="a migração para Zero-Knowledge",
        instrucao=(
            "O QUE FAZER:\n"
            "  1. Com a versão ATUAL do vault (antes de atualizar o código), anote "
            "ou exporte as credenciais que você precisa manter.\n"
            "  2. Rode `vault destroy` para esvaziar o vault, ou aponte "
            "DATABASE_URL para um banco novo.\n"
            "  3. Rode `vault db upgrade` de novo — agora passa.\n"
            "  4. Recadastre as credenciais com `vault add`. Elas serão gravadas "
            "no formato novo, com serviço, login e URL também cifrados."
        ),
    )
    with op.batch_alter_table("credentials", schema=None) as batch_op:
        batch_op.add_column(sa.Column("encrypted_data", sa.LargeBinary(), nullable=False))
        batch_op.add_column(sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.drop_index(batch_op.f("ix_credentials_service_name"))
        batch_op.drop_constraint(batch_op.f("uq_credentials_service_login"), type_="unique")
        batch_op.drop_column("encrypted_password")
        batch_op.drop_column("encrypted_totp_secret")
        batch_op.drop_column("encrypted_notes")
        batch_op.drop_column("url")
        batch_op.drop_column("service_name")
        batch_op.drop_column("login")


def downgrade() -> None:
    """Downgrade schema."""
    # O problema é espelhado: `login` e `service_name` voltam NOT NULL sem default,
    # e `encrypted_data` é derrubada. Com credencial na tabela, ou a migration
    # estoura, ou — se alguém "consertar" com default vazio — o segredo some.
    _abortar_se_houver_credencial(
        sentido="a volta ao schema com metadado em texto puro",
        instrucao=(
            "O QUE FAZER:\n"
            "  1. Anote ou exporte as credenciais que você precisa manter.\n"
            "  2. Rode `vault destroy` para esvaziar o vault.\n"
            "  3. Rode `vault db downgrade` de novo.\n\n"
            "ATENÇÃO: o schema antigo guarda serviço, login e URL em TEXTO PURO no "
            "banco. Só volte para ele se souber exatamente por quê."
        ),
    )
    with op.batch_alter_table("credentials", schema=None) as batch_op:
        batch_op.add_column(sa.Column("login", sa.String(length=255), nullable=False))
        batch_op.add_column(sa.Column("service_name", sa.String(length=255), nullable=False))
        batch_op.add_column(sa.Column("url", sa.String(length=2048), nullable=True))
        batch_op.add_column(sa.Column("encrypted_notes", sa.LargeBinary(), nullable=True))
        batch_op.add_column(sa.Column("encrypted_totp_secret", sa.LargeBinary(), nullable=True))
        batch_op.add_column(sa.Column("encrypted_password", sa.LargeBinary(), nullable=False))
        batch_op.create_unique_constraint(
            batch_op.f("uq_credentials_service_login"), ["service_name", "login"]
        )
        batch_op.create_index(
            batch_op.f("ix_credentials_service_name"), ["service_name"], unique=False
        )
        batch_op.drop_column("deleted_at")
        batch_op.drop_column("encrypted_data")
