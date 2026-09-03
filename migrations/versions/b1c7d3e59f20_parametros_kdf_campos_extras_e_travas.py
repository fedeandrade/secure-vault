"""parametros de kdf, campos extras e travas de integridade

Esta migration é **puramente aditiva** para os dados existentes: nenhuma coluna é
removida ou renomeada, e todas as colunas novas obrigatórias nascem com
`server_default` igual ao valor que o código anterior usava hardcoded. O efeito
é que um vault criado na Fase 3/4 continua abrindo depois do upgrade, com os
mesmos parâmetros de KDF de antes.

O que ela adiciona, e por quê:

- `vault_config.kdf_*` — os parâmetros de derivação deixam de viver no código.
  Ver a explicação em `vault/core/kdf.py`.
- `vault_config.key_check` — sentinela cifrada; nullable porque vaults antigos
  não têm uma, e ela é gravada no primeiro login bem-sucedido.
- `vault_config.totp_secret_encrypted` e `updated_at`.
- `CHECK (id = 1)` em `vault_config` — impede fisicamente um segundo vault.
- `credentials.url`, `encrypted_notes`, `encrypted_totp_secret`.
- `UNIQUE (service_name, login)` e índice em `service_name`.
- Timestamps passam a `timestamptz` no Postgres (eram naive).

Revision ID: b1c7d3e59f20
Revises: 0a4b27000a5b
Create Date: 2026-09-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b1c7d3e59f20"
down_revision: str | Sequence[str] | None = "0a4b27000a5b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


class MigrationBlocked(RuntimeError):
    """A migration parou porque continuar apagaria dado que só o usuário pode julgar."""


def _is_postgres() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _abortar_se_houver(
    consulta: str, *, minimo: int, titulo: str, instrucao: str
) -> None:
    """Interrompe a migration se `consulta` retornar ao menos `minimo` linhas.

    Existe porque a alternativa — apagar sozinha para poder criar a constraint —
    significa destruir segredo do usuário com base num palpite sobre qual linha
    ele quis manter. Uma migration que falha com instruções custa cinco minutos;
    uma que apaga a senha errada custa a conta.
    """
    linhas = op.get_bind().execute(sa.text(consulta)).fetchall()
    if len(linhas) < minimo:
        return

    detalhe = "\n".join(f"  - {tuple(linha)}" for linha in linhas)
    raise MigrationBlocked(
        f"\n\nMIGRATION INTERROMPIDA: {titulo}.\n\n"
        f"{detalhe}\n\n{instrucao}\n\n"
        "Nada foi alterado: a transação da migration será revertida.\n"
    )


def upgrade() -> None:
    """Upgrade schema."""
    # --- vault_config -----------------------------------------------------
    op.add_column(
        "vault_config",
        sa.Column(
            "kdf_algorithm",
            sa.String(length=32),
            nullable=False,
            server_default="argon2id",
        ),
    )
    op.add_column(
        "vault_config",
        sa.Column("kdf_time_cost", sa.Integer(), nullable=False, server_default="3"),
    )
    op.add_column(
        "vault_config",
        sa.Column(
            "kdf_memory_cost", sa.Integer(), nullable=False, server_default="65536"
        ),
    )
    op.add_column(
        "vault_config",
        sa.Column("kdf_parallelism", sa.Integer(), nullable=False, server_default="4"),
    )
    op.add_column(
        "vault_config",
        sa.Column("kdf_hash_len", sa.Integer(), nullable=False, server_default="32"),
    )
    op.add_column(
        "vault_config", sa.Column("key_check", sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        "vault_config",
        sa.Column("totp_secret_encrypted", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "vault_config",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    # Duas linhas em vault_config nunca deveriam ter sido possíveis, mas nada no
    # schema antigo impedia. A CHECK abaixo falharia sem explicar nada se houvesse
    # mais de uma.
    #
    # A primeira versão desta migration resolvia sozinha, apagando as excedentes e
    # preservando a de menor id "porque é a que os dados cifrados usam". Isso era
    # suposição, não fato: se as credenciais foram cifradas com a chave derivada do
    # `salt` da OUTRA linha, apagar essa linha torna o vault ilegível para sempre.
    # Migration de gerenciador de senhas não aposta com o segredo do usuário.
    _abortar_se_houver(
        "SELECT id, created_at FROM vault_config ORDER BY id",
        minimo=2,
        titulo="Há mais de uma linha em vault_config",
        instrucao=(
            "Só uma pode ficar, e apenas você sabe qual `salt` cifrou os dados.\n"
            "Confira as linhas listadas acima, apague as demais manualmente e "
            "rode a migration de novo."
        ),
    )
    op.execute("UPDATE vault_config SET id = 1")
    op.create_check_constraint("ck_vault_config_singleton", "vault_config", "id = 1")

    # --- credentials ------------------------------------------------------
    op.add_column(
        "credentials", sa.Column("url", sa.String(length=2048), nullable=True)
    )
    op.add_column(
        "credentials", sa.Column("encrypted_notes", sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        "credentials",
        sa.Column("encrypted_totp_secret", sa.LargeBinary(), nullable=True),
    )

    # Duplicatas (service_name, login) impediriam criar o índice único.
    #
    # A primeira versão apagava as duplicatas mantendo `MAX(id)` — "a mais recente".
    # Errado duas vezes: `MAX(id)` é a de INSERÇÃO mais recente, não a atualizada
    # por último. Um usuário que salvou `github/renan` em janeiro (id=3), salvou de
    # novo por engano em março (id=9) e desde então vem atualizando a id=3 perderia
    # exatamente a senha em uso — de forma irrecuperável, em silêncio, no meio de um
    # `vault db upgrade`.
    _abortar_se_houver(
        """
        SELECT service_name, login, count(*) AS total
        FROM credentials GROUP BY service_name, login HAVING count(*) > 1
        """,
        minimo=1,
        titulo="Há credenciais duplicadas (mesmo serviço e login)",
        instrucao=(
            "Resolva-as antes de migrar: abra cada uma com `vault get`, decida "
            "qual senha vale e apague a outra com `vault delete <id>`.\n"
            "A migration não escolhe por você — a senha apagada é irrecuperável."
        ),
    )
    op.create_unique_constraint(
        "uq_credentials_service_login", "credentials", ["service_name", "login"]
    )
    op.create_index("ix_credentials_service_name", "credentials", ["service_name"])

    # --- timestamps com fuso ---------------------------------------------
    if _is_postgres():
        for tabela, colunas in (
            ("vault_config", ["created_at"]),
            ("credentials", ["created_at", "updated_at"]),
        ):
            for coluna in colunas:
                op.alter_column(
                    tabela,
                    coluna,
                    type_=sa.DateTime(timezone=True),
                    existing_type=sa.DateTime(),
                    existing_nullable=False,
                    postgresql_using=f"{coluna} AT TIME ZONE 'UTC'",
                )


def downgrade() -> None:
    """Downgrade schema. **Recusa-se a rodar se houver um vault.**

    Este downgrade não tem como ser honesto com dados dentro. Ele derruba as
    colunas `kdf_*` e `key_check`; um `upgrade` posterior as recria com os valores
    **padrão**, não com os do usuário. Como o hash Argon2 carrega os próprios
    parâmetros no formato PHC, a autenticação continua passando — então o vault
    aceita a senha certa, deriva uma chave errada e nenhuma credencial abre mais.

    Medido num Postgres real, num vault com `t=5 m=16384 p=2`:

        downgrade + upgrade
          kdf gravado agora : 3 / 65536 / 4      (não são os do usuário)
          key_check         : None
          unlock            : SUCESSO            (com a chave errada)
          reveal            : DecryptionError

    Some ainda o conteúdo cifrado de `encrypted_notes` e `encrypted_totp_secret`.

    Por isso: se houver qualquer linha em `vault_config`, o downgrade para. Ele
    continua disponível para reverter um upgrade em banco vazio, que é o uso
    legítimo (desenvolvimento, CI, teste de migration).
    """
    _abortar_se_houver(
        "SELECT id FROM vault_config",
        minimo=1,
        titulo="Existe um vault neste banco e o downgrade o tornaria ilegível",
        instrucao=(
            "As colunas kdf_* seriam derrubadas, e um upgrade posterior as "
            "recriaria com os valores PADRÃO — não com os deste vault. A senha "
            "continuaria sendo aceita, mas nenhuma credencial abriria.\n"
            "Se você realmente quer reverter: exporte o que precisa, apague o "
            "vault (`vault destroy`) e só então rode o downgrade."
        ),
    )

    if _is_postgres():
        for tabela, colunas in (
            ("vault_config", ["created_at"]),
            ("credentials", ["created_at", "updated_at"]),
        ):
            for coluna in colunas:
                op.alter_column(
                    tabela,
                    coluna,
                    type_=sa.DateTime(),
                    existing_type=sa.DateTime(timezone=True),
                    existing_nullable=False,
                )

    op.drop_index("ix_credentials_service_name", table_name="credentials")
    op.drop_constraint(
        "uq_credentials_service_login", "credentials", type_="unique"
    )
    op.drop_column("credentials", "encrypted_totp_secret")
    op.drop_column("credentials", "encrypted_notes")
    op.drop_column("credentials", "url")

    op.drop_constraint("ck_vault_config_singleton", "vault_config", type_="check")
    op.drop_column("vault_config", "updated_at")
    op.drop_column("vault_config", "totp_secret_encrypted")
    op.drop_column("vault_config", "key_check")
    op.drop_column("vault_config", "kdf_hash_len")
    op.drop_column("vault_config", "kdf_parallelism")
    op.drop_column("vault_config", "kdf_memory_cost")
    op.drop_column("vault_config", "kdf_time_cost")
    op.drop_column("vault_config", "kdf_algorithm")
