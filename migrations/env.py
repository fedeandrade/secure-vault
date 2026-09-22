"""Ambiente do Alembic.

Mudanças em relação ao gerado pelo `alembic init`:

- A URL vem de `get_settings()` (função) em vez do objeto `settings` global, que
  não existe mais — ele era instanciado no import e quebrava qualquer comando sem
  `.env`.
- Quem chamar as migrations pela aplicação (`vault db upgrade`) já injeta a URL
  no `Config`; aqui só preenchemos se ainda estiver com o placeholder do `.ini`.
- `compare_type=True`: sem isso o autogenerate ignora mudança de tipo de coluna,
  e uma migration "vazia" esconderia, por exemplo, a troca de `DateTime` por
  `DateTime(timezone=True)`.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from vault.config.settings import get_settings
from vault.db import models  # noqa: F401  (importado pelo efeito de registrar os models)
from vault.db.base import Base
from vault.db.migrate import escape_url_for_alembic

config = context.config

# A URL só é buscada na configuração se quem chamou não a definiu. O placeholder
# `driver://user:pass@localhost/dbname` é o que vem no alembic.ini de fábrica.
_url_atual = config.get_main_option("sqlalchemy.url", "")
if not _url_atual or _url_atual.startswith("driver://"):
    config.set_main_option(
        "sqlalchemy.url", escape_url_for_alembic(get_settings().require_database_url())
    )

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Modo offline: emite SQL para stdout, sem conectar."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Modo online: conecta e aplica."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            # Necessário para que ALTER TABLE funcione no SQLite, que não suporta
            # a maior parte dos ALTERs — o Alembic recria a tabela por baixo.
            render_as_batch=connection.dialect.name == "sqlite",
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
