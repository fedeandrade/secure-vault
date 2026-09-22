"""Execução programática das migrations do Alembic.

Existe para que `vault db upgrade` funcione a partir de qualquer diretório e sem
o usuário precisar saber que o Alembic está embaixo. Chamar `alembic upgrade head`
na mão exige estar na raiz do projeto (por causa do `script_location` relativo do
`alembic.ini`); aqui o caminho é resolvido a partir da localização deste módulo.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from vault.config.settings import get_settings
from vault.exceptions import ConfigurationError

#: .../src/vault/db/migrate.py -> .../src/vault/db -> .../src/vault -> .../src -> raiz
PROJECT_ROOT = Path(__file__).resolve().parents[3]


def escape_url_for_alembic(url: str) -> str:
    """Escapa `%` para o ConfigParser do Alembic.

    O `alembic.ini` é lido por `configparser` com interpolação: um `%` na senha
    do banco (perfeitamente legal, e comum em senha gerada) faz o Alembic
    estourar `InterpolationSyntaxError` ao ler a URL. O escape é `%%`.
    """
    return url.replace("%", "%%")


def alembic_config(database_url: str | None = None) -> Config:
    """`Config` do Alembic com o `script_location` e a URL já resolvidos."""
    ini = PROJECT_ROOT / "alembic.ini"
    if not ini.is_file():
        raise ConfigurationError(
            f"alembic.ini não encontrado em {ini}. As migrations só rodam a partir "
            "de um checkout do projeto (não de um wheel instalado)."
        )

    config = Config(str(ini))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    url = database_url or get_settings().require_database_url()
    config.set_main_option("sqlalchemy.url", escape_url_for_alembic(url))
    return config


def upgrade_to_head(database_url: str | None = None) -> None:
    command.upgrade(alembic_config(database_url), "head")


def upgrade_to(revision: str, database_url: str | None = None) -> None:
    """Sobe até uma revisão específica, e não até `head`.

    Existe para os testes conseguirem montar um banco no schema ANTIGO e só
    então tentar a migração seguinte. Sem isso não há como exercitar o caminho
    "vault já populado" — que foi exatamente onde o defeito da migration
    Zero-Knowledge se escondeu.
    """
    command.upgrade(alembic_config(database_url), revision)


def downgrade_to(revision: str, database_url: str | None = None) -> None:
    command.downgrade(alembic_config(database_url), revision)


def current_revision(database_url: str | None = None) -> None:
    command.current(alembic_config(database_url), verbose=True)
