"""Criação do engine SQLAlchemy.

O engine antigo era criado no import (`engine = create_engine(settings.database_url)`),
o que tornava impossível importar qualquer coisa do pacote sem configuração válida
e impossível apontar os testes para outro banco. Aqui ele é criado sob demanda e
memoizado por URL, num registro que sabemos descartar (`reset_engine_cache`).
"""

from __future__ import annotations

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.pool import StaticPool

from vault.config.settings import get_settings

#: URL -> Engine. Registro explícito (em vez de lru_cache) porque precisamos
#: iterar sobre os engines para chamar `dispose()` ao resetar.
_ENGINES: dict[tuple[str, bool], Engine] = {}


def create_engine_for(url: str, *, echo: bool = False) -> Engine:
    """Cria um engine para `url`, com os ajustes específicos de cada dialeto.

    SQLite recebe tratamento especial porque os testes o usam: um banco em
    memória vive por conexão, então sem `StaticPool` cada sessão veria um banco
    vazio diferente. `check_same_thread=False` é necessário porque a TUI (textual)
    executa trabalho em worker threads.
    """
    kwargs: dict[str, object] = {"echo": echo, "future": True}

    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url or url.endswith("sqlite://"):
            kwargs["poolclass"] = StaticPool
    else:
        # Conexões ociosas em pool morrem em silêncio atrás de firewalls e do
        # `idle_session_timeout` do Postgres. pre_ping troca um erro obscuro no
        # meio de uma operação por uma reconexão transparente.
        kwargs["pool_pre_ping"] = True

    engine = create_engine(url, **kwargs)

    if url.startswith("sqlite"):
        # SQLite ignora FOREIGN KEY por padrão; sem isto, restrições que o
        # Postgres aplica passariam despercebidas nos testes.
        @event.listens_for(engine, "connect")
        def _enable_sqlite_foreign_keys(dbapi_connection, _record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def get_engine(url: str | None = None, *, echo: bool = False) -> Engine:
    """Engine da aplicação. Sem `url`, usa a configuração (exige DATABASE_URL)."""
    resolved = url or get_settings().require_database_url()
    key = (resolved, echo)
    engine = _ENGINES.get(key)
    if engine is None:
        engine = create_engine_for(resolved, echo=echo)
        _ENGINES[key] = engine
    return engine


def reset_engine_cache() -> None:
    """Fecha e descarta todos os engines memoizados (usado entre testes)."""
    while _ENGINES:
        _, engine = _ENGINES.popitem()
        engine.dispose()
