"""Fábrica de sessões e escopo transacional.

O padrão adotado no projeto: **nenhuma função de domínio abre sessão por conta
própria**. Elas recebem uma `Session` pronta. Quem decide o limite da transação é
a borda da aplicação (um comando da CLI, uma ação da TUI, um teste). Isso é o que
permite compor duas operações numa transação só e é o que torna os testes
determinísticos — eles fazem rollback no fim e não deixam resíduo.

A versão anterior (`Session = sessionmaker(bind=engine)` no import) forçava cada
função a abrir a própria sessão, e `login()` chegava a abrir duas para a mesma
operação lógica.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from vault.db.engine import get_engine

_SESSION_FACTORY: sessionmaker[Session] | None = None


def configure_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Aponta a aplicação para `engine`. Usado pelos testes e pela TUI."""
    global _SESSION_FACTORY
    _SESSION_FACTORY = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    return _SESSION_FACTORY


def reset_session_factory() -> None:
    """Esquece a fábrica configurada (a próxima chamada volta a usar a config)."""
    global _SESSION_FACTORY
    _SESSION_FACTORY = None


def get_session_factory() -> sessionmaker[Session]:
    """Fábrica de sessões corrente, criando-a a partir da config se necessário."""
    global _SESSION_FACTORY
    if _SESSION_FACTORY is None:
        _SESSION_FACTORY = sessionmaker(
            bind=get_engine(), expire_on_commit=False, future=True
        )
    return _SESSION_FACTORY


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transação: comita ao sair sem erro, faz rollback em qualquer exceção.

    `expire_on_commit=False` é intencional: sem isso, ler um atributo de um objeto
    depois do commit dispararia um SELECT numa sessão já fechada (`DetachedInstanceError`),
    justamente no ponto em que a CLI vai imprimir o resultado.
    """
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
