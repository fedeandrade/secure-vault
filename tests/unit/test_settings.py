"""Testes da configuração.

O primeiro teste deste arquivo cobre o defeito de raiz que impedia a suíte
inteira de coletar: `Settings()` era instanciado no import do módulo, então
qualquer `import vault.*` numa máquina sem `.env` estourava `ValidationError`.

Ele roda num **subprocesso limpo**, e não com `importlib.reload`. A primeira
versão usava reload e o efeito foi instrutivo: recarregar `vault.config.settings`
cria uma segunda função `get_settings` com um `lru_cache` próprio, enquanto os
módulos já importados seguem apontando para a primeira. `reset_settings_cache()`
passava a limpar só um dos dois, e os testes seguintes liam configuração vencida
do outro — dois testes falhavam por causa de um terceiro. Subprocesso não tem
esse problema, e ainda testa o cenário de verdade: um processo novo, sem `.env`.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest
from pydantic import ValidationError

from vault.config.settings import Settings, get_settings, reset_settings_cache
from vault.exceptions import ConfigurationError

MODULOS_PUBLICOS = [
    "vault",
    "vault.config.settings",
    "vault.core.crypto",
    "vault.core.generator",
    "vault.core.kdf",
    "vault.core.master_password",
    "vault.core.session",
    "vault.core.strength",
    "vault.core.totp",
    "vault.db.engine",
    "vault.db.models",
    "vault.db.repository",
    "vault.db.session",
    "vault.cli.main",
    "secure_vault",
]


def _rodar_em_processo_limpo(codigo: str, cwd) -> subprocess.CompletedProcess[str]:
    """Executa `codigo` num Python novo, sem `.env` no diretório corrente."""
    return subprocess.run(  # noqa: S603 - o código é literal deste arquivo, não entrada externa
        [sys.executable, "-c", textwrap.dedent(codigo)],
        capture_output=True,
        text=True,
        cwd=cwd,
        timeout=120,
        check=False,
    )


def test_importar_sem_env_nao_estoura(tmp_path) -> None:
    """Nenhum módulo público pode exigir configuração só para ser importado."""
    resultado = _rodar_em_processo_limpo(
        f"""
        import importlib
        for nome in {MODULOS_PUBLICOS!r}:
            importlib.import_module(nome)
        print("ok")
        """,
        cwd=tmp_path,
    )
    assert resultado.returncode == 0, resultado.stderr
    assert "ok" in resultado.stdout


def test_help_da_cli_funciona_sem_configuracao(tmp_path) -> None:
    """`vault --help` numa máquina recém-clonada tem de funcionar."""
    resultado = _rodar_em_processo_limpo(
        """
        from typer.testing import CliRunner
        from vault.cli.main import app
        r = CliRunner().invoke(app, ["--help"])
        assert r.exit_code == 0, r.output
        print("ok")
        """,
        cwd=tmp_path,
    )
    assert resultado.returncode == 0, resultado.stderr


def test_gerar_senha_funciona_sem_banco(tmp_path) -> None:
    """O gerador não depende de banco — e isso é uma garantia, não um acaso."""
    resultado = _rodar_em_processo_limpo(
        """
        from typer.testing import CliRunner
        from vault.cli.main import app
        r = CliRunner().invoke(app, ["generate", "--length", "24"])
        assert r.exit_code == 0, r.output
        print("ok")
        """,
        cwd=tmp_path,
    )
    assert resultado.returncode == 0, resultado.stderr


def test_database_url_ausente_da_mensagem_acionavel() -> None:
    with pytest.raises(ConfigurationError) as erro:
        Settings().require_database_url()
    mensagem = str(erro.value)
    assert ".env.example" in mensagem
    assert "DATABASE_URL" in mensagem


def test_database_url_definida_e_devolvida(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///x.db")
    reset_settings_cache()
    assert get_settings().require_database_url() == "sqlite+pysqlite:///x.db"


def test_padroes_do_kdf() -> None:
    s = Settings()
    assert (s.kdf_algorithm, s.kdf_time_cost, s.kdf_memory_cost, s.kdf_parallelism) == (
        "argon2id",
        3,
        65536,
        4,
    )


def test_variavel_de_ambiente_sobrepoe_o_padrao(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KDF_TIME_COST", "7")
    monkeypatch.setenv("SESSION_TIMEOUT_SECONDS", "900")
    reset_settings_cache()
    assert get_settings().kdf_time_cost == 7
    assert get_settings().session_timeout_seconds == 900


@pytest.mark.parametrize(
    ("variavel", "valor"),
    [
        ("KDF_TIME_COST", "0"),
        ("KDF_PARALLELISM", "0"),
        ("SESSION_TIMEOUT_SECONDS", "1"),
        ("CLIPBOARD_CLEAR_SECONDS", "0"),
        ("KDF_TIME_COST", "nao-e-numero"),
    ],
)
def test_valor_invalido_e_rejeitado(
    monkeypatch: pytest.MonkeyPatch, variavel: str, valor: str
) -> None:
    """Configuração inválida falha no arranque, não no meio de uma operação."""
    monkeypatch.setenv(variavel, valor)
    reset_settings_cache()
    with pytest.raises(ValidationError):
        get_settings()


def test_get_settings_e_cacheado() -> None:
    assert get_settings() is get_settings()


def test_reset_limpa_o_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    primeiro = get_settings()
    monkeypatch.setenv("KDF_TIME_COST", "5")
    assert get_settings() is primeiro  # ainda cacheado
    reset_settings_cache()
    assert get_settings().kdf_time_cost == 5
