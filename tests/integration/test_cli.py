"""Testes da CLI, do ponto de vista de quem digita os comandos.

Estes testes exercitam o caminho completo — parsing, transação, criptografia,
saída — e são os que provam que as peças conversam. Testes de unidade verdes com
integração quebrada é o modo de falha clássico de um projeto em camadas.

A senha mestra chega por `VAULT_MASTER_PASSWORD` porque `getpass` exige um TTY
que o runner não tem. O clipboard é substituído por um duplo de teste: tocar a
área de transferência real da máquina de quem roda a suíte seria invasivo, e o
`Timer` de auto-clear deixaria a suíte lenta e não-determinística.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine
from typer.testing import CliRunner

from tests.conftest import KDF_TESTE, SENHA_MESTRA
from vault.cli.main import app
from vault.config.settings import reset_settings_cache
from vault.core.kdf import KdfParams

runner = CliRunner()


@pytest.fixture
def clipboard_falso(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Captura o que a CLI copiaria, sem tocar a área de transferência real."""
    copiado: list[str] = []

    def copy_with_autoclear(texto: str, _segundos: int) -> threading.Timer:
        copiado.append(texto)
        timer = threading.Timer(0, lambda: None)  # já expirado: join() é instantâneo
        timer.start()
        return timer

    monkeypatch.setattr("vault.core.clipboard.copy_with_autoclear", copy_with_autoclear)
    monkeypatch.setattr("vault.cli.main.clipboard.copy_with_autoclear", copy_with_autoclear)
    return copiado


@pytest.fixture
def cli(
    engine: Engine,
    database_url: str,
    monkeypatch: pytest.MonkeyPatch,
    kdf_rapido: KdfParams,
) -> Iterator[CliRunner]:
    """Runner com o banco de teste, a senha mestra no ambiente e o KDF barato.

    `DATABASE_URL` é definida além da session factory porque comandos de
    diagnóstico (`vault db check`, `vault db upgrade`) leem a configuração
    diretamente — é o caminho que o usuário exercita de verdade.
    """
    monkeypatch.setenv("DATABASE_URL", database_url)
    reset_settings_cache()
    monkeypatch.setenv("VAULT_MASTER_PASSWORD", SENHA_MESTRA)
    monkeypatch.setattr(
        "vault.core.master_password.KdfParams.from_settings",
        classmethod(lambda cls: KDF_TESTE),
    )
    yield runner


def _rodar(cli: CliRunner, *args: str):
    resultado = cli.invoke(app, list(args))
    return resultado


# ---------------------------------------------------------------------------
# Comandos que não dependem de banco
# ---------------------------------------------------------------------------


def test_help_lista_os_comandos() -> None:
    resultado = runner.invoke(app, ["--help"])
    assert resultado.exit_code == 0
    for comando in ("init", "add", "list", "get", "update", "delete", "generate"):
        assert comando in resultado.output


def test_generate_sem_banco() -> None:
    resultado = runner.invoke(app, ["generate", "--length", "32"])
    assert resultado.exit_code == 0
    linhas = [linha for linha in resultado.output.splitlines() if linha.strip()]
    assert len(linhas[0].strip()) == 32
    assert "entropia" in resultado.output


def test_generate_com_politica_impossivel_falha_com_mensagem() -> None:
    resultado = runner.invoke(
        app,
        ["generate", "--no-lower", "--no-upper", "--no-digits", "--no-symbols"],
    )
    assert resultado.exit_code == 1
    assert "Nenhum conjunto" in resultado.output


def test_strength_avalia_senha_ruim() -> None:
    resultado = runner.invoke(app, ["strength", "123456"])
    assert resultado.exit_code == 0
    assert "péssima" in resultado.output


def test_strength_avalia_senha_boa() -> None:
    resultado = runner.invoke(app, ["strength", "K7#mQ9$vL2@nR5&xW8!p"])
    assert resultado.exit_code == 0
    assert "forte" in resultado.output or "excelente" in resultado.output


# ---------------------------------------------------------------------------
# Ciclo completo
# ---------------------------------------------------------------------------


def test_init_cria_o_vault(cli: CliRunner) -> None:
    resultado = _rodar(cli, "init")
    assert resultado.exit_code == 0, resultado.output
    assert "Vault criado" in resultado.output


def test_init_duas_vezes_e_recusado(cli: CliRunner) -> None:
    _rodar(cli, "init")
    resultado = _rodar(cli, "init")
    assert resultado.exit_code == 1
    assert "Já existe um vault" in resultado.output


def test_comandos_sem_vault_dao_mensagem_acionavel(cli: CliRunner) -> None:
    resultado = _rodar(cli, "status")
    assert resultado.exit_code == 1
    assert "vault init" in resultado.output


def test_fluxo_add_list_get(cli: CliRunner, clipboard_falso: list[str]) -> None:
    assert _rodar(cli, "init").exit_code == 0

    add = _rodar(cli, "add", "github", "renan", "--generate", "--url", "https://github.com")
    assert add.exit_code == 0, add.output
    assert "guardada" in add.output

    listagem = _rodar(cli, "list")
    assert listagem.exit_code == 0
    assert "github" in listagem.output
    assert "renan" in listagem.output

    # A senha gerada foi para o clipboard, não para a tela.
    assert len(clipboard_falso) == 1
    senha_gerada = clipboard_falso[0]
    assert len(senha_gerada) == 20

    get = _rodar(cli, "get", "github", "--login", "renan", "--show")
    assert get.exit_code == 0, get.output
    assert senha_gerada in get.output


def test_a_senha_nao_aparece_na_listagem(cli: CliRunner, clipboard_falso: list[str]) -> None:
    _rodar(cli, "init")
    _rodar(cli, "add", "github", "renan", "--generate")
    senha = clipboard_falso[0]

    listagem = _rodar(cli, "list")
    assert senha not in listagem.output


def test_get_com_senha_mestra_errada(
    cli: CliRunner, monkeypatch: pytest.MonkeyPatch, clipboard_falso: list[str]
) -> None:
    _rodar(cli, "init")
    _rodar(cli, "add", "github", "renan", "--generate")

    monkeypatch.setenv("VAULT_MASTER_PASSWORD", "senha-errada-mesmo")
    resultado = _rodar(cli, "get", "github", "--show")
    assert resultado.exit_code == 1
    assert "incorreta" in resultado.output


def test_add_duplicado_e_recusado(cli: CliRunner, clipboard_falso: list[str]) -> None:
    _rodar(cli, "init")
    _rodar(cli, "add", "github", "renan", "--generate")
    segundo = _rodar(cli, "add", "github", "renan", "--generate")
    assert segundo.exit_code == 1
    assert "Já existe a credencial #1" in segundo.output
    assert "vault update" in segundo.output


def test_get_ambiguo_pede_desambiguacao(cli: CliRunner, clipboard_falso: list[str]) -> None:
    _rodar(cli, "init")
    _rodar(cli, "add", "github", "pessoal", "--generate")
    _rodar(cli, "add", "github", "trabalho", "--generate")

    resultado = _rodar(cli, "get", "github", "--show")
    assert resultado.exit_code == 1
    assert "--login" in resultado.output


def test_busca_filtra(cli: CliRunner, clipboard_falso: list[str]) -> None:
    _rodar(cli, "init")
    _rodar(cli, "add", "github", "renan", "--generate")
    _rodar(cli, "add", "gitlab", "renan", "--generate")
    _rodar(cli, "add", "aws", "admin", "--generate")

    resultado = _rodar(cli, "search", "git")
    assert resultado.exit_code == 0
    assert "github" in resultado.output
    assert "gitlab" in resultado.output
    assert "aws" not in resultado.output


def test_update_troca_a_senha(cli: CliRunner, clipboard_falso: list[str]) -> None:
    _rodar(cli, "init")
    _rodar(cli, "add", "github", "renan", "--generate")
    senha_antiga = clipboard_falso[0]

    atualizado = _rodar(cli, "update", "1", "--generate", "--show")
    assert atualizado.exit_code == 0, atualizado.output

    get = _rodar(cli, "get", "github", "--show")
    assert senha_antiga not in get.output


def test_update_de_id_inexistente(cli: CliRunner) -> None:
    _rodar(cli, "init")
    resultado = _rodar(cli, "update", "999", "--url", "https://x.com")
    assert resultado.exit_code == 1
    assert "não existe" in resultado.output


def test_update_com_flags_conflitantes(cli: CliRunner) -> None:
    _rodar(cli, "init")
    resultado = _rodar(cli, "update", "1", "--password", "--generate")
    assert resultado.exit_code == 1
    assert "mutuamente exclusivos" in resultado.output


def test_delete_com_yes(cli: CliRunner, clipboard_falso: list[str]) -> None:
    _rodar(cli, "init")
    _rodar(cli, "add", "github", "renan", "--generate")

    assert _rodar(cli, "delete", "1", "--yes").exit_code == 0
    assert "Nenhuma credencial" in _rodar(cli, "list").output


def test_status_mostra_o_estado(cli: CliRunner, clipboard_falso: list[str]) -> None:
    _rodar(cli, "init")
    _rodar(cli, "add", "github", "renan", "--generate")

    resultado = _rodar(cli, "status")
    assert resultado.exit_code == 0
    assert "AES-256-GCM" in resultado.output
    assert "argon2id" in resultado.output
    assert "credenciais    : 1" in resultado.output


def test_totp_ativa_e_passa_a_exigir_codigo(
    cli: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _rodar(cli, "init")
    ativacao = _rodar(cli, "totp", "enable")
    assert ativacao.exit_code == 0, ativacao.output
    assert "otpauth://totp/" in ativacao.output

    # Sem código, o vault não abre mais.
    monkeypatch.setenv("VAULT_TOTP_CODE", "000000")
    resultado = _rodar(cli, "status")
    assert resultado.exit_code == 0  # status não destrava
    negado = _rodar(cli, "add", "x", "y", "--generate")
    assert negado.exit_code == 1
    assert "segundo fator" in negado.output.lower() or "inválido" in negado.output.lower()


def test_db_check_com_banco_valido(cli: CliRunner) -> None:
    assert _rodar(cli, "db", "check").exit_code == 0


# ---------------------------------------------------------------------------
# Destruição do vault
# ---------------------------------------------------------------------------


def test_destroy_apaga_tudo(cli: CliRunner, clipboard_falso: list[str]) -> None:
    _rodar(cli, "init")
    _rodar(cli, "add", "github", "renan", "--generate")
    _rodar(cli, "add", "gitlab", "renan", "--generate")

    resultado = _rodar(cli, "destroy", "--yes")
    assert resultado.exit_code == 0, resultado.output
    assert "2 credencial(is)" in resultado.output

    # Sem vault, os comandos voltam a mandar rodar `vault init`.
    depois = _rodar(cli, "status")
    assert depois.exit_code == 1
    assert "vault init" in depois.output


def test_destroy_sem_vault_e_recusado(cli: CliRunner) -> None:
    resultado = _rodar(cli, "destroy", "--yes")
    assert resultado.exit_code == 1
    assert "Não há vault" in resultado.output


def test_destroy_exige_a_frase_exata(cli: CliRunner, clipboard_falso: list[str]) -> None:
    """Um `[s/N]` seria fraco demais para uma operação irreversível."""
    _rodar(cli, "init")
    _rodar(cli, "add", "github", "renan", "--generate")

    resultado = cli.invoke(app, ["destroy"], input="apagar tudo\n")  # minúsculas
    assert resultado.exit_code != 0
    assert _rodar(cli, "list").output.count("github") == 1  # nada foi apagado


def test_destroy_com_a_frase_certa(cli: CliRunner, clipboard_falso: list[str]) -> None:
    _rodar(cli, "init")
    _rodar(cli, "add", "github", "renan", "--generate")

    resultado = cli.invoke(app, ["destroy"], input="APAGAR TUDO\n")
    assert resultado.exit_code == 0, resultado.output
    assert _rodar(cli, "status").exit_code == 1


def test_destroy_com_senha_mestra_errada(
    cli: CliRunner, monkeypatch: pytest.MonkeyPatch, clipboard_falso: list[str]
) -> None:
    _rodar(cli, "init")
    _rodar(cli, "add", "github", "renan", "--generate")

    monkeypatch.setenv("VAULT_MASTER_PASSWORD", "senha-errada-mesmo")
    resultado = cli.invoke(app, ["destroy"], input="APAGAR TUDO\n")
    assert resultado.exit_code == 1
    assert "incorreta" in resultado.output

    monkeypatch.setenv("VAULT_MASTER_PASSWORD", SENHA_MESTRA)
    assert _rodar(cli, "status").exit_code == 0  # o vault continua lá


# ---------------------------------------------------------------------------
# Integridade da saída: markup do rich
# ---------------------------------------------------------------------------
#
# O alfabeto do gerador inclui `[` e `]`, e notas e nomes de serviço são texto
# livre. `console.print("aB3[bold]xY9")` imprime `aB3xY9` — o rich lê `[bold]`
# como tag de estilo e a engole. O usuário veria uma senha mais curta do que a
# guardada, copiaria da tela e não entraria em lugar nenhum: perda de dado sem
# nenhum erro. Estes testes fixam o comportamento correto.

SENHA_COM_MARKUP = "aB3[bold]xY9-Kq[/]Zt[red]7"


def test_senha_com_colchetes_e_exibida_integra(
    cli: CliRunner, monkeypatch: pytest.MonkeyPatch, clipboard_falso: list[str]
) -> None:
    monkeypatch.setattr(
        "vault.cli.main.generate_password", lambda _policy=None: SENHA_COM_MARKUP
    )
    _rodar(cli, "init")
    _rodar(cli, "add", "github", "renan", "--generate", "--show")

    get = _rodar(cli, "get", "github", "--show")
    assert SENHA_COM_MARKUP in get.output


def test_notas_com_colchetes_sao_exibidas_integras(
    cli: CliRunner, clipboard_falso: list[str]
) -> None:
    nota = "servidor [prod] — porta [8080]"
    _rodar(cli, "init")
    _rodar(cli, "add", "aws", "admin", "--generate", "--notes", nota)

    get = _rodar(cli, "get", "aws", "--show", "--notes")
    assert nota in get.output


def test_nome_de_servico_com_colchetes_aparece_na_lista(
    cli: CliRunner, clipboard_falso: list[str]
) -> None:
    _rodar(cli, "init")
    _rodar(cli, "add", "[interno] wiki", "renan", "--generate")

    listagem = _rodar(cli, "list")
    assert "[interno]" in listagem.output


def test_generate_imprime_a_senha_inteira(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vault.cli.main.generate_password", lambda _policy=None: SENHA_COM_MARKUP
    )
    resultado = runner.invoke(app, ["generate", "-n", "1"])
    assert resultado.exit_code == 0
    assert SENHA_COM_MARKUP in resultado.output


def test_generate_varias_tem_o_comprimento_pedido() -> None:
    """Conta senhas pelo total de linhas, não por comprimento.

    A versão anterior filtrava linhas com exatamente 16 caracteres — e falhava de
    forma intermitente justamente quando o rich comia parte de uma senha com
    colchetes. O teste acusava "gerou menos de 5", quando o defeito era de saída.
    """
    resultado = runner.invoke(app, ["generate", "-n", "5", "-l", "16"])
    assert resultado.exit_code == 0
    linhas = [x for x in resultado.output.splitlines() if x.strip()]
    senhas = [x for x in linhas if not x.startswith("entropia")]
    assert len(senhas) == 5
    assert all(len(x.strip()) == 16 for x in senhas), senhas
    assert len({x.strip() for x in senhas}) == 5


def test_senha_longa_sai_inteira_numa_linha_so(cli: CliRunner) -> None:
    """Segredo nao pode ser quebrado pela largura do terminal.

    Medido em 22/09/2026: o `console` normal do rich quebra na largura do
    terminal, e uma senha de 100 caracteres em 80 colunas saia em 3 linhas --
    com o valor inteiro em NENHUMA delas. Quem copia da tela cola uma senha
    partida e nao entra em lugar nenhum. E a mesma classe de perda silenciosa
    que `literal()` evita com markup, e por isso segredo sai pelo
    `segredo_console`, que tem `soft_wrap=True` e `no_color=True`.

    Se alguem trocar `segredo_console` pelo `console` normal, este teste falha.
    """
    resultado = runner.invoke(app, ["generate", "--length", "100"])
    assert resultado.exit_code == 0, f"saida={resultado.output!r}"

    linhas = [linha.strip() for linha in resultado.output.splitlines()]
    inteiras = [linha for linha in linhas if len(linha) == 100]
    assert inteiras, (
        "nenhuma linha traz a senha de 100 caracteres inteira -- ela foi quebrada "
        f"pela largura do terminal. Saida: {linhas!r}"
    )
    assert "" not in inteiras[0], "escape ANSI no meio do segredo"
