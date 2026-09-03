"""Sessão interativa (`vault shell`).

Motivação: a CLI normal é *stateless* — cada comando pede a senha mestra de novo,
o que é seguro mas custa ~200 ms de Argon2 por comando e cansa o usuário. O shell
destrava uma vez, guarda a chave numa `VaultSession` com timeout e libera comandos
curtos enquanto a sessão estiver viva.

Deliberadamente **não** persiste a chave em lugar nenhum: fechou o shell, acabou.
A alternativa comum (um daemon com socket, estilo `ssh-agent`) foi descartada —
resolveria o mesmo problema com uma superfície de ataque muito maior, e está
fora do escopo declarado do projeto.
"""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from vault.config.settings import get_settings
from vault.core import clipboard
from vault.core.generator import PasswordPolicy, generate_password
from vault.core.master_password import unlock
from vault.core.session import VaultSession
from vault.core.totp import current_code
from vault.db import repository as repo
from vault.db.session import session_scope
from vault.exceptions import SessionExpiredError, VaultError

console = Console()

_AJUDA = """[bold]Comandos[/bold]
  list [termo]     lista (ou busca) credenciais
  get <id>         copia a senha da credencial para a área de transferência
  show <id>        exibe a senha na tela
  code <id>        mostra o código TOTP atual da credencial
  gen [tamanho]    gera uma senha e copia
  lock             tranca a sessão e sai
  help             esta ajuda
  quit / exit      sair
"""


def run_shell() -> None:
    """Destrava o vault e entra no laço interativo."""
    from vault.cli.main import _pedir_totp_se_necessario, prompt_master_password

    senha = prompt_master_password()
    codigo = _pedir_totp_se_necessario()

    with session_scope() as db:
        chave = unlock(db, senha, totp_code=codigo)

    timeout = get_settings().session_timeout_seconds
    try:
        with VaultSession(chave, timeout) as sessao:
            console.print(
                f"[green]Vault destravado.[/green] A sessão expira após {timeout}s "
                "de inatividade. `help` para os comandos."
            )
            _laco(sessao)
    finally:
        # Sem isto, sair do shell antes do prazo deixava a senha na área de
        # transferência indefinidamente: o Timer é daemon e morre com o processo.
        clipboard.flush_pending()


def _laco(sessao: VaultSession) -> None:
    while True:
        try:
            linha = console.input("[bold cyan]vault>[/bold cyan] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return

        if not linha:
            continue

        comando, _, resto = linha.partition(" ")
        comando = comando.lower()
        resto = resto.strip()

        if comando in {"quit", "exit"}:
            return
        if comando == "lock":
            sessao.lock()
            console.print("[green]Sessão trancada.[/green]")
            return
        if comando == "help":
            console.print(_AJUDA)
            continue

        try:
            _executar(sessao, comando, resto)
        except SessionExpiredError as exc:
            console.print(f"[yellow]{exc}[/yellow]")
            return
        except VaultError as exc:
            console.print(f"[red]erro:[/red] {exc}")
        except ValueError as exc:
            console.print(f"[red]erro:[/red] {exc}")


def _executar(sessao: VaultSession, comando: str, argumento: str) -> None:
    from vault.cli.main import _tabela

    if comando == "list":
        with session_scope() as db:
            achados = (
                repo.search_credentials(db, argumento)
                if argumento
                else repo.list_credentials(db)
            )
            tabela = _tabela(achados)
            total = len(achados)
        sessao.touch()
        console.print(tabela if total else "[dim]Nenhuma credencial.[/dim]")
        return

    if comando in {"get", "show", "code"}:
        if not argumento.isdigit():
            raise ValueError(f"`{comando}` espera um ID numérico. Veja `list`.")
        chave = sessao.key()
        with session_scope() as db:
            aberta = repo.reveal(chave, repo.get_credential(db, int(argumento)))

        if comando == "show":
            # Text(), nunca f-string com markup: a senha pode conter colchetes.
            console.print(
                Text(f"{aberta.service_name}/{aberta.login}: ")
                + Text(aberta.password, style="bold")
            )
        elif comando == "code":
            if not aberta.totp_secret:
                console.print("[dim]Esta credencial não tem segredo TOTP.[/dim]")
            else:
                console.print(f"TOTP: [bold]{current_code(aberta.totp_secret)}[/bold]")
        else:
            segundos = get_settings().clipboard_clear_seconds
            clipboard.copy_with_autoclear(aberta.password, segundos)
            console.print(f"Senha copiada. Some em {segundos}s.")
        return

    if comando == "gen":
        tamanho = int(argumento) if argumento.isdigit() else 20
        senha = generate_password(PasswordPolicy(length=tamanho))
        segundos = get_settings().clipboard_clear_seconds
        clipboard.copy_with_autoclear(senha, segundos)
        sessao.touch()
        console.print(f"Senha de {tamanho} caracteres gerada e copiada. Some em {segundos}s.")
        return

    raise ValueError(f"Comando desconhecido: {comando!r}. `help` para a lista.")
