"""Interface de linha de comando (Typer).

Princípios que guiam esta camada:

- **A CLI não conhece criptografia.** Ela coleta entrada, abre uma transação e
  chama o domínio. Nenhum `AESGCM` ou `AAD` aparece aqui.
- **Segredo não vai em argumento de linha de comando.** `vault add --password X`
  deixaria a senha no histórico do shell (`~/.bash_history`), na lista de
  processos (`ps aux`, visível a outros usuários) e nos logs de auditoria do SO.
  Senhas são lidas com `getpass`, que não ecoa e não passa por `argv`. A única
  exceção é a variável de ambiente `VAULT_MASTER_PASSWORD`, existente para CI e
  scripts — com o aviso correspondente no `--help`.
- **Erro de domínio vira mensagem; bug vira traceback.** `VaultError` sai como
  uma linha vermelha e código de saída 1. Qualquer outra exceção sobe inteira:
  esconder um bug atrás de "algo deu errado" é como se perde um dia de debug.
"""

from __future__ import annotations

import getpass
import os
import sys
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from vault.config.settings import get_settings
from vault.core import clipboard, crypto
from vault.core.generator import PasswordPolicy, generate_password
from vault.core.master_password import (
    change_master_password,
    create_vault,
    get_vault_config,
    unlock,
    vault_exists,
)
from vault.core.strength import evaluate
from vault.core.totp import (
    current_code,
    generate_totp_secret,
    normalize_secret,
    provisioning_uri,
)
from vault.db import repository as repo
from vault.db.repository import CredentialInput
from vault.db.session import session_scope
from vault.exceptions import VaultError

console = Console()
err_console = Console(stderr=True)

#: Console EXCLUSIVO para imprimir segredo. Ver `_imprimir_segredo`.
segredo_console = Console(soft_wrap=True, no_color=True, highlight=False)


def _imprimir_segredo(rotulo: str, valor: str) -> None:
    """Imprime um segredo garantindo que ele saia **numa linha só e sem estilo**.

    O `console` normal quebra a linha na largura do terminal. Medido em
    22/09/2026: uma senha de 100 caracteres num terminal de 80 colunas sai em
    3 linhas, e **o valor inteiro não aparece em nenhuma delas**. Quem copia da
    tela cola uma senha partida e não entra em lugar nenhum — o mesmo tipo de
    perda silenciosa que a função `literal()` existe para evitar com markup.

    `soft_wrap=True` desliga a quebra; `no_color=True` e `highlight=False`
    impedem que qualquer escape ANSI entre no meio do valor. Isso importa além
    da estética: com `FORCE_COLOR` no ambiente, o rich colore mesmo sem TTY, e um
    segredo TOTP saía com `[1m` no meio — o `base32decode` de quem o lesse
    estourava `binascii.Error: Non-base32 digit found`, que não parece problema
    de cor nenhum.
    """
    segredo_console.print(Text(f"{rotulo}: ") + Text(valor))

#: Variável de ambiente aceita no lugar do prompt. Ver docstring do módulo.
MASTER_PASSWORD_ENV = "VAULT_MASTER_PASSWORD"  # noqa: S105 - nome da variável, não um segredo

#: Variável separada para a senha **nova** em `vault passwd`. Ver `prompt_master_password`.
NEW_MASTER_PASSWORD_ENV = "VAULT_NEW_MASTER_PASSWORD"  # noqa: S105

app = typer.Typer(
    name="vault",
    help="Secure Vault — gerenciador de senhas com criptografia local.",
    no_args_is_help=True,
    add_completion=False,
)
totp_app = typer.Typer(help="Segundo fator (TOTP) da senha mestra.", no_args_is_help=True)
db_app = typer.Typer(help="Manutenção do banco de dados.", no_args_is_help=True)
app.add_typer(totp_app, name="totp")
app.add_typer(db_app, name="db")


# --------------------------------------------------------------------------
# Entrada de dados
# --------------------------------------------------------------------------


def prompt_master_password(
    *,
    confirm: bool = False,
    prompt: str = "Senha mestra",
    env_var: str = MASTER_PASSWORD_ENV,
) -> str:
    """Lê a senha mestra sem eco. Usa a variável de ambiente `env_var`, se definida.

    `env_var` é parâmetro, e não a constante fixa, por um motivo concreto: em
    `vault passwd` as duas leituras (senha atual e senha nova) liam a **mesma**
    `VAULT_MASTER_PASSWORD`. Quem tivesse essa variável exportada — o cenário para
    o qual ela existe — via "Senha mestra trocada. N credenciais re-cifradas." e
    continuava com a senha antiga. Nenhum erro em lugar nenhum: o comando de fato
    gerava salt novo e re-cifrava tudo, com a mesma senha. Alguém rotacionando a
    senha depois de um vazamento acreditaria estar protegido.
    """
    do_ambiente = os.environ.get(env_var)
    if do_ambiente:
        return do_ambiente

    if not sys.stdin.isatty():
        raise VaultError(
            f"Entrada não é um terminal e {env_var} não está definida — não há "
            "como pedir a senha mestra com segurança. "
            f"Em automação, defina {env_var}."
        )

    senha = getpass.getpass(f"{prompt}: ")
    if confirm and senha != getpass.getpass("Confirme a senha mestra: "):
        raise VaultError("As senhas não conferem.")
    return senha


def prompt_secret(rotulo: str, *, confirm: bool = False) -> str:
    """Lê um segredo qualquer (senha de credencial) sem eco."""
    if not sys.stdin.isatty():
        raise VaultError(f"Entrada não é um terminal; não é possível ler {rotulo}.")
    valor = getpass.getpass(f"{rotulo}: ")
    if confirm and valor != getpass.getpass(f"Confirme {rotulo.lower()}: "):
        raise VaultError("Os valores não conferem.")
    return valor


def literal(valor: str) -> Text:
    """Envolve um valor para que o `rich` NÃO o interprete como markup.

    `console.print("aB3[bold]xY9")` imprime `aB3xY9`: o rich lê `[bold]` como uma
    tag de estilo e a engole. O alfabeto do gerador inclui `[` e `]`, e notas e
    nomes de serviço são texto livre — ou seja, o caminho normal do programa
    produz valores que o rich mutila.

    O efeito seria de perder dados sem erro: o usuário veria uma senha mais curta
    do que a que está guardada, copiaria da tela e não conseguiria entrar em lugar
    nenhum. `Text` é a forma correta de imprimir dado do usuário no rich — ele
    trata o conteúdo como literal, sempre.
    """
    return Text(valor)


def _fail(mensagem: str) -> NoReturn:
    err_console.print(f"[bold red]erro:[/bold red] {mensagem}")
    raise typer.Exit(code=1)


def _entregar_segredo(valor: str, *, copiar: bool, mostrar: bool, rotulo: str) -> None:
    """Mostra na tela ou copia com auto-clear, conforme as flags."""
    if mostrar:
        _imprimir_segredo(rotulo, valor)
        return

    segundos = get_settings().clipboard_clear_seconds
    try:
        timer = clipboard.copy_with_autoclear(valor, segundos)
    except VaultError as exc:
        _fail(str(exc))

    console.print(
        f"{rotulo} copiada para a área de transferência. "
        f"Será apagada em {segundos}s — não feche antes."
    )
    timer.join()
    console.print("[dim]Área de transferência limpa.[/dim]")


def _tabela(credenciais: list[repo.CredentialMetadata]) -> Table:
    tabela = Table(show_header=True, header_style="bold cyan")
    tabela.add_column("ID", justify="right", style="dim")
    tabela.add_column("Serviço")
    tabela.add_column("Login")
    tabela.add_column("URL", overflow="fold")
    tabela.add_column("2FA", justify="center")
    tabela.add_column("Atualizada", style="dim")
    for c in credenciais:
        tabela.add_row(
            str(c.id),
            literal(c.service_name),
            literal(c.login),
            literal(c.url) if c.url else "—",
            "sim" if c.has_totp else "—",
            c.updated_at.strftime("%Y-%m-%d %H:%M") if c.updated_at else "—",
        )
    return tabela


# --------------------------------------------------------------------------
# Ciclo de vida do vault
# --------------------------------------------------------------------------


@app.command()
def init() -> None:
    """Cria o vault neste banco (uma vez só)."""
    try:
        senha = prompt_master_password(confirm=True, prompt="Nova senha mestra")
        relatorio = evaluate(senha)
        if not relatorio.acceptable:
            console.print(
                f"[yellow]Aviso:[/yellow] senha mestra {relatorio.as_line()}."
            )
            if relatorio.warning:
                console.print(f"  {relatorio.warning}")
            for sugestao in relatorio.suggestions:
                console.print(f"  • {sugestao}")
            if not typer.confirm("Usar mesmo assim?", default=False):
                raise typer.Abort()

        with session_scope() as session:
            config = create_vault(session, senha)
            console.print(
                f"[green]Vault criado.[/green] KDF: {config.kdf_algorithm} "
                f"(t={config.kdf_time_cost}, m={config.kdf_memory_cost} KiB, "
                f"p={config.kdf_parallelism})"
            )
    except VaultError as exc:
        _fail(str(exc))


@app.command()
def status() -> None:
    """Mostra o estado do vault: existência, parâmetros e total de credenciais."""
    try:
        with session_scope() as session:
            if not vault_exists(session):
                console.print("[yellow]Nenhum vault neste banco.[/yellow] Rode `vault init`.")
                raise typer.Exit(code=1)
            config = get_vault_config(session)
            total = repo.count_credentials(session)

        console.print("[bold]Secure Vault[/bold]")
        console.print(f"  criado em      : {config.created_at:%Y-%m-%d %H:%M}")
        console.print(f"  KDF            : {config.kdf_algorithm}")
        console.print(
            f"  parâmetros     : t={config.kdf_time_cost}, "
            f"m={config.kdf_memory_cost} KiB, p={config.kdf_parallelism}"
        )
        console.print(f"  cifra          : AES-256-GCM (blob v{crypto.BLOB_VERSION})")
        console.print(f"  segundo fator  : {'ativo' if config.totp_enabled else 'inativo'}")
        console.print(f"  credenciais    : {total}")
    except VaultError as exc:
        _fail(str(exc))


@app.command(name="passwd")
def change_password() -> None:
    """Troca a senha mestra e re-cifra todo o conteúdo do vault."""
    try:
        atual = prompt_master_password(prompt="Senha mestra atual")
        codigo = _pedir_totp_se_necessario()
        nova = prompt_master_password(
            confirm=True,
            prompt="Nova senha mestra",
            env_var=NEW_MASTER_PASSWORD_ENV,
        )

        if nova == atual:
            _fail(
                "A nova senha mestra é igual à atual — nada seria trocado. "
                f"Em automação, defina {NEW_MASTER_PASSWORD_ENV} com a senha nova "
                f"(a {MASTER_PASSWORD_ENV} continua sendo a atual)."
            )

        with session_scope() as session:
            total = change_master_password(session, atual, nova, totp_code=codigo)
        console.print(
            f"[green]Senha mestra trocada.[/green] {total} credencial(is) re-cifrada(s)."
        )
    except VaultError as exc:
        _fail(str(exc))


def _pedir_totp_se_necessario() -> str | None:
    """Pergunta o código TOTP apenas se este vault exigir segundo fator."""
    with session_scope() as session:
        if not vault_exists(session):
            return None
        precisa = get_vault_config(session).totp_enabled
    if not precisa:
        return None
    do_ambiente = os.environ.get("VAULT_TOTP_CODE")
    if do_ambiente:
        return do_ambiente
    return typer.prompt("Código do segundo fator (6 dígitos)")


# --------------------------------------------------------------------------
# CRUD de credenciais
# --------------------------------------------------------------------------


@app.command()
def add(
    service: Annotated[str, typer.Argument(help="Nome do serviço, ex.: github")],
    login: Annotated[str, typer.Argument(help="Usuário ou e-mail")],
    url: Annotated[str | None, typer.Option("--url", help="URL do serviço")] = None,
    notes: Annotated[str | None, typer.Option("--notes", help="Anotação (cifrada)")] = None,
    generate: Annotated[
        bool, typer.Option("--generate", "-g", help="Gerar a senha em vez de digitá-la")
    ] = False,
    length: Annotated[int, typer.Option("--length", "-l", help="Comprimento gerado")] = 20,
    no_symbols: Annotated[bool, typer.Option("--no-symbols", help="Gerar sem símbolos")] = False,
    totp: Annotated[
        bool, typer.Option("--totp", help="Guardar também um segredo TOTP do serviço")
    ] = False,
    show: Annotated[bool, typer.Option("--show", help="Exibir a senha gerada na tela")] = False,
) -> None:
    """Guarda uma credencial nova, cifrada."""
    try:
        mestra = prompt_master_password()
        codigo = _pedir_totp_se_necessario()

        if generate:
            senha = generate_password(
                PasswordPolicy(length=length, use_symbols=not no_symbols)
            )
        else:
            senha = prompt_secret("Senha do serviço", confirm=True)

        segredo_totp = prompt_secret("Segredo TOTP (base32)") if totp else None

        with session_scope() as session:
            chave = unlock(session, mestra, totp_code=codigo)
            credential = repo.create_credential(
                session,
                chave,
                CredentialInput(
                    service_name=service,
                    login=login,
                    password=senha,
                    url=url,
                    notes=notes,
                    totp_secret=segredo_totp,
                ),
            )
            novo_id = credential.id

        console.print(f"[green]Credencial #{novo_id} guardada.[/green]")
        if generate:
            _entregar_segredo(senha, copiar=not show, mostrar=show, rotulo="Senha gerada")
    except (VaultError, ValueError) as exc:
        _fail(str(exc))


@app.command(name="list")
def list_command(
    search: Annotated[
        str | None, typer.Option("--search", "-s", help="Filtra por serviço, login ou URL")
    ] = None,
) -> None:
    """Lista as credenciais. **Pede a senha mestra**, e não tem como não pedir.

    Isto mudou com a arquitetura Zero-Knowledge. Antes, serviço, login e URL
    ficavam em texto puro no banco e a lista saía sem chave nenhuma. Hoje esses
    campos vivem dentro do blob cifrado: **sem a senha mestra não existe nome de
    serviço para mostrar nem para ordenar.** O preço de o banco não saber de quem
    é a credencial é este.

    O que a lista continua NÃO fazendo é exibir segredo: `list_credentials`
    devolve `CredentialMetadata`, sem senha, sem notas e sem segredo TOTP.
    Para abrir uma credencial existe `vault get`.
    """
    try:
        # A checagem vem ANTES de pedir a senha: em banco sem vault, pedir
        # primeiro faz o usuario digitar a senha mestra para so entao descobrir
        # que nao havia nada para abrir.
        with session_scope() as session:
            if not vault_exists(session):
                _fail("Nenhum vault neste banco. Rode `vault init`.")

        mestra = prompt_master_password()
        codigo = _pedir_totp_se_necessario()

        with session_scope() as session:
            chave = unlock(session, mestra, totp_code=codigo)
            credenciais = (
                repo.search_credentials(session, chave, search)
                if search
                else repo.list_credentials(session, chave)
            )
            tabela = _tabela(credenciais)
            total = len(credenciais)

        if total == 0:
            console.print("[dim]Nenhuma credencial encontrada.[/dim]")
            return
        console.print(tabela)
        console.print(f"[dim]{total} credencial(is).[/dim]")
    except VaultError as exc:
        _fail(str(exc))


@app.command()
def search(termo: Annotated[str, typer.Argument(help="Texto a procurar")]) -> None:
    """Busca credenciais por serviço, login ou URL (Fase 8)."""
    list_command(search=termo)


@app.command()
def get(
    service: Annotated[str, typer.Argument(help="Nome do serviço")],
    login: Annotated[str | None, typer.Option("--login", help="Desambigua o serviço")] = None,
    show: Annotated[bool, typer.Option("--show", help="Exibir na tela em vez de copiar")] = False,
    notes: Annotated[bool, typer.Option("--notes", help="Mostrar também as anotações")] = False,
    code: Annotated[bool, typer.Option("--code", help="Mostrar o código TOTP atual")] = False,
) -> None:
    """Recupera a senha de uma credencial."""
    try:
        mestra = prompt_master_password()
        codigo_mestre = _pedir_totp_se_necessario()

        with session_scope() as session:
            chave = unlock(session, mestra, totp_code=codigo_mestre)
            if login:
                encontrada = repo.find_by_service_login(session, chave, service, login)
            else:
                achados = repo.search_credentials(session, chave, service)
                if not achados:
                    _fail(f"Nenhuma credencial para {service!r}.")
                if len(achados) > 1:
                    console.print(_tabela(achados))
                    _fail(
                        f"{len(achados)} credenciais casam com {service!r}. "
                        "Use --login para escolher."
                    )
                encontrada = achados[0]
            # A busca devolve metadado (sem segredo). Abrir é o passo explícito.
            aberta = repo.reveal(chave, repo.get_credential(session, encontrada.id))

        console.print(
            Text(aberta.service_name, style="bold") + Text(f" / {aberta.login}")
        )
        if aberta.url:
            console.print(Text("URL: ") + literal(aberta.url))
        if notes and aberta.notes:
            console.print(Text("Notas: ") + literal(aberta.notes))
        if code:
            if aberta.totp_secret:
                console.print(
                    Text("TOTP agora: ")
                    + Text(current_code(aberta.totp_secret))
                )
            else:
                console.print("[dim]Sem segredo TOTP guardado.[/dim]")

        _entregar_segredo(aberta.password, copiar=not show, mostrar=show, rotulo="Senha")
    except VaultError as exc:
        _fail(str(exc))


@app.command()
def update(
    credential_id: Annotated[int, typer.Argument(help="ID da credencial (veja `vault list`)")],
    login: Annotated[str | None, typer.Option("--login", help="Novo login")] = None,
    url: Annotated[str | None, typer.Option("--url", help="Nova URL")] = None,
    notes: Annotated[str | None, typer.Option("--notes", help="Novas anotações")] = None,
    clear_notes: Annotated[bool, typer.Option("--clear-notes", help="Apagar as anotações")] = False,
    password: Annotated[
        bool, typer.Option("--password", "-p", help="Trocar a senha (pergunta sem eco)")
    ] = False,
    generate: Annotated[
        bool, typer.Option("--generate", "-g", help="Trocar a senha por uma gerada")
    ] = False,
    length: Annotated[int, typer.Option("--length", "-l")] = 20,
    show: Annotated[bool, typer.Option("--show", help="Exibir a senha gerada")] = False,
) -> None:
    """Altera campos de uma credencial. O que não for informado fica como está."""
    try:
        if clear_notes and notes is not None:
            _fail("--notes e --clear-notes são mutuamente exclusivos.")
        if password and generate:
            _fail("--password e --generate são mutuamente exclusivos.")

        mestra = prompt_master_password()
        codigo = _pedir_totp_se_necessario()

        nova_senha: str | object = repo.UNSET
        if generate:
            nova_senha = generate_password(PasswordPolicy(length=length))
        elif password:
            nova_senha = prompt_secret("Nova senha do serviço", confirm=True)

        with session_scope() as session:
            chave = unlock(session, mestra, totp_code=codigo)
            credential = repo.get_credential(session, credential_id)
            repo.update_credential(
                session,
                chave,
                credential,
                login=login if login is not None else repo.UNSET,
                password=nova_senha,
                url=url if url is not None else repo.UNSET,
                notes=None if clear_notes else (notes if notes is not None else repo.UNSET),
            )

        console.print(f"[green]Credencial #{credential_id} atualizada.[/green]")
        if generate and isinstance(nova_senha, str):
            _entregar_segredo(nova_senha, copiar=not show, mostrar=show, rotulo="Nova senha")
    except (VaultError, ValueError) as exc:
        _fail(str(exc))


@app.command()
def delete(
    credential_id: Annotated[int, typer.Argument(help="ID da credencial")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Não perguntar")] = False,
) -> None:
    """Apaga uma credencial. Irreversível.

    Exige a senha mestra. A primeira versão não exigia — e quem sentasse num
    terminal destravado, ou qualquer processo do mesmo usuário, podia apagar o
    vault inteiro com `for i in $(seq 1 500); do vault delete $i --yes; done`
    sem nunca conhecer a senha. Comando destrutivo autentica como qualquer outro
    comando de escrita.
    """
    try:
        mestra = prompt_master_password()
        codigo = _pedir_totp_se_necessario()

        with session_scope() as session:
            chave = unlock(session, mestra, totp_code=codigo)
            # O rótulo da confirmação vive dentro do blob: só sai decifrando.
            aberta = repo.reveal(chave, repo.get_credential(session, credential_id))
            rotulo = f"{aberta.service_name} / {aberta.login}"

        if not yes and not typer.confirm(f"Apagar {rotulo} definitivamente?", default=False):
            raise typer.Abort()

        with session_scope() as session:
            unlock(session, mestra, totp_code=codigo)
            repo.delete_credential(session, repo.get_credential(session, credential_id))
        console.print(f"[green]Credencial #{credential_id} apagada.[/green]")
    except VaultError as exc:
        _fail(str(exc))


# --------------------------------------------------------------------------
# Ferramentas de senha (não tocam o banco)
# --------------------------------------------------------------------------


@app.command()
def generate(
    length: Annotated[int, typer.Option("--length", "-l", help="Comprimento")] = 20,
    count: Annotated[int, typer.Option("--count", "-n", help="Quantas gerar")] = 1,
    no_lower: Annotated[bool, typer.Option("--no-lower")] = False,
    no_upper: Annotated[bool, typer.Option("--no-upper")] = False,
    no_digits: Annotated[bool, typer.Option("--no-digits")] = False,
    no_symbols: Annotated[bool, typer.Option("--no-symbols")] = False,
    no_ambiguous: Annotated[
        bool, typer.Option("--no-ambiguous", help="Excluir caracteres confundíveis (0/O, 1/l)")
    ] = False,
    copy: Annotated[bool, typer.Option("--copy", "-c", help="Copiar em vez de exibir")] = False,
) -> None:
    """Gera senhas fortes. Funciona sem banco configurado."""
    try:
        politica = PasswordPolicy(
            length=length,
            use_lowercase=not no_lower,
            use_uppercase=not no_upper,
            use_digits=not no_digits,
            use_symbols=not no_symbols,
            exclude_ambiguous=no_ambiguous,
        )
        politica.validate()
        from vault.core.generator import entropy_bits

        bits = entropy_bits(len(set(politica.alphabet())), politica.length)
        senhas = [generate_password(politica) for _ in range(max(1, count))]

        if copy:
            _entregar_segredo(senhas[0], copiar=True, mostrar=False, rotulo="Senha")
        else:
            # `segredo_console`, e não `console`: senha longa tem de sair inteira
            # numa linha só. Ver `_imprimir_segredo`. Aqui sem rótulo, porque a
            # saída é feita para ser copiada direto.
            for senha in senhas:
                segredo_console.print(literal(senha))
        console.print(f"[dim]entropia: {bits:.1f} bits por senha[/dim]")
    except VaultError as exc:
        _fail(str(exc))


@app.command()
def strength(
    password: Annotated[
        str | None,
        typer.Argument(help="Senha a avaliar. Omita para digitar sem eco."),
    ] = None,
    context: Annotated[
        list[str] | None,
        typer.Option("--context", help="Contexto (serviço, login) para a análise"),
    ] = None,
) -> None:
    """Avalia a força de uma senha (zxcvbn). Funciona sem banco configurado."""
    try:
        senha = password if password is not None else prompt_secret("Senha a avaliar")
        relatorio = evaluate(senha, user_inputs=list(context or []))

        cor = {0: "red", 1: "red", 2: "yellow", 3: "green", 4: "bright_green"}[relatorio.score]
        console.print(f"Força: [{cor}]{relatorio.as_line()}[/{cor}]")
        console.print(f"Tempo estimado para quebrar (offline, hash lento): {relatorio.crack_time_display}")
        if relatorio.warning:
            console.print(f"[yellow]{relatorio.warning}[/yellow]")
        for sugestao in relatorio.suggestions:
            console.print(f"  • {sugestao}")
    except VaultError as exc:
        _fail(str(exc))


# --------------------------------------------------------------------------
# Segundo fator da senha mestra
# --------------------------------------------------------------------------


@totp_app.command("enable")
def totp_enable(
    secret: Annotated[
        str | None, typer.Option("--secret", help="Usar este segredo em vez de gerar um")
    ] = None,
) -> None:
    """Ativa o segundo fator TOTP na senha mestra."""
    try:
        mestra = prompt_master_password()
        with session_scope() as session:
            chave = unlock(session, mestra)
            config = get_vault_config(session)
            if config.totp_enabled:
                _fail("O segundo fator já está ativo. Desative antes de trocar o segredo.")
            segredo = normalize_secret(secret) if secret else generate_totp_secret()
            config.totp_secret_encrypted = crypto.encrypt(
                chave, segredo, aad=crypto.AAD_MASTER_TOTP
            )
            uri = provisioning_uri(segredo, account_name="senha-mestra")

        console.print("[green]Segundo fator ativado.[/green]")
        _imprimir_segredo("Segredo (guarde offline)", segredo)
        console.print(Text("URI para o QR code: ") + literal(uri))
        console.print("[yellow]Sem este segredo e sem o app autenticador, você perde o acesso.[/yellow]")
    except VaultError as exc:
        _fail(str(exc))


@totp_app.command("disable")
def totp_disable() -> None:
    """Desativa o segundo fator TOTP."""
    try:
        mestra = prompt_master_password()
        codigo = _pedir_totp_se_necessario()
        with session_scope() as session:
            unlock(session, mestra, totp_code=codigo)
            config = get_vault_config(session)
            if not config.totp_enabled:
                _fail("O segundo fator já está inativo.")
            config.totp_secret_encrypted = None
        console.print("[green]Segundo fator desativado.[/green]")
    except VaultError as exc:
        _fail(str(exc))


# --------------------------------------------------------------------------
# Banco
# --------------------------------------------------------------------------


@db_app.command("upgrade")
def db_upgrade() -> None:
    """Aplica as migrations pendentes (equivale a `alembic upgrade head`)."""
    from vault.db.migrate import upgrade_to_head

    try:
        upgrade_to_head()
        console.print("[green]Banco atualizado para a última migration.[/green]")
    except VaultError as exc:
        _fail(str(exc))


@db_app.command("check")
def db_check() -> None:
    """Testa a conexão com o banco configurado."""
    from sqlalchemy import text

    from vault.db.engine import get_engine

    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        console.print("[green]Conexão com o banco OK.[/green]")
    except VaultError as exc:
        _fail(str(exc))
    except Exception as exc:
        _fail(f"Não foi possível conectar: {exc}")


@app.command()
def destroy(
    yes: Annotated[
        bool, typer.Option("--yes", help="Pula a confirmação (para automação)")
    ] = False,
) -> None:
    """Apaga o vault e TODAS as credenciais deste banco. Irreversível.

    Existe para que "recomeçar do zero" seja um comando explícito, e não a
    instrução de dropar o banco na mão — que é como se apaga o banco errado.

    A confirmação exige **digitar a senha mestra e a palavra APAGAR TUDO**. Um
    `[s/N]` seria fraco demais para uma operação que destrói todos os segredos do
    usuário: um Enter distraído não pode custar o vault inteiro.
    """
    try:
        with session_scope() as session:
            if not vault_exists(session):
                _fail("Não há vault neste banco para apagar.")
            total = repo.count_credentials(session)

        if not yes:
            senha = prompt_master_password(prompt="Senha mestra (para confirmar)")
            codigo = _pedir_totp_se_necessario()
            with session_scope() as session:
                unlock(session, senha, totp_code=codigo)

            console.print(
                f"[bold red]Isto apagará o vault e {total} credencial(is), "
                "sem possibilidade de desfazer.[/bold red]"
            )
            if typer.prompt("Digite APAGAR TUDO para confirmar") != "APAGAR TUDO":
                console.print("Cancelado.")
                raise typer.Abort()

        with session_scope() as session:
            # Exclusão física, e sem chave: destruir o vault inteiro não precisa
            # decifrar nada, e `delete_credential` aqui só marcaria `deleted_at`
            # deixando as linhas cifradas para trás — o oposto de "apagar tudo".
            repo.purge_all_credentials(session)
            session.delete(get_vault_config(session))

        console.print(f"[green]Vault apagado ({total} credencial(is)).[/green]")
    except VaultError as exc:
        _fail(str(exc))


@app.command()
def shell() -> None:
    """Sessão interativa: destrava uma vez e mantém a chave em memória com timeout."""
    from vault.cli.shell import run_shell

    try:
        run_shell()
    except VaultError as exc:
        _fail(str(exc))


@app.command()
def tui() -> None:
    """Interface visual no terminal (Fase 9)."""
    from vault.tui.app import run_tui

    try:
        run_tui()
    except VaultError as exc:
        _fail(str(exc))


def main() -> None:
    """Ponto de entrada do console script `vault` / `secure-vault`."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
