"""Interface visual no terminal (Fase 9), com `textual`.

Desenho da tela: campo de busca em cima, tabela de credenciais no meio, painel de
detalhe embaixo. A senha **nunca** aparece sozinha — é preciso apertar `r` para
revelar ou `c` para copiar, e ela some ao trocar de linha. Uma TUI que mostra a
senha ao selecionar transforma qualquer screenshot ou compartilhamento de tela
num vazamento.

A chave vive numa `VaultSession`; um timer verifica a expiração a cada segundo e
tranca a interface sozinho. `SessionExpiredError` é tratada em cada ação, não só
no timer, porque entre um tique e outro a sessão pode ter vencido.
"""

from __future__ import annotations

from typing import ClassVar

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
)

from vault.config.settings import get_settings
from vault.core import clipboard
from vault.core.master_password import unlock
from vault.core.session import VaultSession
from vault.core.totp import current_code
from vault.db import repository as repo
from vault.db.session import session_scope
from vault.exceptions import SessionExpiredError, VaultError


class VaultTUI(App[None]):
    """Aplicação textual do Secure Vault."""

    CSS = """
    Screen { layout: vertical; }
    #busca { dock: top; }
    #tabela { height: 1fr; }
    #detalhe { height: auto; min-height: 7; border: round $accent; padding: 0 1; }
    #segredo { color: $warning; text-style: bold; }
    #relogio { dock: bottom; height: 1; color: $text-muted; }
    """

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("r", "revelar", "Revelar senha"),
        Binding("c", "copiar", "Copiar senha"),
        Binding("t", "totp", "Código TOTP"),
        Binding("escape", "esconder", "Esconder"),
        Binding("l", "trancar", "Trancar"),
        Binding("q", "quit", "Sair"),
    ]

    def __init__(self, sessao: VaultSession) -> None:
        super().__init__()
        self._sessao = sessao
        self._ids: list[int] = []
        #: Metadado já decifrado da última busca, por id. Guardar isto é o que
        #: permite ao painel de detalhe continuar **sem tocar na senha**: no
        #: Zero-Knowledge, serviço e login só existem dentro do blob, e reabrir a
        #: credencial a cada tecla de navegação decifraria a senha junto.
        self._metadados: dict[int, repo.CredentialMetadata] = {}

    # -- construção da tela ------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Input(placeholder="Buscar por serviço, login ou URL…", id="busca")
        yield DataTable(id="tabela", cursor_type="row")
        with Vertical(id="detalhe"):
            yield Label("", id="titulo")
            yield Static("", id="campos")
            yield Static("", id="segredo")
        with Horizontal(id="relogio"):
            yield Label("", id="restante")
        yield Footer()

    def on_mount(self) -> None:
        tabela = self.query_one("#tabela", DataTable)
        tabela.add_columns("ID", "Serviço", "Login", "URL", "2FA")
        self._recarregar("")
        self.set_interval(1.0, self._tique)
        self.query_one("#busca", Input).focus()

    # -- dados -------------------------------------------------------------

    def _recarregar(self, termo: str) -> None:
        tabela = self.query_one("#tabela", DataTable)
        tabela.clear()
        self._ids.clear()
        self._metadados.clear()
        try:
            chave = self._sessao.key()  # pode levantar SessionExpiredError
            with session_scope() as db:
                achados = repo.search_credentials(db, chave, termo)
                linhas = [
                    (
                        str(c.id),
                        c.service_name,
                        c.login,
                        c.url or "—",
                        "sim" if c.has_totp else "—",
                    )
                    for c in achados
                ]
                self._ids = [c.id for c in achados]
                self._metadados = {c.id: c for c in achados}
        except VaultError as exc:
            self.notify(str(exc), severity="error")
            return

        for linha in linhas:
            tabela.add_row(*linha)
        self._limpar_detalhe()

    def _credencial_selecionada(self) -> int | None:
        tabela = self.query_one("#tabela", DataTable)
        indice = tabela.cursor_row
        if indice is None or not (0 <= indice < len(self._ids)):
            return None
        return self._ids[indice]

    def _limpar_detalhe(self) -> None:
        self.query_one("#titulo", Label).update("")
        self.query_one("#campos", Static).update("")
        self.query_one("#segredo", Static).update("")

    # -- eventos -----------------------------------------------------------

    @on(Input.Changed, "#busca")
    def _buscar(self, evento: Input.Changed) -> None:
        self._sessao.touch()
        self._recarregar(evento.value)

    @on(DataTable.RowHighlighted)
    def _mostrar_detalhe(self) -> None:
        self._sessao.touch()
        self.query_one("#segredo", Static).update("")  # nunca vaza ao navegar
        credential_id = self._credencial_selecionada()
        if credential_id is None:
            return
        # Sem ida ao banco e sem decifrar de novo: o metadado da busca basta, e
        # navegar pela lista nunca chega perto da senha.
        meta = self._metadados.get(credential_id)
        if meta is None:
            return
        titulo = f"{meta.service_name} / {meta.login}"  # literal
        campos = (
            f"URL: {meta.url or '—'}\n"
            f"Criada: {meta.created_at:%Y-%m-%d %H:%M}   "
            f"Atualizada: {meta.updated_at:%Y-%m-%d %H:%M}\n"
            f"Segundo fator: {'sim' if meta.has_totp else 'não'}"
        )
        self.query_one("#titulo", Label).update(Text(titulo))
        self.query_one("#campos", Static).update(Text(campos))

    def _tique(self) -> None:
        restante = self._sessao.seconds_remaining()
        if restante <= 0:
            self.notify("Sessão expirada por inatividade.", severity="warning")
            self.exit()
            return
        self.query_one("#restante", Label).update(
            f"sessão expira em {int(restante)}s  ·  r revelar · c copiar · t TOTP · l trancar"
        )

    # -- ações -------------------------------------------------------------

    def _com_credencial_aberta(self):
        credential_id = self._credencial_selecionada()
        if credential_id is None:
            self.notify("Selecione uma credencial.", severity="warning")
            return None
        chave = self._sessao.key()  # pode levantar SessionExpiredError
        with session_scope() as db:
            return repo.reveal(chave, repo.get_credential(db, credential_id))

    def action_revelar(self) -> None:
        try:
            aberta = self._com_credencial_aberta()
        except SessionExpiredError as exc:
            self.notify(str(exc), severity="error")
            self.exit()
            return
        except VaultError as exc:
            self.notify(str(exc), severity="error")
            return
        if aberta is not None:
            # Text(): o textual também interpreta markup em Static/Label, e a
            # senha pode conter colchetes.
            self.query_one("#segredo", Static).update(
                Text(f"senha: {aberta.password}")
            )

    def action_esconder(self) -> None:
        self.query_one("#segredo", Static).update("")

    def action_copiar(self) -> None:
        try:
            aberta = self._com_credencial_aberta()
        except SessionExpiredError as exc:
            self.notify(str(exc), severity="error")
            self.exit()
            return
        except VaultError as exc:
            self.notify(str(exc), severity="error")
            return
        if aberta is None:
            return
        segundos = get_settings().clipboard_clear_seconds
        try:
            clipboard.copy_with_autoclear(aberta.password, segundos)
        except VaultError as exc:
            self.notify(str(exc), severity="error")
            return
        self.notify(f"Senha copiada. Limpa em {segundos}s.")

    def action_totp(self) -> None:
        try:
            aberta = self._com_credencial_aberta()
        except SessionExpiredError as exc:
            self.notify(str(exc), severity="error")
            self.exit()
            return
        except VaultError as exc:
            self.notify(str(exc), severity="error")
            return
        if aberta is None:
            return
        if not aberta.totp_secret:
            self.notify("Esta credencial não tem segredo TOTP.", severity="warning")
            return
        self.query_one("#segredo", Static).update(
            f"TOTP agora: {current_code(aberta.totp_secret)}"
        )

    def action_trancar(self) -> None:
        self._sessao.lock()
        self.exit()

    def on_unmount(self) -> None:
        """Limpa a área de transferência ao fechar a interface.

        `copy_with_autoclear` usa um `Timer` daemon: fechar a TUI antes do prazo
        mataria a thread sem que ela executasse, e a senha ficaria no clipboard
        do sistema para sempre.
        """
        clipboard.flush_pending()
        self._sessao.lock()


def run_tui() -> None:
    """Pede a senha mestra, destrava e abre a interface."""
    from vault.cli.main import _pedir_totp_se_necessario, prompt_master_password

    senha = prompt_master_password()
    codigo = _pedir_totp_se_necessario()

    with session_scope() as db:
        chave = unlock(db, senha, totp_code=codigo)

    with VaultSession(chave, get_settings().session_timeout_seconds) as sessao:
        VaultTUI(sessao).run()
