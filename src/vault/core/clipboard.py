"""Área de transferência com limpeza automática (Fase 10).

Copiar uma senha e deixá-la no clipboard é um vazamento silencioso: qualquer
programa em execução pode lê-la, ela sobrevive ao fechamento do terminal e, em
alguns gerenciadores de área de transferência, entra num histórico persistente.

Duas garantias aqui:

1. **Limpeza por tempo**, numa thread daemon. Daemon de propósito: se o usuário
   fecha o programa antes do prazo, o processo não fica pendurado esperando a
   thread — e, como o clipboard é do sistema, o conteúdo continuaria lá de todo
   jeito. Por isso existe a garantia 2.

2. **Só limpa se o conteúdo ainda for o nosso.** Se o usuário copiou outra coisa
   nesse meio-tempo, apagar o clipboard destruiria o trabalho dele. Comparamos
   antes de limpar, em tempo constante.

`pyperclip` depende de um utilitário do sistema no Linux (`xclip`/`xsel`/
`wl-clipboard`). Quando falta, ele levanta `PyperclipException` — que é
convertida numa mensagem acionável em vez de um traceback.
"""

from __future__ import annotations

import contextlib
import hmac
import threading

import pyperclip

from vault.exceptions import VaultError


class ClipboardUnavailableError(VaultError):
    """Não há mecanismo de área de transferência utilizável nesta máquina."""


_ERRO_INDISPONIVEL = (
    "Área de transferência indisponível nesta máquina.\n"
    "No Linux, instale um destes: xclip, xsel ou wl-clipboard.\n"
    "Alternativa: use --show para exibir o valor no terminal."
)


def copy(text: str) -> None:
    """Copia `text`. Levanta `ClipboardUnavailableError` se não houver suporte."""
    try:
        pyperclip.copy(text)
    except pyperclip.PyperclipException as exc:
        raise ClipboardUnavailableError(_ERRO_INDISPONIVEL) from exc


def _clear_if_unchanged(expected: str) -> None:
    try:
        atual = pyperclip.paste()
    except pyperclip.PyperclipException:  # pragma: no cover - ambiente sem clipboard
        return
    # compare_digest evita vazar por timing quanto do conteúdo coincide — mas a
    # sobrecarga que aceita `str` **só funciona com ASCII** e levanta TypeError
    # para qualquer outro caractere. Uma senha com acento, um símbolo fora do
    # ASCII ou uma nota em português faziam a limpeza estourar dentro da thread
    # do Timer, onde ninguém veria o erro — e o segredo ficava na área de
    # transferência indefinidamente. Comparar os bytes UTF-8 resolve e mantém a
    # comparação em tempo constante.
    if isinstance(atual, str) and hmac.compare_digest(
        atual.encode("utf-8"), expected.encode("utf-8")
    ):
        # A limpeza é best-effort: se o clipboard sumiu no meio do caminho
        # (sessão gráfica encerrada), não há o que fazer nem a quem avisar.
        with contextlib.suppress(pyperclip.PyperclipException):
            pyperclip.copy("")


#: Timers de limpeza ainda pendentes neste processo. Ver `flush_pending`.
_PENDENTES: list[tuple[threading.Timer, str]] = []


def copy_with_autoclear(text: str, seconds: int) -> threading.Timer:
    """Copia `text` e agenda a limpeza para daqui a `seconds`.

    Devolve o `Timer` para que a chamadora possa aguardá-lo, e o registra em
    `_PENDENTES` para que `flush_pending()` possa garantir a limpeza na saída.

    O timer é daemon, e isso sozinho seria uma promessa quebrada: no `vault shell`
    e na TUI o programa dizia "some em 20s" e, se o usuário saísse antes, o
    processo terminava, a thread daemon morria sem executar e a senha ficava na
    área de transferência **para sempre** — incluindo no histórico de
    gerenciadores de clipboard que o mantêm. Por isso as duas interfaces chamam
    `flush_pending()` ao sair.
    """
    copy(text)
    timer = threading.Timer(seconds, _clear_if_unchanged, args=(text,))
    timer.daemon = True
    timer.start()
    _PENDENTES.append((timer, text))
    return timer


def flush_pending(*, wait: bool = False) -> None:
    """Resolve todas as limpezas pendentes antes de o processo terminar.

    Com `wait=False` (padrão nas interfaces interativas), cancela os timers e
    limpa **imediatamente** — sair do programa é sinal claro de que o usuário já
    colou o que precisava, e deixar o segredo lá para cumprir o cronômetro seria
    pior do que limpar cedo.

    Com `wait=True`, aguarda cada timer terminar (usado quando faz sentido honrar
    o prazo cheio). Nos dois casos, `_clear_if_unchanged` garante que só limpamos
    se o conteúdo ainda for o nosso.
    """
    pendentes, _PENDENTES[:] = list(_PENDENTES), []
    for timer, texto in pendentes:
        if wait:
            timer.join()
            continue
        timer.cancel()
        _clear_if_unchanged(texto)


def clear() -> None:
    """Esvazia a área de transferência, incondicionalmente."""
    try:
        pyperclip.copy("")
    except pyperclip.PyperclipException as exc:
        raise ClipboardUnavailableError(_ERRO_INDISPONIVEL) from exc
