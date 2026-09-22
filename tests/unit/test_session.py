"""Testes da sessão com timeout."""

from __future__ import annotations

import threading

import pytest

from vault.core.session import VaultSession
from vault.exceptions import SessionExpiredError

CHAVE = b"\x07" * 32


def test_devolve_a_chave_enquanto_viva() -> None:
    with VaultSession(CHAVE, 60) as sessao:
        assert sessao.key() == CHAVE
        assert not sessao.locked


def test_expira_por_inatividade(monkeypatch: pytest.MonkeyPatch) -> None:
    relogio = {"agora": 1000.0}
    monkeypatch.setattr("vault.core.session.time.monotonic", lambda: relogio["agora"])

    sessao = VaultSession(CHAVE, 30)
    assert sessao.key() == CHAVE

    relogio["agora"] += 31
    with pytest.raises(SessionExpiredError, match="expirou"):
        sessao.key()


def test_uso_renova_o_prazo(monkeypatch: pytest.MonkeyPatch) -> None:
    relogio = {"agora": 1000.0}
    monkeypatch.setattr("vault.core.session.time.monotonic", lambda: relogio["agora"])

    sessao = VaultSession(CHAVE, 30)
    for _ in range(5):
        relogio["agora"] += 20
        assert sessao.key() == CHAVE  # cada uso reinicia a contagem


def test_touch_renova_sem_ler_a_chave(monkeypatch: pytest.MonkeyPatch) -> None:
    relogio = {"agora": 1000.0}
    monkeypatch.setattr("vault.core.session.time.monotonic", lambda: relogio["agora"])

    sessao = VaultSession(CHAVE, 30)
    relogio["agora"] += 20
    sessao.touch()
    relogio["agora"] += 20
    assert sessao.key() == CHAVE


def test_expirada_descarta_a_chave_de_vez(monkeypatch: pytest.MonkeyPatch) -> None:
    """Depois de expirar, a segunda tentativa nao pode devolver a chave."""
    relogio = {"agora": 1000.0}
    monkeypatch.setattr("vault.core.session.time.monotonic", lambda: relogio["agora"])

    sessao = VaultSession(CHAVE, 10)
    relogio["agora"] += 11
    with pytest.raises(SessionExpiredError):
        sessao.key()
    with pytest.raises(SessionExpiredError, match="encerrada"):
        sessao.key()


def test_lock_e_idempotente() -> None:
    sessao = VaultSession(CHAVE, 60)
    sessao.lock()
    sessao.lock()
    assert sessao.locked
    with pytest.raises(SessionExpiredError):
        sessao.key()


def test_context_manager_tranca_na_saida() -> None:
    with VaultSession(CHAVE, 60) as sessao:
        assert sessao.key() == CHAVE
    assert sessao.locked


def test_tranca_mesmo_com_excecao() -> None:
    sessao = VaultSession(CHAVE, 60)
    with pytest.raises(RuntimeError), sessao:
        raise RuntimeError("boom")
    assert sessao.locked


def test_segundos_restantes_zera_depois_do_lock() -> None:
    sessao = VaultSession(CHAVE, 60)
    assert sessao.seconds_remaining() > 0
    sessao.lock()
    assert sessao.seconds_remaining() == 0.0


def test_chave_de_tamanho_errado_e_rejeitada() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        VaultSession(b"curta", 60)


def test_timeout_nao_positivo_e_rejeitado() -> None:
    with pytest.raises(ValueError, match="positivo"):
        VaultSession(CHAVE, 0)


def test_leitura_concorrente_nao_quebra() -> None:
    """Leituras simultaneas da chave, como a TUI faz de worker threads."""
    sessao = VaultSession(CHAVE, 60)
    erros: list[BaseException] = []

    def trabalhador() -> None:
        try:
            for _ in range(200):
                assert sessao.key() == CHAVE
                sessao.touch()
        except BaseException as exc:
            erros.append(exc)

    threads = [threading.Thread(target=trabalhador) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not erros


def test_lock_concorrente_nunca_entrega_chave_pela_metade() -> None:
    """A corrida que a trava existe para cobrir: `lock()` cruzando com `key()`.

    A primeira versao deste teste so rodava leituras simultaneas, e passava mesmo
    trocando `self._lock` por `contextlib.nullcontext()` — provava reentrancia, nao
    exclusao mutua. Aqui uma thread zera o buffer enquanto as outras leem: sem a
    trava, uma leitura pode capturar o bytearray no meio da sobrescrita e devolver
    uma chave parcialmente zerada, que abriria o vault em nenhum lugar e sem erro.
    """
    sessao = VaultSession(CHAVE, 60)
    erros: list[BaseException] = []
    leituras: list[bytes] = []
    parar = threading.Event()

    def leitor() -> None:
        try:
            while not parar.is_set():
                try:
                    leituras.append(sessao.key())
                except SessionExpiredError:
                    return  # resultado legitimo depois do lock()
        except BaseException as exc:
            erros.append(exc)

    def trancador() -> None:
        try:
            for _ in range(50):
                sessao.lock()
        except BaseException as exc:
            erros.append(exc)
        finally:
            parar.set()

    threads = [threading.Thread(target=leitor) for _ in range(6)]
    threads.append(threading.Thread(target=trancador))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not erros
    # Toda leitura bem-sucedida devolveu a chave INTEIRA — nunca uma meio zerada.
    assert all(valor == CHAVE for valor in leituras), "chave parcial vazou"
