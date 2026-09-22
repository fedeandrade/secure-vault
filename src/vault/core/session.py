"""Sessão destravada em memória, com expiração por inatividade (Fase 10).

Guarda a chave derivada enquanto o usuário está trabalhando (no `vault shell` e
na TUI), para não pedir a senha mestra a cada comando, e a descarta sozinha após
um período de inatividade.

Dois detalhes que costumam passar batido:

- **`time.monotonic()`, nunca `time.time()`.** Relógio de parede pode andar para
  trás (NTP, fuso, usuário mexendo na hora) e uma sessão que deveria expirar
  ficaria válida indefinidamente. O monotônico não volta.
- **O `Lock`.** A TUI do textual roda trabalho em worker threads; sem trava, uma
  thread poderia ler a chave no exato instante em que outra a está zerando.

Sobre "apagar da memória": `bytearray` + sobrescrita reduz a janela, mas CPython
não garante que não sobrou cópia. Está declarado como limitação no README — é
melhor do que fingir uma garantia que não existe.
"""

from __future__ import annotations

import threading
import time

from vault.core.crypto import KEY_SIZE, wipe
from vault.exceptions import SessionExpiredError


class VaultSession:
    """Detém a chave de criptografia por tempo limitado."""

    def __init__(self, key: bytes, timeout_seconds: int) -> None:
        if len(key) != KEY_SIZE:
            raise ValueError(f"chave deve ter {KEY_SIZE} bytes, tem {len(key)}")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds deve ser positivo")

        self._key: bytearray | None = bytearray(key)
        self._timeout = timeout_seconds
        self._last_used = time.monotonic()
        self._lock = threading.Lock()

    @property
    def timeout_seconds(self) -> int:
        return self._timeout

    @property
    def locked(self) -> bool:
        """`True` se a chave já não está disponível (expirou ou foi descartada)."""
        with self._lock:
            return self._key is None or self._expired_unlocked()

    def seconds_remaining(self) -> float:
        """Quanto falta para expirar. `0.0` se já expirou."""
        with self._lock:
            if self._key is None:
                return 0.0
            restante = self._timeout - (time.monotonic() - self._last_used)
            return max(0.0, restante)

    def key(self) -> bytes:
        """A chave, renovando o relógio de inatividade.

        Levanta `SessionExpiredError` se o prazo passou — e, nesse caso, já
        descarta a chave, para que uma segunda chamada não a devolva.
        """
        with self._lock:
            if self._key is None:
                raise SessionExpiredError(
                    "Sessão encerrada. Destrave o vault novamente."
                )
            if self._expired_unlocked():
                self._wipe_unlocked()
                raise SessionExpiredError(
                    f"Sessão expirou após {self._timeout}s de inatividade. "
                    "Destrave o vault novamente."
                )
            self._last_used = time.monotonic()
            return bytes(self._key)

    def touch(self) -> None:
        """Renova o relógio sem ler a chave (atividade de interface)."""
        with self._lock:
            if self._key is not None and not self._expired_unlocked():
                self._last_used = time.monotonic()

    def lock(self) -> None:
        """Descarta a chave imediatamente. Idempotente."""
        with self._lock:
            self._wipe_unlocked()

    # -- internos: só chamar com o lock tomado ------------------------------

    def _expired_unlocked(self) -> bool:
        return (time.monotonic() - self._last_used) >= self._timeout

    def _wipe_unlocked(self) -> None:
        if self._key is not None:
            wipe(self._key)
            self._key = None

    # -- protocolo de context manager --------------------------------------

    def __enter__(self) -> VaultSession:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.lock()

    def __repr__(self) -> str:  # pragma: no cover - conveniência de debug
        estado = "trancada" if self.locked else f"{self.seconds_remaining():.0f}s restantes"
        return f"<VaultSession {estado}>"
