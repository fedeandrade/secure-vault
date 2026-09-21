"""Schema de dados para a arquitetura Zero-Knowledge do vault.

Este módulo define a estrutura de dados das credenciais que é empacotada,
serializada em JSON e criptografada como um único blob autenticado antes de ser
armazenada no banco de dados.

Vantagens:
- Zero-Knowledge: O servidor/banco não tem visibilidade de nomes de serviço,
  logins, URLs, notas ou segredos.
- Histórico de senhas: Cada credencial pode manter um histórico de senhas antigas
  com carimbo de data/hora (ISO 8601).
- Evolução de schema simplificada: Novos campos opcionais podem ser adicionados ao
  payload sem requerer migrações estruturais pesadas em colunas individuais.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class PasswordHistoryItem:
    """Item do histórico de alterações de senha."""

    password: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def __post_init__(self) -> None:
        if isinstance(self.created_at, datetime):
            self.created_at = self.created_at.isoformat()


@dataclass
class CredentialPayload:
    """Payload completo de uma credencial protegida por Zero-Knowledge."""

    service_name: str
    login: str
    password: str
    url: str | None = None
    notes: str | None = None
    totp_secret: str | None = None
    history: list[PasswordHistoryItem] = field(default_factory=list)


class PayloadSerializer:
    """Serializador e desserializador para JSON bytes de CredentialPayload."""

    @staticmethod
    def dump(payload: CredentialPayload) -> bytes:
        """Serializa o payload para bytes em formato JSON (UTF-8)."""
        data_dict = asdict(payload)
        return json.dumps(data_dict, ensure_ascii=False).encode("utf-8")

    @staticmethod
    def load(data: bytes | str) -> CredentialPayload:
        """Desserializa bytes ou string JSON para uma instância de CredentialPayload."""
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        raw: dict[str, Any] = json.loads(text)
        if "history" in raw and isinstance(raw["history"], list):
            raw["history"] = [
                PasswordHistoryItem(**item) if isinstance(item, dict) else item
                for item in raw["history"]
            ]
        return CredentialPayload(**raw)
