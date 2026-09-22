"""Modelos SQLAlchemy.

Regra que vale para o schema inteiro: **nada em texto puro que seja segredo.**
Toda coluna que guarda segredo é `LargeBinary` e recebe um blob de
`vault.core.crypto`. Na arquitetura Zero-Knowledge, as credenciais têm todos
os seus campos e metadados cifrados em um único blob opaco (`encrypted_data`),
e suportam exclusão lógica via `deleted_at`.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    LargeBinary,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from vault.db.base import Base

#: Único id permitido na tabela de configuração. Ver `VaultConfig`.
VAULT_CONFIG_ID = 1


class VaultConfig(Base):
    """Configuração do vault. A tabela tem, no máximo, **uma** linha.

    A unicidade é imposta pelo banco (`CHECK (id = 1)`), não pela aplicação. A
    versão anterior lia essa linha com `scalar_one()`, que estoura com
    `MultipleResultsFound` se por qualquer caminho aparecer uma segunda —
    duas execuções concorrentes de `create_vault`, um restore parcial, um insert
    manual. Restrição no schema resolve na origem: a segunda linha simplesmente
    não entra.
    """

    __tablename__ = "vault_config"
    __table_args__ = (CheckConstraint("id = 1", name="ck_vault_config_singleton"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=False)

    master_password_hash: Mapped[str] = mapped_column(String(255))
    """Hash Argon2id da senha mestra (formato PHC, com salt próprio embutido)."""

    salt: Mapped[bytes] = mapped_column(LargeBinary)
    """Salt do KDF da chave de criptografia. Diferente do salt do hash acima."""

    kdf_algorithm: Mapped[str] = mapped_column(
        String(32), server_default="argon2id", default="argon2id"
    )
    kdf_time_cost: Mapped[int] = mapped_column(server_default="3", default=3)
    kdf_memory_cost: Mapped[int] = mapped_column(server_default="65536", default=65536)
    kdf_parallelism: Mapped[int] = mapped_column(server_default="4", default=4)
    kdf_hash_len: Mapped[int] = mapped_column(server_default="32", default=32)
    """Parâmetros usados para derivar a chave DESTE vault. Ver `vault.core.kdf`."""

    key_check: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    """Sentinela cifrada: prova que a chave derivada abre este vault."""

    totp_secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    """Segredo TOTP do segundo fator da senha mestra (Fase 10). Cifrado."""

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    @property
    def totp_enabled(self) -> bool:
        return self.totp_secret_encrypted is not None

    def __repr__(self) -> str:  # pragma: no cover - conveniência de debug
        return f"<VaultConfig id={self.id} kdf={self.kdf_algorithm} totp={self.totp_enabled}>"


class Credential(Base):
    """Uma credencial guardada como blob cifrado opaco (Zero-Knowledge).

    Na arquitetura Zero-Knowledge, nenhum metadado (serviço, login, url) fica em
    texto claro no banco de dados. Todo o payload da credencial é cifrado e
    armazenado na coluna `encrypted_data`. A exclusão é lógica via `deleted_at`.
    """

    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(primary_key=True)

    encrypted_data: Mapped[bytes] = mapped_column(LargeBinary)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - conveniência de debug
        return f"<Credential id={self.id} deleted={self.deleted_at is not None}>"
