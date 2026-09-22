"""Testes para o modelo Credential atualizado para arquitetura Zero-Knowledge."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from vault.db.models import Credential


def test_credential_model_instantiation() -> None:
    """Verifica instanciação do modelo com os novos campos Zero-Knowledge."""
    cred = Credential(encrypted_data=b"opaque_ciphertext_blob", deleted_at=None)
    assert cred.encrypted_data == b"opaque_ciphertext_blob"
    assert cred.deleted_at is None
    assert "deleted=False" in repr(cred)


def test_credential_model_removed_legacy_attributes() -> None:
    """Garante que atributos legíveis legados foram removidos do modelo."""
    cred = Credential(encrypted_data=b"blob")
    assert not hasattr(cred, "service_name")
    assert not hasattr(cred, "login")
    assert not hasattr(cred, "url")
    assert not hasattr(cred, "encrypted_password")
    assert not hasattr(cred, "encrypted_notes")
    assert not hasattr(cred, "encrypted_totp_secret")
    assert not hasattr(cred, "has_totp")


def test_credential_persistence_roundtrip(session: Session) -> None:
    """Verifica persistência e recuperação do Credential no banco de dados."""
    cred = Credential(encrypted_data=b"segredo_cifrado_bytes")
    session.add(cred)
    session.flush()

    assert cred.id is not None
    assert cred.created_at is not None
    assert cred.updated_at is not None
    assert cred.deleted_at is None

    # Consulta do banco
    saved = session.scalar(select(Credential).where(Credential.id == cred.id))
    assert saved is not None
    assert saved.encrypted_data == b"segredo_cifrado_bytes"
    assert saved.deleted_at is None


def test_credential_soft_delete(session: Session) -> None:
    """Verifica preenchimento de deleted_at para soft delete."""
    now = datetime.now(UTC)
    cred = Credential(encrypted_data=b"segredo_cifrado_bytes", deleted_at=now)
    session.add(cred)
    session.flush()

    saved = session.scalar(select(Credential).where(Credential.id == cred.id))
    assert saved is not None
    assert saved.deleted_at is not None
    assert "deleted=True" in repr(saved)
