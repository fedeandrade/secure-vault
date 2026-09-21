"""Testes unitários para o schema de dados Zero-Knowledge e serialização."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from vault.core.schema import CredentialPayload, PasswordHistoryItem, PayloadSerializer


def test_payload_serialization() -> None:
    payload = CredentialPayload(
        service_name="github",
        login="renan",
        password="secure",
        url="https://github.com",
        notes="Conta principal",
        totp_secret="JBSWY3DPEHPK3PXP",
        history=[
            PasswordHistoryItem(password="old_pass_1", created_at=datetime.now(UTC)),
            PasswordHistoryItem(password="old_pass_2", created_at="2026-01-01T00:00:00+00:00"),
        ],
    )
    data_bytes = PayloadSerializer.dump(payload)
    assert isinstance(data_bytes, bytes)

    loaded = PayloadSerializer.load(data_bytes)
    assert loaded.service_name == "github"
    assert loaded.login == "renan"
    assert loaded.password == "secure"
    assert loaded.url == "https://github.com"
    assert loaded.notes == "Conta principal"
    assert loaded.totp_secret == "JBSWY3DPEHPK3PXP"
    assert len(loaded.history) == 2
    assert loaded.history[0].password == "old_pass_1"
    assert isinstance(loaded.history[0].created_at, str)
    assert loaded.history[1].password == "old_pass_2"
    assert loaded.history[1].created_at == "2026-01-01T00:00:00+00:00"


def test_payload_serialization_defaults() -> None:
    payload = CredentialPayload(
        service_name="gitlab",
        login="felip",
        password="another_password",
    )
    assert payload.url is None
    assert payload.notes is None
    assert payload.totp_secret is None
    assert payload.history == []

    data_bytes = PayloadSerializer.dump(payload)
    assert isinstance(data_bytes, bytes)

    loaded = PayloadSerializer.load(data_bytes)
    assert loaded.service_name == "gitlab"
    assert loaded.login == "felip"
    assert loaded.password == "another_password"
    assert loaded.url is None
    assert loaded.notes is None
    assert loaded.totp_secret is None
    assert loaded.history == []


def test_password_history_item_datetime_handling() -> None:
    now = datetime(2026, 9, 20, 20, 0, 0, tzinfo=UTC)
    item_from_dt = PasswordHistoryItem(password="pass1", created_at=now)
    assert item_from_dt.created_at == "2026-09-20T20:00:00+00:00"

    item_from_str = PasswordHistoryItem(password="pass2", created_at="2026-09-20T20:00:00")
    assert item_from_str.created_at == "2026-09-20T20:00:00"

    item_default = PasswordHistoryItem(password="pass3")
    assert isinstance(item_default.created_at, str)
    assert "T" in item_default.created_at


def test_payload_serializer_invalid_json() -> None:
    with pytest.raises(json.JSONDecodeError):
        PayloadSerializer.load(b"not-valid-json")
