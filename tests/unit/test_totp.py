"""Testes do segundo fator."""

from __future__ import annotations

import time

import pyotp
import pytest

from vault.core.totp import (
    current_code,
    generate_totp_secret,
    normalize_secret,
    provisioning_uri,
    seconds_remaining,
    verify_totp,
)
from vault.exceptions import TotpError


def test_segredo_gerado_e_base32_valido_e_unico() -> None:
    segredos = {generate_totp_secret() for _ in range(100)}
    assert len(segredos) == 100
    for segredo in segredos:
        pyotp.TOTP(normalize_secret(segredo))  # não levanta


def test_codigo_atual_e_aceito() -> None:
    segredo = generate_totp_secret()
    assert verify_totp(segredo, current_code(segredo))


def test_codigo_errado_e_recusado() -> None:
    segredo = generate_totp_secret()
    correto = current_code(segredo)
    errado = "000000" if correto != "000000" else "111111"
    assert not verify_totp(segredo, errado)


def test_codigo_de_outro_segredo_e_recusado() -> None:
    a, b = generate_totp_secret(), generate_totp_secret()
    assert not verify_totp(a, current_code(b))


@pytest.mark.parametrize("invalido", ["", "abc", "12345", "1234567", "12 34 56x", None])
def test_formato_invalido_e_recusado_sem_estourar(invalido) -> None:
    assert not verify_totp(generate_totp_secret(), invalido)


def test_codigo_muito_antigo_e_recusado() -> None:
    """Fora da janela de tolerância, o código não vale mais."""
    segredo = generate_totp_secret()
    antigo = pyotp.TOTP(normalize_secret(segredo)).at(time.time() - 300)
    assert not verify_totp(segredo, antigo)


def test_codigo_da_janela_anterior_e_aceito() -> None:
    """Tolerância de +-1 intervalo cobre relogio dessincronizado."""
    segredo = generate_totp_secret()
    anterior = pyotp.TOTP(normalize_secret(segredo)).at(time.time() - 30)
    assert verify_totp(segredo, anterior)


def test_normalizacao_aceita_o_formato_que_o_app_mostra() -> None:
    segredo = generate_totp_secret()
    com_espacos = " ".join(segredo[i : i + 4] for i in range(0, len(segredo), 4))
    assert normalize_secret(com_espacos.lower()) == normalize_secret(segredo)


def test_segredo_invalido_da_erro_de_dominio() -> None:
    with pytest.raises(TotpError, match="base32"):
        normalize_secret("nao-e-base32-!!!")


def test_segredo_vazio_da_erro_de_dominio() -> None:
    with pytest.raises(TotpError, match="vazio"):
        normalize_secret("   ")


def test_uri_de_provisionamento_tem_o_formato_do_padrao() -> None:
    uri = provisioning_uri(generate_totp_secret(), "senha-mestra")
    assert uri.startswith("otpauth://totp/")
    assert "issuer=Secure%20Vault" in uri


def test_segundos_restantes_ficam_na_faixa() -> None:
    """Nunca zero: zero significaria expirado, e o codigo ainda vale."""
    segredo = generate_totp_secret()
    for _ in range(200):  # cobre instantes espalhados dentro do intervalo
        restante = seconds_remaining(segredo)
        assert 1 <= restante <= 30, restante


def test_segundos_restantes_na_borda_do_intervalo(monkeypatch) -> None:
    """O instante exato em que `int()` truncaria para zero."""
    monkeypatch.setattr("vault.core.totp.time.time", lambda: 29.999)
    assert seconds_remaining(generate_totp_secret()) == 1

    monkeypatch.setattr("vault.core.totp.time.time", lambda: 30.0)
    assert seconds_remaining(generate_totp_secret()) == 30
