"""Segundo fator TOTP (RFC 6238), via `pyotp`.

**Nota honesta de modelo de ameaça**, porque é o tipo de coisa que separa um
projeto de portfólio de um teatro de segurança:

O segredo TOTP fica cifrado com a chave derivada da senha mestra. Logo, quem já
tem a senha mestra pode derivar a chave, decifrar o segredo TOTP e gerar códigos
válidos sozinho. **O TOTP aqui não protege os dados contra quem já tem a senha
mestra** — ele protege o *acesso pela aplicação*: alguém que descobriu a senha
mestra (por cima do ombro, keylogger, senha reusada) mas não tem o dispositivo
autenticador não consegue destravar o vault pela CLI ou pela TUI.

Para o segundo fator proteger a *cifra*, o segredo teria de entrar na derivação
da chave — o que quebraria a recuperação e não é o que o RFC 6238 se propõe a
fazer. A limitação está declarada no README em vez de ficar subentendida.
"""

from __future__ import annotations

import base64
import binascii
import math
import secrets
import time

import pyotp

from vault.exceptions import TotpError

#: Janela de tolerância: aceita o código anterior e o próximo (±30 s). Cobre
#: relógio dessincronizado sem abrir a porta para replay de códigos antigos.
VALID_WINDOW = 1

ISSUER = "Secure Vault"


def generate_totp_secret() -> str:
    """Segredo base32 novo (160 bits), do CSPRNG."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def normalize_secret(secret: str) -> str:
    """Normaliza um segredo digitado à mão: sem espaços, maiúsculo, com padding."""
    limpo = secret.strip().replace(" ", "").replace("-", "").upper()
    if not limpo:
        raise TotpError("Segredo TOTP vazio.")
    # base32 exige comprimento múltiplo de 8; app autenticador costuma omitir o '='.
    padding = (-len(limpo)) % 8
    candidato = limpo + ("=" * padding)
    try:
        base64.b32decode(candidato, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise TotpError(
            "Segredo TOTP inválido: não é base32 válido. Copie o segredo exatamente "
            "como o aplicativo autenticador mostra."
        ) from exc
    return candidato


def verify_totp(secret: str, code: str, *, valid_window: int = VALID_WINDOW) -> bool:
    """Confere um código de 6 dígitos contra o segredo.

    `pyotp.TOTP.verify` compara em tempo constante (`hmac.compare_digest`), o que
    evita vazar por timing quantos dígitos iniciais estavam certos.
    """
    codigo = (code or "").strip().replace(" ", "")
    if not codigo.isdigit() or len(codigo) != 6:
        return False
    try:
        return pyotp.TOTP(normalize_secret(secret)).verify(
            codigo, valid_window=valid_window
        )
    except TotpError:
        raise
    except Exception as exc:  # pragma: no cover - defesa contra segredo corrompido
        raise TotpError(f"Falha ao verificar o código TOTP: {exc}") from exc


def current_code(secret: str) -> str:
    """Código válido agora — usado para mostrar o TOTP guardado de uma credencial."""
    return pyotp.TOTP(normalize_secret(secret)).now()


def seconds_remaining(secret: str) -> int:
    """Segundos até o código atual expirar (para a TUI mostrar a contagem).

    Arredonda **para cima**, e nunca devolve zero. Com `int()` — truncamento — um
    instante logo antes da virada do intervalo (`time() % 30 == 29.999`) daria
    `int(0.001) == 0`, e a interface exibiria "0s restantes" para um código que
    ainda é perfeitamente válido. Zero significaria "expirou", que é justamente o
    contrário do estado real. O resultado fica sempre em 1..interval.
    """
    totp = pyotp.TOTP(normalize_secret(secret))
    restante = totp.interval - (time.time() % totp.interval)
    return max(1, math.ceil(restante))


def provisioning_uri(secret: str, account_name: str, issuer: str = ISSUER) -> str:
    """URI `otpauth://` para o QR code do aplicativo autenticador."""
    return pyotp.TOTP(normalize_secret(secret)).provisioning_uri(
        name=account_name, issuer_name=issuer
    )
