"""Criptografia simétrica dos segredos guardados no vault.

Escolha: **AES-256-GCM**, da biblioteca `cryptography`.

Por que GCM e não Fernet (que também estava na mesa):

- Fernet é AES-128-CBC + HMAC-SHA256. Funciona, mas usa só 128 bits da nossa
  chave de 256 e obriga a re-codificar a chave em base64.
- GCM é AEAD nativo: autenticação e cifragem no mesmo passo, com *associated
  data* — dá para amarrar o texto cifrado ao contexto em que ele nasceu. Um blob
  copiado da coluna `encrypted_password` para a coluna `encrypted_notes` no banco
  falha na abertura, porque o AAD não bate.

Formato do blob gravado no banco:

    [1 byte versão][12 bytes nonce][ciphertext + tag de 16 bytes]

O byte de versão existe para permitir trocar de algoritmo no futuro sem
adivinhação: um blob antigo se identifica sozinho. Sem ele, migrar de cifra vira
tentativa e erro sobre dados que ninguém consegue ler.

O nonce é sorteado por `secrets.token_bytes` a **cada** operação de cifragem —
nunca reaproveitado entre registros nem entre atualizações do mesmo registro.
Reusar nonce em GCM não vaza só um valor: permite recuperar a chave de
autenticação. É a falha mais séria possível neste modo, e por isso ela é
verificada por teste (`test_crypto.py::test_nonce_nunca_se_repete`).
"""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault.exceptions import DecryptionError

#: Versão do formato do blob. Incrementar ao mudar algoritmo ou layout.
BLOB_VERSION = 1

NONCE_SIZE = 12  # 96 bits: tamanho recomendado pelo NIST SP 800-38D para GCM
TAG_SIZE = 16
KEY_SIZE = 32  # AES-256

#: Rótulos de *associated data*. Amarram cada texto cifrado ao campo de origem.
#:
#: Na arquitetura Zero-Knowledge a credencial inteira vira **um** blob, cifrado
#: sob `AAD_CREDENTIAL`. `AAD_MASTER_TOTP` e `AAD_KEY_CHECK` seguem em uso pelo
#: `vault_config`.
#:
#: ⚠️ `AAD_PASSWORD`, `AAD_NOTES` e `AAD_TOTP` **não são mais usados em produção**
#: — nenhum código em `src/` os referencia desde a migration `edb62ca16834`.
#: Sobrevivem por dois motivos, e nenhum deles é compatibilidade: (1) a migration
#: **recusa** converter vault populado, então não existe dado legado alcançável
#: por este código; (2) `tests/unit/test_crypto.py` precisa de dois rótulos
#: distintos para provar que decifrar com o AAD errado falha — que é a garantia
#: central do AEAD.
#:
#: **Nunca reaproveite um `:v1` para significado novo; crie `:v2`.** Trocar o
#: sentido de um rótulo torna indecifrável todo texto cifrado sob ele.
AAD_CREDENTIAL = b"secure-vault:credential.payload:v1"
AAD_PASSWORD = b"secure-vault:credential.password:v1"
AAD_NOTES = b"secure-vault:credential.notes:v1"
AAD_TOTP = b"secure-vault:credential.totp:v1"
AAD_MASTER_TOTP = b"secure-vault:vault.totp:v1"
AAD_KEY_CHECK = b"secure-vault:vault.key_check:v1"

#: Texto conhecido cifrado na criação do vault. Serve para provar, antes de
#: tentar abrir qualquer dado real, que a chave derivada é a chave certa.
KEY_CHECK_PLAINTEXT = "secure-vault-key-check"


def _validate_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError(f"chave deve ser bytes, recebido {type(key).__name__}")
    if len(key) != KEY_SIZE:
        raise DecryptionError(
            f"Chave com tamanho inválido: {len(key)} bytes, esperado {KEY_SIZE}."
        )


def encrypt(key: bytes, plaintext: str, *, aad: bytes) -> bytes:
    """Cifra `plaintext` com `key`, devolvendo o blob versionado."""
    _validate_key(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = AESGCM(bytes(key)).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return bytes([BLOB_VERSION]) + nonce + ciphertext


def decrypt(key: bytes, blob: bytes, *, aad: bytes) -> str:
    """Abre um blob produzido por `encrypt`.

    Levanta `DecryptionError` para qualquer falha — chave errada, dado adulterado,
    blob truncado ou versão desconhecida. A mensagem nunca diferencia "chave
    errada" de "dado corrompido" para o atacante, mas diferencia o suficiente
    para o usuário legítimo saber o que fazer.
    """
    _validate_key(key)

    if not blob:
        raise DecryptionError("Texto cifrado vazio no banco.")

    minimo = 1 + NONCE_SIZE + TAG_SIZE
    if len(blob) < minimo:
        raise DecryptionError(
            f"Texto cifrado truncado: {len(blob)} bytes, mínimo {minimo}."
        )

    version = blob[0]
    if version != BLOB_VERSION:
        raise DecryptionError(
            f"Versão de formato desconhecida: {version}. "
            f"Esta build entende a versão {BLOB_VERSION}. "
            "O banco foi escrito por uma versão mais nova do Secure Vault?"
        )

    nonce = blob[1 : 1 + NONCE_SIZE]
    ciphertext = blob[1 + NONCE_SIZE :]

    try:
        plaintext = AESGCM(bytes(key)).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "Não foi possível decifrar: a chave não corresponde a este dado, "
            "ou o registro foi alterado por fora da aplicação."
        ) from exc

    return plaintext.decode("utf-8")


def encrypt_optional(key: bytes, plaintext: str | None, *, aad: bytes) -> bytes | None:
    """Como `encrypt`, mas propaga `None` (campos opcionais como notas e TOTP)."""
    if plaintext is None or plaintext == "":
        return None
    return encrypt(key, plaintext, aad=aad)


def decrypt_optional(key: bytes, blob: bytes | None, *, aad: bytes) -> str | None:
    """Como `decrypt`, mas propaga `None`."""
    if blob is None:
        return None
    return decrypt(key, blob, aad=aad)


def build_key_check(key: bytes) -> bytes:
    """Cifra o texto-sentinela; guardado no vault na criação."""
    return encrypt(key, KEY_CHECK_PLAINTEXT, aad=AAD_KEY_CHECK)


def verify_key_check(key: bytes, blob: bytes) -> bool:
    """Confere se `key` é a chave deste vault, sem tocar em dado real.

    Exige a sentinela. A primeira versão aceitava `blob=None` e devolvia `True`
    — "não há o que verificar" — e isso abria um buraco sério: bastava a coluna
    `key_check` sumir (o `downgrade` do Alembic a derruba) para que `unlock`
    voltasse a aceitar como boa qualquer chave derivada. A ausência da sentinela
    é uma decisão da chamadora, tomada com contexto, e não um `True` silencioso
    aqui dentro.
    """
    if blob is None:
        raise ValueError(
            "verify_key_check exige a sentinela; trate a ausência na chamadora."
        )
    try:
        return decrypt(key, blob, aad=AAD_KEY_CHECK) == KEY_CHECK_PLAINTEXT
    except DecryptionError:
        return False


def wipe(buffer: bytearray) -> None:
    """Sobrescreve um `bytearray` com zeros.

    Limitação honesta: em CPython isto reduz a janela de exposição, mas **não**
    garante que a chave sumiu da memória — o interpretador pode ter feito cópias
    (realocação, string intermediária) fora do nosso alcance, e a página pode ter
    ido para o swap. Proteção real contra memory dumping está declarada como fora
    de escopo no README.
    """
    for i in range(len(buffer)):
        buffer[i] = 0
