"""Derivação da chave de criptografia a partir da senha mestra.

Três decisões que valem explicação, porque cada uma corrige um jeito real de
perder o vault ou de enfraquecê-lo:

1. **Os parâmetros do Argon2id são persistidos junto do vault**, não fixados no
   código. Antes, `derive_encryption_key` tinha `time_cost=3, memory_cost=65536`
   escritos na função. No dia em que alguém subisse esses números para endurecer
   o KDF, todo vault já existente passaria a derivar uma chave diferente e os
   dados ficariam ilegíveis — sem nenhuma mensagem de erro dizendo por quê. Com
   os parâmetros gravados no banco, um vault antigo continua abrindo com os
   parâmetros dele e um vault novo nasce com os parâmetros novos.

2. **Separação de domínio via HKDF.** A senha mestra alimenta dois usos: o hash
   de autenticação e a chave de criptografia. Eles usam salts diferentes, o que
   já basta para não serem iguais — mas "não são iguais por acidente do salt" é
   uma garantia frágil. Passar a saída do Argon2 por um HKDF com um rótulo fixo
   (`info=`) torna a separação explícita e sobreviveria até a um erro futuro de
   alguém reaproveitar o mesmo salt.

3. **Normalização Unicode NFC.** "café" digitado num Mac (e + acento combinante)
   e num Windows (é pré-composto) são strings diferentes com os mesmos bytes na
   tela e bytes UTF-8 distintos — ou seja, chaves distintas. Normalizar antes de
   codificar elimina a classe inteira de "minha senha está certa e não abre".
"""

from __future__ import annotations

import secrets
import unicodedata
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vault.config.settings import (
    DEFAULT_KDF_HASH_LEN,
    DEFAULT_KDF_MEMORY_COST,
    DEFAULT_KDF_PARALLELISM,
    DEFAULT_KDF_TIME_COST,
    get_settings,
)
from vault.exceptions import ConfigurationError

#: Rótulo de separação de domínio. Mudar esta constante invalida todos os vaults
#: existentes — se algum dia for preciso, faça com um número de versão novo e
#: uma rotina de rotação, nunca editando este valor no lugar.
_ENCRYPTION_KEY_INFO = b"secure-vault:encryption-key:v1"

#: Tamanho do salt do KDF. 16 bytes é o mínimo recomendado pelo RFC 9106.
SALT_SIZE = 16

SUPPORTED_ALGORITHMS = frozenset({"argon2id"})


@dataclass(frozen=True, slots=True)
class KdfParams:
    """Parâmetros de derivação. Gravados no vault para poder abri-lo no futuro."""

    algorithm: str = "argon2id"
    time_cost: int = DEFAULT_KDF_TIME_COST
    memory_cost: int = DEFAULT_KDF_MEMORY_COST
    parallelism: int = DEFAULT_KDF_PARALLELISM
    hash_len: int = DEFAULT_KDF_HASH_LEN

    def __post_init__(self) -> None:
        if self.algorithm not in SUPPORTED_ALGORITHMS:
            raise ConfigurationError(
                f"Algoritmo de KDF não suportado: {self.algorithm!r}. "
                f"Suportados: {', '.join(sorted(SUPPORTED_ALGORITHMS))}."
            )
        if self.hash_len != 32:
            # AES-256-GCM exige exatamente 256 bits. Aceitar outro tamanho aqui
            # só adiaria o erro para dentro da biblioteca de criptografia.
            raise ConfigurationError(
                f"hash_len precisa ser 32 (AES-256), recebido {self.hash_len}."
            )
        for name in ("time_cost", "memory_cost", "parallelism"):
            if getattr(self, name) < 1:
                raise ConfigurationError(f"{name} precisa ser >= 1.")

    @classmethod
    def from_settings(cls) -> KdfParams:
        """Parâmetros para um vault **novo**, vindos da configuração."""
        settings = get_settings()
        return cls(
            algorithm=settings.kdf_algorithm.lower(),
            time_cost=settings.kdf_time_cost,
            memory_cost=settings.kdf_memory_cost,
            parallelism=settings.kdf_parallelism,
            hash_len=DEFAULT_KDF_HASH_LEN,
        )


def generate_salt(size: int = SALT_SIZE) -> bytes:
    """Salt aleatório de um CSPRNG (`secrets`, nunca `random`)."""
    return secrets.token_bytes(size)


def normalize_password(password: str) -> bytes:
    """Normaliza (NFC) e codifica a senha em UTF-8. Ver decisão 3 no topo."""
    return unicodedata.normalize("NFC", password).encode("utf-8")


def derive_encryption_key(password: str, salt: bytes, params: KdfParams) -> bytes:
    """Deriva a chave AES-256 da senha mestra. Nunca é persistida em disco."""
    if len(salt) < 8:
        raise ConfigurationError(
            f"Salt curto demais ({len(salt)} bytes); mínimo 8, esperado {SALT_SIZE}."
        )

    raw = hash_secret_raw(
        secret=normalize_password(password),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=params.hash_len,
        type=Type.ID,
    )

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_ENCRYPTION_KEY_INFO,
    ).derive(raw)
