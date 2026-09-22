"""Testes da derivação de chave."""

from __future__ import annotations

import unicodedata

import pytest
from argon2.low_level import Type, hash_secret_raw

from vault.core.kdf import (
    KdfParams,
    derive_encryption_key,
    generate_salt,
    normalize_password,
)
from vault.exceptions import ConfigurationError

BARATO = KdfParams(time_cost=1, memory_cost=8, parallelism=1)
SALT = b"\x00" * 16


def test_derivacao_e_deterministica() -> None:
    a = derive_encryption_key("senha", SALT, BARATO)
    b = derive_encryption_key("senha", SALT, BARATO)
    assert a == b
    assert len(a) == 32


def test_salts_diferentes_dao_chaves_diferentes() -> None:
    a = derive_encryption_key("senha", generate_salt(), BARATO)
    b = derive_encryption_key("senha", generate_salt(), BARATO)
    assert a != b


def test_senhas_diferentes_dao_chaves_diferentes() -> None:
    assert derive_encryption_key("senha-a", SALT, BARATO) != derive_encryption_key(
        "senha-b", SALT, BARATO
    )


def test_parametros_diferentes_dao_chaves_diferentes() -> None:
    """Este é o motivo de os parâmetros serem persistidos junto do vault.

    Mudar o custo do KDF muda a chave. Se os parâmetros vivessem no código, subir
    o custo tornaria todo vault existente ilegível — sem nenhum aviso.
    """
    outros = KdfParams(time_cost=2, memory_cost=8, parallelism=1)
    assert derive_encryption_key("senha", SALT, BARATO) != derive_encryption_key(
        "senha", SALT, outros
    )


def test_chave_nao_e_a_saida_crua_do_argon2() -> None:
    """Separação de domínio: o HKDF tem de estar no caminho.

    Se a chave fosse a saída direta do Argon2 com o salt do vault, qualquer erro
    futuro que reaproveitasse esse salt no hash de autenticação faria o hash
    armazenado *ser* a chave de criptografia.
    """
    cru = hash_secret_raw(
        secret=normalize_password("senha"),
        salt=SALT,
        time_cost=BARATO.time_cost,
        memory_cost=BARATO.memory_cost,
        parallelism=BARATO.parallelism,
        hash_len=32,
        type=Type.ID,
    )
    assert derive_encryption_key("senha", SALT, BARATO) != cru


def test_normalizacao_nfc_iguala_formas_unicode() -> None:
    """"café" pré-composto e decomposto têm de gerar a MESMA chave."""
    composto = unicodedata.normalize("NFC", "café")
    decomposto = unicodedata.normalize("NFD", "café")
    assert composto != decomposto  # são strings diferentes...
    assert normalize_password(composto) == normalize_password(decomposto)
    assert derive_encryption_key(composto, SALT, BARATO) == derive_encryption_key(
        decomposto, SALT, BARATO
    )


def test_salt_tem_16_bytes_e_e_aleatorio() -> None:
    salts = {generate_salt() for _ in range(200)}
    assert len(salts) == 200
    assert all(len(s) == 16 for s in salts)


def test_salt_curto_e_rejeitado() -> None:
    with pytest.raises(ConfigurationError, match="Salt curto"):
        derive_encryption_key("senha", b"123", BARATO)


def test_algoritmo_desconhecido_e_rejeitado() -> None:
    with pytest.raises(ConfigurationError, match="não suportado"):
        KdfParams(algorithm="scrypt")


def test_hash_len_diferente_de_32_e_rejeitado() -> None:
    with pytest.raises(ConfigurationError, match="hash_len"):
        KdfParams(hash_len=16)


@pytest.mark.parametrize("campo", ["time_cost", "memory_cost", "parallelism"])
def test_parametro_nao_positivo_e_rejeitado(campo: str) -> None:
    with pytest.raises(ConfigurationError, match=campo):
        KdfParams(**{campo: 0})


def test_from_settings_usa_os_padroes_sem_env() -> None:
    params = KdfParams.from_settings()
    assert params.algorithm == "argon2id"
    assert params.memory_cost == 65536
    assert params.hash_len == 32


@pytest.mark.slow
def test_custo_real_de_producao_funciona() -> None:
    """Os parâmetros que vão para produção precisam de prova, não só os baratos."""
    params = KdfParams.from_settings()
    chave = derive_encryption_key("senha-de-producao", generate_salt(), params)
    assert len(chave) == 32
