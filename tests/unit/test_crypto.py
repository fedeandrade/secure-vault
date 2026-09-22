"""Testes da camada de criptografia.

O teste mais importante do arquivo é `test_nonce_nunca_se_repete`. Reuso de nonce
em AES-GCM não vaza só um texto: permite recuperar a chave de autenticação e
forjar mensagens. É a falha mais séria possível neste modo de operação, e o tipo
de coisa que uma refatoração distraída reintroduz (trocar `secrets.token_bytes`
por um nonce "derivado do id" para economizar bytes, por exemplo).
"""

from __future__ import annotations

import secrets

import pytest

from vault.core import crypto
from vault.exceptions import DecryptionError

CHAVE = b"\x01" * 32
OUTRA_CHAVE = b"\x02" * 32


def test_roundtrip_preserva_o_texto() -> None:
    blob = crypto.encrypt(CHAVE, "senha secreta", aad=crypto.AAD_PASSWORD)
    assert crypto.decrypt(CHAVE, blob, aad=crypto.AAD_PASSWORD) == "senha secreta"


@pytest.mark.parametrize(
    "texto",
    [
        "",
        "a",
        "senha com espaços",
        "acentuação: ção, ü, ñ",
        "emoji 🔐 e símbolos !@#$%^&*()",
        "x" * 10_000,
        "linha1\nlinha2\ttab",
    ],
)
def test_roundtrip_com_qualquer_unicode(texto: str) -> None:
    blob = crypto.encrypt(CHAVE, texto, aad=crypto.AAD_NOTES)
    assert crypto.decrypt(CHAVE, blob, aad=crypto.AAD_NOTES) == texto


def test_texto_cifrado_nao_contem_o_texto_puro() -> None:
    blob = crypto.encrypt(CHAVE, "senha-que-nao-pode-vazar", aad=crypto.AAD_PASSWORD)
    assert b"senha-que-nao-pode-vazar" not in blob


def test_nonce_nunca_se_repete() -> None:
    """Cifrar o MESMO texto com a MESMA chave produz blobs distintos.

    Se esta asserção cair, o nonce virou determinístico e a segurança do GCM
    desabou — não é um detalhe estético.
    """
    blobs = {
        crypto.encrypt(CHAVE, "mesmo texto", aad=crypto.AAD_PASSWORD)
        for _ in range(500)
    }
    assert len(blobs) == 500

    nonces = {blob[1 : 1 + crypto.NONCE_SIZE] for blob in blobs}
    assert len(nonces) == 500


def test_chave_errada_nao_abre() -> None:
    blob = crypto.encrypt(CHAVE, "segredo", aad=crypto.AAD_PASSWORD)
    with pytest.raises(DecryptionError):
        crypto.decrypt(OUTRA_CHAVE, blob, aad=crypto.AAD_PASSWORD)


def test_aad_diferente_nao_abre() -> None:
    """Blob movido de um campo para outro é rejeitado (é o que o AAD garante)."""
    blob = crypto.encrypt(CHAVE, "segredo", aad=crypto.AAD_PASSWORD)
    with pytest.raises(DecryptionError):
        crypto.decrypt(CHAVE, blob, aad=crypto.AAD_NOTES)


@pytest.mark.parametrize("posicao", [0, 1, 5, 13, 20, -1])
def test_qualquer_bit_alterado_e_detectado(posicao: int) -> None:
    blob = bytearray(crypto.encrypt(CHAVE, "conteúdo íntegro", aad=crypto.AAD_PASSWORD))
    blob[posicao] ^= 0x01
    with pytest.raises(DecryptionError):
        crypto.decrypt(CHAVE, bytes(blob), aad=crypto.AAD_PASSWORD)


def test_blob_truncado_e_detectado() -> None:
    blob = crypto.encrypt(CHAVE, "segredo", aad=crypto.AAD_PASSWORD)
    with pytest.raises(DecryptionError, match="truncado"):
        crypto.decrypt(CHAVE, blob[:10], aad=crypto.AAD_PASSWORD)


def test_blob_vazio_e_detectado() -> None:
    with pytest.raises(DecryptionError, match="vazio"):
        crypto.decrypt(CHAVE, b"", aad=crypto.AAD_PASSWORD)


def test_versao_desconhecida_da_mensagem_util() -> None:
    blob = bytearray(crypto.encrypt(CHAVE, "segredo", aad=crypto.AAD_PASSWORD))
    blob[0] = 99
    with pytest.raises(DecryptionError, match="Versão de formato desconhecida"):
        crypto.decrypt(CHAVE, bytes(blob), aad=crypto.AAD_PASSWORD)


def test_blob_carrega_o_byte_de_versao() -> None:
    blob = crypto.encrypt(CHAVE, "x", aad=crypto.AAD_PASSWORD)
    assert blob[0] == crypto.BLOB_VERSION


@pytest.mark.parametrize("tamanho", [0, 16, 31, 33, 64])
def test_chave_de_tamanho_errado_e_rejeitada(tamanho: int) -> None:
    with pytest.raises(DecryptionError, match="tamanho inválido"):
        crypto.encrypt(secrets.token_bytes(tamanho), "x", aad=crypto.AAD_PASSWORD)


def test_campos_opcionais_propagam_none() -> None:
    assert crypto.encrypt_optional(CHAVE, None, aad=crypto.AAD_NOTES) is None
    assert crypto.encrypt_optional(CHAVE, "", aad=crypto.AAD_NOTES) is None
    assert crypto.decrypt_optional(CHAVE, None, aad=crypto.AAD_NOTES) is None


def test_key_check_aceita_a_chave_certa_e_recusa_a_errada() -> None:
    sentinela = crypto.build_key_check(CHAVE)
    assert crypto.verify_key_check(CHAVE, sentinela) is True
    assert crypto.verify_key_check(OUTRA_CHAVE, sentinela) is False


def test_key_check_ausente_e_erro_de_programacao() -> None:
    """A ausência da sentinela é decisão da chamadora, não um `True` aqui dentro.

    A primeira versão devolvia `True` para `blob=None` ("não há o que verificar").
    Isso significava que bastava a coluna `key_check` sumir — o `downgrade` do
    Alembic a derruba — para `unlock` voltar a aceitar qualquer chave derivada.
    Ver `tests/integration/test_regressao_revisao.py`.
    """
    with pytest.raises(ValueError, match="exige a sentinela"):
        crypto.verify_key_check(CHAVE, None)


def test_wipe_zera_o_buffer() -> None:
    buffer = bytearray(b"segredo em memoria")
    crypto.wipe(buffer)
    assert set(buffer) == {0}
