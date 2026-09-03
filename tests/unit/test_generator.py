"""Testes do gerador de senhas."""

from __future__ import annotations

import math
import re

import pytest

from vault.core.generator import (
    AMBIGUOUS,
    DIGITS,
    LOWERCASE,
    SYMBOLS,
    UPPERCASE,
    PasswordPolicy,
    PasswordPolicyError,
    entropy_bits,
    generate_password,
    generate_with_entropy,
)


@pytest.mark.parametrize("tamanho", [4, 8, 16, 20, 64, 128])
def test_respeita_o_comprimento(tamanho: int) -> None:
    assert len(generate_password(PasswordPolicy(length=tamanho))) == tamanho


def test_padrao_contem_uma_de_cada_classe() -> None:
    for _ in range(50):
        senha = generate_password()
        assert any(c in LOWERCASE for c in senha)
        assert any(c in UPPERCASE for c in senha)
        assert any(c in DIGITS for c in senha)
        assert any(c in SYMBOLS for c in senha)


def test_classes_desligadas_nao_aparecem() -> None:
    politica = PasswordPolicy(length=40, use_symbols=False, use_digits=False)
    for _ in range(50):
        senha = generate_password(politica)
        assert not any(c in SYMBOLS for c in senha)
        assert not any(c in DIGITS for c in senha)


def test_apenas_digitos_gera_pin() -> None:
    senha = generate_password(
        PasswordPolicy(
            length=6, use_lowercase=False, use_uppercase=False, use_symbols=False
        )
    )
    assert re.fullmatch(r"\d{6}", senha)


def test_excluir_ambiguos_realmente_exclui() -> None:
    politica = PasswordPolicy(length=60, exclude_ambiguous=True)
    for _ in range(30):
        senha = generate_password(politica)
        assert not set(senha) & set(AMBIGUOUS)


def test_senhas_geradas_nao_se_repetem() -> None:
    """Prova prática de que a fonte é aleatória de verdade."""
    senhas = {generate_password(PasswordPolicy(length=20)) for _ in range(500)}
    assert len(senhas) == 500


def test_distribuicao_cobre_o_alfabeto() -> None:
    """Detecta um gerador enviesado (ex.: que sempre põe o símbolo no fim).

    Com 4000 caracteres sorteados de um alfabeto de ~85, ver menos de 60 símbolos
    distintos seria um indício forte de viés.
    """
    amostra = "".join(generate_password(PasswordPolicy(length=40)) for _ in range(100))
    assert len(set(amostra)) >= 60


def test_nenhuma_posicao_e_previsivel() -> None:
    """Se o gerador fixasse classes por posição, a primeira letra seria sempre igual."""
    primeiros = {generate_password(PasswordPolicy(length=12))[0] for _ in range(300)}
    assert len(primeiros) > 20


def test_entropia_bate_com_a_formula() -> None:
    politica = PasswordPolicy(length=20)
    tamanho_alfabeto = len(set(politica.alphabet()))
    _, bits = generate_with_entropy(politica)
    assert bits == pytest.approx(20 * math.log2(tamanho_alfabeto))


def test_entropia_de_alfabeto_degenerado_e_zero() -> None:
    assert entropy_bits(1, 20) == 0.0
    assert entropy_bits(64, 0) == 0.0


def test_sem_nenhuma_classe_e_erro_claro() -> None:
    politica = PasswordPolicy(
        use_lowercase=False, use_uppercase=False, use_digits=False, use_symbols=False
    )
    with pytest.raises(PasswordPolicyError, match="Nenhum conjunto"):
        generate_password(politica)


@pytest.mark.parametrize("tamanho", [0, 1, 3, 513, -5])
def test_comprimento_fora_da_faixa_e_erro(tamanho: int) -> None:
    with pytest.raises(PasswordPolicyError, match="Comprimento"):
        generate_password(PasswordPolicy(length=tamanho))


def test_comprimento_menor_que_as_classes_exigidas_e_erro() -> None:
    """Comprimento 4 não cabe 4 classes... cabe. Comprimento 4 com 5 não caberia.

    Como só existem 4 classes, o caso real é o comprimento mínimo: verificamos
    que a validação existe e é acionada por um comprimento abaixo do mínimo.
    """
    with pytest.raises(PasswordPolicyError):
        generate_password(PasswordPolicy(length=3))


def test_politica_e_imutavel() -> None:
    politica = PasswordPolicy()
    with pytest.raises(AttributeError):
        politica.length = 99  # type: ignore[misc]
