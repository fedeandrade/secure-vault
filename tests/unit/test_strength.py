"""Testes do medidor de força."""

from __future__ import annotations

import pytest

from vault.core.strength import MIN_ACCEPTABLE_SCORE, evaluate


@pytest.mark.parametrize("ruim", ["123456", "password", "qwerty", "abc123", "senha"])
def test_senhas_de_dicionario_pontuam_baixo(ruim: str) -> None:
    relatorio = evaluate(ruim)
    assert relatorio.score <= 1
    assert not relatorio.acceptable


def test_senha_aleatoria_longa_pontua_alto() -> None:
    relatorio = evaluate("K7#mQ9$vL2@nR5&x")
    assert relatorio.score >= MIN_ACCEPTABLE_SCORE
    assert relatorio.acceptable


def test_regra_ingenua_nao_engana_o_zxcvbn() -> None:
    """`Password1!` passa em qualquer regra de "maiúscula + número + símbolo"."""
    relatorio = evaluate("Password1!")
    assert relatorio.score <= 2


def test_contexto_derruba_a_nota() -> None:
    """Usar o nome do serviço como senha tem de pontuar zero."""
    sem_contexto = evaluate("github2024")
    com_contexto = evaluate("github2024", user_inputs=["github", "renan"])
    assert com_contexto.score <= sem_contexto.score


def test_senha_vazia() -> None:
    relatorio = evaluate("")
    assert relatorio.score == 0
    assert not relatorio.acceptable
    assert "vazia" in relatorio.warning.lower()


def test_senha_muito_longa_e_truncada_sem_travar() -> None:
    relatorio = evaluate("x9K#" * 100)  # 400 caracteres
    assert relatorio.truncated
    assert "no mínimo" in relatorio.as_line()


def test_contexto_com_valores_nulos_nao_quebra() -> None:
    assert evaluate("K7#mQ9$vL2@nR5&x", user_inputs=["", "github"]).score >= 3


def test_relatorio_tem_rotulo_legivel() -> None:
    assert evaluate("123456").label == "péssima"
    assert evaluate("K7#mQ9$vL2@nR5&xW8!p").label in {"forte", "excelente"}
