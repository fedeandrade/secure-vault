"""Geração de senhas fortes (Fase 6).

Duas armadilhas clássicas, evitadas de propósito:

**1. `random` em vez de `secrets`.** O `random` do Python é um Mersenne Twister:
observando algumas saídas dá para reconstruir o estado interno e prever todas as
próximas. Aqui só se usa `secrets`, que puxa do CSPRNG do sistema operacional.

**2. Enviesar a distribuição ao "garantir um de cada tipo".** A implementação
ingênua sorteia um caractere de cada classe exigida, preenche o resto e embaralha
— o que fixa a contagem de cada classe e reduz o espaço de senhas possíveis (a
entropia real fica abaixo da anunciada). Aqui usamos *rejection sampling*: gera
uma senha uniformemente aleatória e descarta se não cumprir os requisitos. A
distribuição resultante é a uniforme condicionada aos requisitos, que é
exatamente o que se quer, e o número esperado de tentativas é baixo.
"""

from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass

from vault.exceptions import VaultError

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/~"

#: Caracteres fáceis de confundir ao ler em voz alta ou copiar de uma tela.
AMBIGUOUS = "0OoIl1|`'\"{}[]()/\\"

DEFAULT_LENGTH = 20
MIN_LENGTH = 4
MAX_LENGTH = 512

#: Teto de tentativas do rejection sampling. Com os alfabetos padrão a chance de
#: uma senha de 8+ caracteres falhar todos os requisitos é ínfima; o limite existe
#: para transformar uma configuração impossível num erro claro em vez de um
#: laço infinito (ex.: comprimento 4 exigindo 5 classes distintas).
_MAX_ATTEMPTS = 1000


class PasswordPolicyError(VaultError):
    """Os requisitos pedidos são impossíveis de satisfazer."""


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """O que a senha gerada precisa conter."""

    length: int = DEFAULT_LENGTH
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False

    def alphabet(self) -> str:
        pools = self.pools()
        if not pools:
            raise PasswordPolicyError(
                "Nenhum conjunto de caracteres habilitado: a senha seria vazia. "
                "Habilite ao menos um entre minúsculas, maiúsculas, dígitos e símbolos."
            )
        alfabeto = "".join(pools)
        if len(set(alfabeto)) < 2:
            raise PasswordPolicyError(
                "O alfabeto resultante tem menos de 2 caracteres distintos."
            )
        return alfabeto

    def pools(self) -> list[str]:
        candidatos = [
            (self.use_lowercase, LOWERCASE),
            (self.use_uppercase, UPPERCASE),
            (self.use_digits, DIGITS),
            (self.use_symbols, SYMBOLS),
        ]
        pools: list[str] = []
        for habilitado, pool in candidatos:
            if not habilitado:
                continue
            if self.exclude_ambiguous:
                pool = "".join(c for c in pool if c not in AMBIGUOUS)
            if pool:
                pools.append(pool)
        return pools

    def validate(self) -> None:
        if not MIN_LENGTH <= self.length <= MAX_LENGTH:
            raise PasswordPolicyError(
                f"Comprimento precisa estar entre {MIN_LENGTH} e {MAX_LENGTH}; "
                f"recebido {self.length}."
            )
        exigidas = len(self.pools())
        if exigidas == 0:
            self.alphabet()  # levanta a mensagem específica
        if self.length < exigidas:
            raise PasswordPolicyError(
                f"Comprimento {self.length} é menor que o número de classes de "
                f"caracteres exigidas ({exigidas}); impossível conter uma de cada."
            )


def entropy_bits(alphabet_size: int, length: int) -> float:
    """Entropia em bits de uma senha uniforme: `length * log2(alphabet_size)`.

    É a entropia de *geração* — o que um atacante enfrenta sabendo exatamente a
    política usada. Não é a mesma coisa que a nota do zxcvbn, que estima o custo
    de adivinhar uma senha escolhida por um humano. Ver `vault.core.strength`.
    """
    if alphabet_size < 2 or length <= 0:
        return 0.0
    return length * math.log2(alphabet_size)


def _satisfies(password: str, policy: PasswordPolicy) -> bool:
    pools = policy.pools()
    return all(any(c in pool for c in password) for pool in pools)


def generate_password(policy: PasswordPolicy | None = None) -> str:
    """Gera uma senha uniformemente aleatória que satisfaz a política."""
    policy = policy or PasswordPolicy()
    policy.validate()
    alfabeto = policy.alphabet()

    for _ in range(_MAX_ATTEMPTS):
        candidata = "".join(secrets.choice(alfabeto) for _ in range(policy.length))
        if _satisfies(candidata, policy):
            return candidata

    raise PasswordPolicyError(  # pragma: no cover - inalcançável com políticas válidas
        f"Não foi possível gerar uma senha que cumprisse os requisitos em "
        f"{_MAX_ATTEMPTS} tentativas. Reveja a política (comprimento {policy.length}, "
        f"{len(policy.pools())} classes exigidas)."
    )


def generate_with_entropy(policy: PasswordPolicy | None = None) -> tuple[str, float]:
    """Senha gerada e a entropia em bits da política que a produziu."""
    policy = policy or PasswordPolicy()
    senha = generate_password(policy)
    return senha, entropy_bits(len(set(policy.alphabet())), policy.length)
