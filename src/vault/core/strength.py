"""Avaliação de força de senha (Fase 7), via zxcvbn.

Por que zxcvbn e não uma regra de "8 caracteres com maiúscula e número":
`Password1!` passa em qualquer regra dessas e está entre as primeiras senhas que
qualquer dicionário tenta. O zxcvbn estima o **número de tentativas** para
adivinhar, casando a senha contra listas de senhas comuns, nomes, padrões de
teclado (`qwerty`), sequências (`abc123`), datas e substituições l33t.

Duas notas de implementação:

- O zxcvbn compara a senha contra `user_inputs`. Passamos o nome do serviço e o
  login: `github` como senha do GitHub tem que pontuar zero, e sem esse contexto
  ele pontuaria como uma palavra qualquer.
- A análise é **super-linear** no comprimento da senha. Uma passphrase de 200
  caracteres trava a CLI por segundos. Truncamos em `_MAX_ANALYSIS_LENGTH`: uma
  senha maior que isso já está muito além de qualquer limite de força útil, e o
  resultado é reportado como o piso ("no mínimo isto").
"""

from __future__ import annotations

from dataclasses import dataclass

from zxcvbn import zxcvbn

_MAX_ANALYSIS_LENGTH = 72

#: Rótulos dos scores 0-4 do zxcvbn.
SCORE_LABELS = {
    0: "péssima",
    1: "fraca",
    2: "razoável",
    3: "forte",
    4: "excelente",
}

#: Score mínimo que consideramos aceitável para uma senha mestra.
MIN_ACCEPTABLE_SCORE = 3


@dataclass(frozen=True, slots=True)
class StrengthReport:
    """Resultado da análise, já traduzido para o vocabulário do projeto."""

    score: int
    label: str
    guesses_log10: float
    crack_time_display: str
    warning: str
    suggestions: tuple[str, ...]
    truncated: bool

    @property
    def acceptable(self) -> bool:
        return self.score >= MIN_ACCEPTABLE_SCORE

    def as_line(self) -> str:
        base = f"{self.label} (score {self.score}/4, ~10^{self.guesses_log10:.1f} tentativas)"
        return f"no mínimo {base}" if self.truncated else base


def evaluate(password: str, *, user_inputs: list[str] | None = None) -> StrengthReport:
    """Analisa `password`. `user_inputs` recebe contexto (serviço, login, e-mail)."""
    if not password:
        return StrengthReport(
            score=0,
            label=SCORE_LABELS[0],
            guesses_log10=0.0,
            crack_time_display="instantâneo",
            warning="Senha vazia.",
            suggestions=("Informe uma senha.",),
            truncated=False,
        )

    truncated = len(password) > _MAX_ANALYSIS_LENGTH
    amostra = password[:_MAX_ANALYSIS_LENGTH]

    # zxcvbn rejeita entradas não-string em user_inputs; normalizamos aqui.
    contexto = [str(v) for v in (user_inputs or []) if v]

    resultado = zxcvbn(amostra, user_inputs=contexto)
    feedback = resultado.get("feedback") or {}
    crack_times = resultado.get("crack_times_display") or {}

    return StrengthReport(
        score=int(resultado["score"]),
        label=SCORE_LABELS[int(resultado["score"])],
        guesses_log10=float(resultado["guesses_log10"]),
        crack_time_display=str(
            crack_times.get("offline_slow_hashing_1e4_per_second", "desconhecido")
        ),
        warning=str(feedback.get("warning") or ""),
        suggestions=tuple(str(s) for s in (feedback.get("suggestions") or [])),
        truncated=truncated,
    )
