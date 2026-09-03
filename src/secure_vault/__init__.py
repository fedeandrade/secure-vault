"""Ponto de entrada do console script.

Este pacote existe apenas para expor `main()` sob o nome de distribuição
(`secure-vault`). A implementação inteira mora em `vault.*`; aqui não há lógica
nenhuma de propósito, para que o entry point não vire um segundo lugar onde
comportamento se esconde.
"""

from __future__ import annotations

from vault.cli.main import main

__all__ = ["main"]
