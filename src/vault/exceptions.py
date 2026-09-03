"""Hierarquia de erros do Secure Vault.

Toda falha esperada do domínio vira uma exceção desta hierarquia. A CLI captura
apenas `VaultError` e imprime a mensagem — qualquer outra exceção que escape é,
por definição, um bug nosso e deve aparecer com stack trace completo.

Nunca engolir erro silenciosamente: um gerenciador de senhas que falha em
silêncio é pior que um que quebra ruidosamente.
"""

from __future__ import annotations


class VaultError(Exception):
    """Erro esperado do domínio. A CLI mostra a mensagem, sem stack trace."""


class ConfigurationError(VaultError):
    """Configuração ausente ou inválida (ex.: DATABASE_URL não definida)."""


class VaultNotInitializedError(VaultError):
    """Nenhum vault existe ainda no banco. Rode `vault init`."""


class VaultAlreadyExistsError(VaultError):
    """Já existe um vault. O schema permite exatamente um."""


class AuthenticationError(VaultError):
    """Senha mestra incorreta ou segundo fator inválido."""


class DecryptionError(VaultError):
    """O texto cifrado não pôde ser aberto: chave errada ou dado corrompido.

    Distinta de `AuthenticationError` de propósito: aqui a senha pode até estar
    certa, mas a chave derivada não abre o dado (parâmetros de KDF divergentes,
    banco adulterado, blob truncado).
    """


class CredentialNotFoundError(VaultError):
    """A credencial pedida não existe."""


class DuplicateCredentialError(VaultError):
    """Já existe uma credencial com esse par (serviço, login)."""


class SessionExpiredError(VaultError):
    """A sessão em memória expirou por inatividade; autentique de novo."""


class TotpError(VaultError):
    """Erro relacionado ao segundo fator (TOTP)."""
