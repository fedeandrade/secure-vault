"""Configuração da aplicação, lida de variáveis de ambiente / `.env`.

Duas decisões deliberadas aqui:

1. **Nada é instanciado no import.** A versão anterior fazia `settings = Settings()`
   no nível do módulo: qualquer `import vault.<qualquer coisa>` explodia com
   `ValidationError` se não existisse um `.env`. Isso quebrava até `vault --help`
   e impedia a suíte de testes de sequer coletar. Agora a leitura acontece dentro
   de `get_settings()`, com cache — o custo é o mesmo, o acoplamento não.

2. **`database_url` é opcional no modelo, obrigatório no uso.** Comandos que não
   tocam o banco (`vault generate`, `vault strength`, `vault --help`) funcionam
   numa máquina sem `.env`. Quem precisa do banco chama `require_database_url()`
   e recebe uma mensagem acionável em vez de um traceback do Pydantic.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from vault.exceptions import ConfigurationError

#: Parâmetros padrão do Argon2id. São o piso recomendado pelo RFC 9106 para uso
#: interativo e batem com os valores que a Fase 4 usava hardcoded — de modo que
#: um vault criado antes desta refatoração continua abrindo sem migração de dados.
DEFAULT_KDF_TIME_COST = 3
DEFAULT_KDF_MEMORY_COST = 65536  # 64 MiB
DEFAULT_KDF_PARALLELISM = 4
DEFAULT_KDF_HASH_LEN = 32  # 256 bits — tamanho exato da chave do AES-256-GCM


class Settings(BaseSettings):
    """Configuração tipada. Campos vêm de variáveis de ambiente ou do `.env`."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    database_url: str | None = None
    """URL SQLAlchemy. Ex.: postgresql+psycopg://vault:senha@localhost:5432/secure_vault"""

    kdf_algorithm: str = "argon2id"
    kdf_time_cost: int = Field(default=DEFAULT_KDF_TIME_COST, ge=1)
    kdf_memory_cost: int = Field(default=DEFAULT_KDF_MEMORY_COST, ge=8)
    kdf_parallelism: int = Field(default=DEFAULT_KDF_PARALLELISM, ge=1)

    session_timeout_seconds: int = Field(default=300, ge=10)
    """Inatividade máxima do `vault shell` e da TUI antes de descartar a chave."""

    clipboard_clear_seconds: int = Field(default=20, ge=1)
    """Quanto tempo uma senha copiada permanece na área de transferência."""

    def require_database_url(self) -> str:
        """Retorna a URL do banco ou explica o que fazer para configurá-la."""
        if not self.database_url:
            raise ConfigurationError(
                "DATABASE_URL não está definida.\n"
                "Copie .env.example para .env e preencha DATABASE_URL, ou exporte "
                "a variável de ambiente.\n"
                "Exemplo: "
                "DATABASE_URL=postgresql+psycopg://vault:senha@localhost:5432/secure_vault"
            )
        return self.database_url


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Configuração da aplicação (lida uma vez por processo)."""
    return Settings()


def reset_settings_cache() -> None:
    """Descarta o cache. Usado pelos testes ao trocar variáveis de ambiente."""
    get_settings.cache_clear()
