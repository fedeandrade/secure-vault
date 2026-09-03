"""Senha mestra: criação do vault, autenticação e destravamento.

O que mudou em relação à Fase 3/4 e por quê:

- **As funções recebem uma `Session`** em vez de abrirem a própria. `login()`
  abria duas sessões para a mesma operação lógica e lia `VaultConfig` duas vezes;
  entre uma leitura e outra o vault podia mudar. Agora é uma transação só.
- **`scalar_one()` virou erro de domínio.** Antes, rodar qualquer comando num
  banco sem vault estourava `NoResultFound` do SQLAlchemy na cara do usuário.
  Agora levanta `VaultNotInitializedError`, cuja mensagem diz o comando a rodar.
- **`VerifyMismatchError` não é a única falha possível.** Um hash corrompido
  levanta `InvalidHashError`, que a versão anterior deixava escapar. Todo o
  conjunto de exceções do argon2 é tratado.
- **Trocar a senha mestra re-cifra o vault inteiro** numa transação só, em vez de
  deixar os dados ilegíveis com a chave nova.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from vault.core import crypto
from vault.core.kdf import KdfParams, derive_encryption_key, generate_salt, normalize_password
from vault.db.models import VAULT_CONFIG_ID, Credential, VaultConfig
from vault.exceptions import (
    AuthenticationError,
    DecryptionError,
    TotpError,
    VaultAlreadyExistsError,
    VaultNotInitializedError,
)

MIN_MASTER_PASSWORD_LENGTH = 8


def _hasher(params: KdfParams) -> PasswordHasher:
    """PasswordHasher com os mesmos custos do KDF do vault.

    O hash Argon2 no formato PHC carrega os próprios parâmetros embutidos, então
    verificar um hash antigo continua funcionando mesmo depois de mudarmos estes
    valores — é o `check_needs_rehash` que cuida da atualização gradual.
    """
    return PasswordHasher(
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=params.hash_len,
    )


def hash_master_password(password: str, params: KdfParams | None = None) -> str:
    """Hash Argon2id da senha mestra, para autenticação (não é a chave)."""
    params = params or KdfParams.from_settings()
    return _hasher(params).hash(normalize_password(password))


def get_vault_config(session: Session) -> VaultConfig:
    """A linha de configuração do vault, ou erro acionável se não existir."""
    config = session.scalars(select(VaultConfig)).one_or_none()
    if config is None:
        raise VaultNotInitializedError(
            "Nenhum vault encontrado neste banco. Rode `vault init` para criar um."
        )
    return config


def vault_exists(session: Session) -> bool:
    return session.scalars(select(VaultConfig.id)).one_or_none() is not None


def create_vault(
    session: Session, password: str, *, params: KdfParams | None = None
) -> VaultConfig:
    """Cria o vault. Falha se já existir — nunca sobrescreve em silêncio."""
    if len(password) < MIN_MASTER_PASSWORD_LENGTH:
        raise AuthenticationError(
            f"A senha mestra precisa ter ao menos {MIN_MASTER_PASSWORD_LENGTH} "
            "caracteres. Ela é a única coisa entre um atacante e todo o resto."
        )

    if vault_exists(session):
        raise VaultAlreadyExistsError(
            "Já existe um vault neste banco. Para começar do zero, apague os "
            "dados explicitamente (`vault destroy --yes`) — não vamos sobrescrever "
            "um vault existente por acidente."
        )

    params = params or KdfParams.from_settings()
    salt = generate_salt()
    key = derive_encryption_key(password, salt, params)

    config = VaultConfig(
        id=VAULT_CONFIG_ID,
        master_password_hash=hash_master_password(password, params),
        salt=salt,
        kdf_algorithm=params.algorithm,
        kdf_time_cost=params.time_cost,
        kdf_memory_cost=params.memory_cost,
        kdf_parallelism=params.parallelism,
        kdf_hash_len=params.hash_len,
        key_check=crypto.build_key_check(key),
    )
    session.add(config)
    session.flush()
    return config


def params_of(config: VaultConfig) -> KdfParams:
    """Parâmetros de KDF gravados neste vault (não os da configuração atual)."""
    return KdfParams(
        algorithm=config.kdf_algorithm,
        time_cost=config.kdf_time_cost,
        memory_cost=config.kdf_memory_cost,
        parallelism=config.kdf_parallelism,
        hash_len=config.kdf_hash_len,
    )


def verify_master_password(session: Session, password: str) -> bool:
    """`True` se a senha bate com o hash gravado. Não deriva chave nenhuma."""
    config = get_vault_config(session)
    return _verify_against(config, password)


def _verify_against(config: VaultConfig, password: str) -> bool:
    hasher = _hasher(params_of(config))
    try:
        hasher.verify(config.master_password_hash, normalize_password(password))
    except VerifyMismatchError:
        return False
    except InvalidHashError as exc:
        # Não é "senha errada": é o hash no banco que está corrompido. Confundir
        # os dois faria o usuário trocar a senha achando que errou de tecla.
        raise AuthenticationError(
            "O hash da senha mestra gravado no banco é inválido ou está "
            "corrompido. Restaure um backup do banco."
        ) from exc
    except VerificationError as exc:
        raise AuthenticationError(
            f"Falha ao verificar a senha mestra: {exc}"
        ) from exc

    # NÃO reescrevemos o hash aqui, embora `hasher.check_needs_rehash` esteja
    # disponível e a senha em claro esteja em mãos — que é o padrão recomendado
    # na maioria das aplicações.
    #
    # O motivo é específico deste projeto: o hash Argon2 no formato PHC carrega
    # embutidos os parâmetros com que foi gerado (`$m=16384,t=5,p=2$`), e essa
    # string é a **última cópia sobrevivente** desses parâmetros caso as colunas
    # `kdf_*` sejam perdidas — o `downgrade` do Alembic as derruba, e o `upgrade`
    # seguinte as recria com os valores padrão. Nesse cenário, `check_needs_rehash`
    # veria divergência real e um rehash automático sobrescreveria a evidência que
    # ainda permitiria recuperar o vault com um UPDATE manual.
    #
    # Rotacionar o custo do KDF é trabalho de `vault passwd`, que é explícito e
    # re-cifra todo o conteúdo — não efeito colateral silencioso de um login.
    return True


def unlock(session: Session, password: str, *, totp_code: str | None = None) -> bytes:
    """Autentica e devolve a chave de criptografia derivada em memória.

    Ordem das checagens, e por quê:

    1. Verifica o hash Argon2 — barato de errar, caro de forçar.
    2. Deriva a chave com os parâmetros **do vault**.
    3. Confere a sentinela `key_check`. Se o hash bate mas a sentinela não, os
       parâmetros de KDF no banco não são os que criaram o vault: falhamos com
       uma mensagem clara em vez de devolver uma chave que só vai produzir
       "não foi possível decifrar" em cada credencial.
    4. Se houver segundo fator, valida o código TOTP.

    A chave **nunca** é escrita em disco. Ela existe no processo pelo tempo da
    operação (ou da sessão, no `vault shell` / TUI, com timeout).
    """
    config = get_vault_config(session)

    if not _verify_against(config, password):
        raise AuthenticationError("Senha mestra incorreta.")

    key = derive_encryption_key(password, config.salt, params_of(config))

    if config.key_check is None:
        _adotar_sentinela(session, config, key)
    elif not crypto.verify_key_check(key, config.key_check):
        raise DecryptionError(
            "A senha está correta, mas a chave derivada não abre este vault.\n"
            "Os parâmetros de KDF gravados não são os que criaram o vault.\n"
            f"Gravados agora: {config.kdf_algorithm} t={config.kdf_time_cost} "
            f"m={config.kdf_memory_cost} p={config.kdf_parallelism}.\n"
            "Os parâmetros originais podem estar preservados dentro da string do "
            "hash da senha mestra (formato PHC). Compare-os antes de restaurar "
            "um backup."
        )

    if config.totp_secret_encrypted is not None:
        _require_valid_totp(config, key, totp_code)

    return key


def _adotar_sentinela(session: Session, config: VaultConfig, key: bytes) -> None:
    """Grava uma sentinela num vault que ainda não tem — mas só se puder provar.

    Dois vaults chegam aqui sem `key_check`, e eles são opostos:

    - Um vault legítimo da Fase 3/4, criado antes de a coluna existir. A chave
      derivada é a certa, e a sentinela deve ser adotada.
    - Um vault cujo `key_check` **sumiu** junto com as colunas `kdf_*` num
      `downgrade` seguido de `upgrade` do Alembic. Aí os parâmetros voltaram para
      os valores padrão, a chave derivada é a **errada**, e gravar uma sentinela
      agora carimbaria a chave errada como boa — tornando o diagnóstico correto
      inalcançável para sempre e transformando um problema recuperável em perda
      definitiva.

    Distinguir os dois é possível sem adivinhação: se existir qualquer credencial,
    ela foi cifrada com a chave verdadeira. Basta tentar abrir uma. Abriu, a chave
    é boa. Não abriu, é o segundo caso, e falhamos com a mensagem certa antes de
    escrever qualquer coisa.

    Num vault sem nenhuma credencial não há o que perder, e a sentinela é adotada.
    """
    amostra = session.scalars(select(Credential).limit(1)).one_or_none()

    if amostra is not None:
        try:
            crypto.decrypt(key, amostra.encrypted_password, aad=crypto.AAD_PASSWORD)
        except DecryptionError as exc:
            raise DecryptionError(
                "A senha está correta, mas a chave derivada não abre as "
                "credenciais deste vault, e a sentinela de verificação não "
                "existe.\n"
                "O sintoma típico é um `alembic downgrade` seguido de `upgrade`: "
                "as colunas de parâmetros do KDF voltam aos valores padrão.\n"
                f"Gravados agora: {config.kdf_algorithm} t={config.kdf_time_cost} "
                f"m={config.kdf_memory_cost} p={config.kdf_parallelism}.\n"
                "Os parâmetros ORIGINAIS provavelmente continuam dentro da string "
                "do hash da senha mestra, no formato PHC. Restaure-os nas colunas "
                "kdf_* antes de tentar de novo — e não rode mais comandos neste "
                "vault até corrigir."
            ) from exc

    config.key_check = crypto.build_key_check(key)


def _require_valid_totp(config: VaultConfig, key: bytes, totp_code: str | None) -> None:
    from vault.core.totp import verify_totp  # import tardio: evita ciclo

    if not totp_code:
        raise TotpError(
            "Este vault exige segundo fator. Informe o código de 6 dígitos "
            "(`--totp 123456`)."
        )
    secret = crypto.decrypt(
        key, config.totp_secret_encrypted, aad=crypto.AAD_MASTER_TOTP
    )
    if not verify_totp(secret, totp_code):
        raise TotpError("Código de segundo fator inválido ou expirado.")


def change_master_password(
    session: Session,
    current_password: str,
    new_password: str,
    *,
    totp_code: str | None = None,
) -> int:
    """Troca a senha mestra e **re-cifra todo o conteúdo** do vault.

    Este é o ponto em que um gerenciador de senhas ingênuo destrói os dados do
    usuário: trocar a senha muda a chave derivada, e todo blob cifrado com a
    chave antiga vira lixo. Aqui, tudo é decifrado com a chave velha e re-cifrado
    com a nova dentro de uma única transação — ou tudo troca, ou nada troca.

    Devolve quantas credenciais foram re-cifradas.
    """
    if len(new_password) < MIN_MASTER_PASSWORD_LENGTH:
        raise AuthenticationError(
            f"A nova senha mestra precisa ter ao menos {MIN_MASTER_PASSWORD_LENGTH} caracteres."
        )

    old_key = unlock(session, current_password, totp_code=totp_code)
    config = get_vault_config(session)

    new_params = KdfParams.from_settings()
    new_salt = generate_salt()
    new_key = derive_encryption_key(new_password, new_salt, new_params)

    credentials = list(session.scalars(select(Credential)))
    for credential in credentials:
        senha = crypto.decrypt(
            old_key, credential.encrypted_password, aad=crypto.AAD_PASSWORD
        )
        notas = crypto.decrypt_optional(
            old_key, credential.encrypted_notes, aad=crypto.AAD_NOTES
        )
        totp_secret = crypto.decrypt_optional(
            old_key, credential.encrypted_totp_secret, aad=crypto.AAD_TOTP
        )

        credential.encrypted_password = crypto.encrypt(
            new_key, senha, aad=crypto.AAD_PASSWORD
        )
        credential.encrypted_notes = crypto.encrypt_optional(
            new_key, notas, aad=crypto.AAD_NOTES
        )
        credential.encrypted_totp_secret = crypto.encrypt_optional(
            new_key, totp_secret, aad=crypto.AAD_TOTP
        )

    if config.totp_secret_encrypted is not None:
        master_totp = crypto.decrypt(
            old_key, config.totp_secret_encrypted, aad=crypto.AAD_MASTER_TOTP
        )
        config.totp_secret_encrypted = crypto.encrypt(
            new_key, master_totp, aad=crypto.AAD_MASTER_TOTP
        )

    config.master_password_hash = hash_master_password(new_password, new_params)
    config.salt = new_salt
    config.kdf_algorithm = new_params.algorithm
    config.kdf_time_cost = new_params.time_cost
    config.kdf_memory_cost = new_params.memory_cost
    config.kdf_parallelism = new_params.parallelism
    config.kdf_hash_len = new_params.hash_len
    config.key_check = crypto.build_key_check(new_key)

    session.flush()
    return len(credentials)
