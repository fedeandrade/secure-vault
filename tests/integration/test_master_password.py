"""Testes do ciclo de vida do vault: criação, autenticação, troca de senha."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from tests.conftest import KDF_TESTE, SENHA_MESTRA
from vault.core import crypto
from vault.core.kdf import KdfParams
from vault.core.master_password import (
    change_master_password,
    create_vault,
    get_vault_config,
    params_of,
    unlock,
    vault_exists,
    verify_master_password,
)
from vault.db import repository as repo
from vault.db.models import VAULT_CONFIG_ID
from vault.db.repository import CredentialInput
from vault.exceptions import (
    AuthenticationError,
    DecryptionError,
    TotpError,
    VaultAlreadyExistsError,
    VaultNotInitializedError,
)


def test_vault_novo_nasce_completo(session: Session, kdf_rapido: KdfParams) -> None:
    config = create_vault(session, SENHA_MESTRA, params=kdf_rapido)
    assert config.id == VAULT_CONFIG_ID
    assert len(config.salt) == 16
    assert config.key_check is not None
    assert config.kdf_algorithm == "argon2id"
    assert not config.totp_enabled


def test_senha_mestra_nao_e_gravada_em_texto_puro(
    session: Session, kdf_rapido: KdfParams
) -> None:
    """A garantia central do projeto, verificada e não só prometida no README."""
    config = create_vault(session, SENHA_MESTRA, params=kdf_rapido)
    assert SENHA_MESTRA not in config.master_password_hash
    assert config.master_password_hash.startswith("$argon2id$")
    assert SENHA_MESTRA.encode() not in config.salt
    assert SENHA_MESTRA.encode() not in (config.key_check or b"")


def test_hash_nao_e_a_chave_de_criptografia(
    session: Session, kdf_rapido: KdfParams
) -> None:
    config = create_vault(session, SENHA_MESTRA, params=kdf_rapido)
    chave = unlock(session, SENHA_MESTRA)
    assert chave not in config.master_password_hash.encode()


def test_segundo_vault_e_recusado(session: Session, kdf_rapido: KdfParams) -> None:
    create_vault(session, SENHA_MESTRA, params=kdf_rapido)
    with pytest.raises(VaultAlreadyExistsError, match="Já existe um vault"):
        create_vault(session, "outra-senha-qualquer", params=kdf_rapido)


def test_senha_mestra_curta_e_recusada(session: Session, kdf_rapido: KdfParams) -> None:
    with pytest.raises(AuthenticationError, match="ao menos 8"):
        create_vault(session, "curta", params=kdf_rapido)


def test_operacao_sem_vault_da_mensagem_acionavel(session: Session) -> None:
    with pytest.raises(VaultNotInitializedError, match="vault init"):
        get_vault_config(session)
    assert not vault_exists(session)


def test_unlock_com_a_senha_certa(session: Session, vault_criado) -> None:
    chave = unlock(session, SENHA_MESTRA)
    assert len(chave) == 32


def test_unlock_e_deterministico(session: Session, vault_criado) -> None:
    assert unlock(session, SENHA_MESTRA) == unlock(session, SENHA_MESTRA)


def test_unlock_com_senha_errada(session: Session, vault_criado) -> None:
    with pytest.raises(AuthenticationError, match="incorreta"):
        unlock(session, "senha-errada-mesmo")


def test_verify_nao_deriva_chave(session: Session, vault_criado) -> None:
    assert verify_master_password(session, SENHA_MESTRA) is True
    assert verify_master_password(session, "errada-demais") is False


def test_parametros_gravados_sao_os_usados(session: Session, vault_criado) -> None:
    config = get_vault_config(session)
    assert params_of(config) == KDF_TESTE


def test_parametros_adulterados_sao_detectados(session: Session, vault_criado) -> None:
    """O `key_check` é o que impede o vault de virar lixo em silêncio.

    Sem ele, mudar o custo do KDF no banco faria `unlock` devolver uma chave
    errada com ar de sucesso, e cada credencial falharia depois, uma a uma.
    """
    config = get_vault_config(session)
    config.kdf_time_cost = config.kdf_time_cost + 1
    session.flush()

    with pytest.raises(DecryptionError, match="não abre este vault"):
        unlock(session, SENHA_MESTRA)


def test_key_check_ausente_e_preenchido_no_login(session: Session, vault_criado) -> None:
    """Vault da Fase 3/4 (sem sentinela) ganha uma no primeiro login."""
    config = get_vault_config(session)
    config.key_check = None
    session.flush()

    chave = unlock(session, SENHA_MESTRA)
    assert config.key_check is not None
    assert crypto.verify_key_check(chave, config.key_check)


def test_hash_corrompido_nao_e_confundido_com_senha_errada(
    session: Session, vault_criado
) -> None:
    config = get_vault_config(session)
    config.master_password_hash = "isto-nao-e-um-hash-argon2"
    session.flush()

    with pytest.raises(AuthenticationError, match="corrompido"):
        unlock(session, SENHA_MESTRA)


# ---------------------------------------------------------------------------
# Troca de senha mestra
# ---------------------------------------------------------------------------

NOVA_SENHA = "nova-senha-mestra-456"


def test_troca_de_senha_re_cifra_tudo(session: Session, vault_criado) -> None:
    chave_velha = unlock(session, SENHA_MESTRA)
    repo.create_credential(
        session,
        chave_velha,
        CredentialInput(
            service_name="github",
            login="renan",
            password="senha-do-github",
            notes="anotação secreta",
        ),
    )

    total = change_master_password(session, SENHA_MESTRA, NOVA_SENHA)
    assert total == 1

    with pytest.raises(AuthenticationError):
        unlock(session, SENHA_MESTRA)

    chave_nova = unlock(session, NOVA_SENHA)
    assert chave_nova != chave_velha

    aberta = repo.reveal(chave_nova, repo.find_by_service_login(session, "github", "renan"))
    assert aberta.password == "senha-do-github"
    assert aberta.notes == "anotação secreta"


def test_troca_de_senha_gera_salt_novo(session: Session, vault_criado) -> None:
    salt_antigo = get_vault_config(session).salt
    change_master_password(session, SENHA_MESTRA, NOVA_SENHA)
    assert get_vault_config(session).salt != salt_antigo


def test_troca_com_senha_atual_errada_nao_muda_nada(
    session: Session, vault_criado
) -> None:
    with pytest.raises(AuthenticationError):
        change_master_password(session, "errada-de-proposito", NOVA_SENHA)
    assert unlock(session, SENHA_MESTRA)  # a senha antiga continua valendo


def test_troca_para_senha_curta_e_recusada(session: Session, vault_criado) -> None:
    with pytest.raises(AuthenticationError, match="ao menos 8"):
        change_master_password(session, SENHA_MESTRA, "curta")


def test_troca_de_senha_em_vault_vazio(session: Session, vault_criado) -> None:
    assert change_master_password(session, SENHA_MESTRA, NOVA_SENHA) == 0
    assert unlock(session, NOVA_SENHA)


# ---------------------------------------------------------------------------
# Segundo fator na senha mestra
# ---------------------------------------------------------------------------


def _ativar_totp(session: Session, chave: bytes) -> str:
    from vault.core.totp import generate_totp_secret

    segredo = generate_totp_secret()
    config = get_vault_config(session)
    config.totp_secret_encrypted = crypto.encrypt(
        chave, segredo, aad=crypto.AAD_MASTER_TOTP
    )
    session.flush()
    return segredo


def test_com_totp_ativo_a_senha_sozinha_nao_basta(
    session: Session, vault_criado
) -> None:
    _ativar_totp(session, unlock(session, SENHA_MESTRA))
    with pytest.raises(TotpError, match="segundo fator"):
        unlock(session, SENHA_MESTRA)


def test_codigo_totp_correto_destrava(session: Session, vault_criado) -> None:
    from vault.core.totp import current_code

    segredo = _ativar_totp(session, unlock(session, SENHA_MESTRA))
    assert unlock(session, SENHA_MESTRA, totp_code=current_code(segredo))


def test_codigo_totp_errado_nao_destrava(session: Session, vault_criado) -> None:
    from vault.core.totp import current_code

    segredo = _ativar_totp(session, unlock(session, SENHA_MESTRA))
    correto = current_code(segredo)
    errado = "000000" if correto != "000000" else "111111"
    with pytest.raises(TotpError, match="inválido"):
        unlock(session, SENHA_MESTRA, totp_code=errado)


def test_troca_de_senha_re_cifra_o_segredo_totp(session: Session, vault_criado) -> None:
    from vault.core.totp import current_code

    segredo = _ativar_totp(session, unlock(session, SENHA_MESTRA))
    change_master_password(
        session, SENHA_MESTRA, NOVA_SENHA, totp_code=current_code(segredo)
    )
    # O mesmo autenticador continua valendo depois da troca.
    assert unlock(session, NOVA_SENHA, totp_code=current_code(segredo))
