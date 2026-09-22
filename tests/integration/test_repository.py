"""Testes do CRUD e da busca de credenciais."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from vault.db import repository as repo
from vault.db.models import Credential
from vault.db.repository import UNSET, CredentialInput
from vault.exceptions import (
    CredentialNotFoundError,
    DecryptionError,
    DuplicateCredentialError,
)


def _entrada(**kwargs) -> CredentialInput:
    base = {
        "service_name": "github",
        "login": "renan",
        "password": "senha-do-github",
    }
    return CredentialInput(**{**base, **kwargs})


def test_credencial_e_gravada_cifrada(session: Session, chave: bytes) -> None:
    """A garantia central do Zero-Knowledge: **nem a senha nem o metadado** em claro.

    A versão anterior deste teste terminava em
    `assert bruto.service_name == "github"  # metadado é legível de propósito`.
    Era verdade até a migration `edb62ca16834` e virou exatamente o contrário do
    que o projeto promete: hoje o banco não pode saber de qual serviço é a
    credencial. Por isso o teste afirma a **ausência** dos dois.
    """
    repo.create_credential(
        session,
        chave,
        _entrada(
            password="s3nh4-ultra-secreta",
            url="https://github.com",
            notes="nota-secreta",
        ),
    )
    session.commit()

    bruto = session.execute(select(Credential.encrypted_data)).scalar_one()
    for vazamento in (
        b"s3nh4-ultra-secreta",
        b"github",  # o nome do servico E a URL
        b"renan",  # o login
        b"nota-secreta",
    ):
        assert vazamento not in bruto, f"{vazamento!r} vazou em texto puro no blob"

    # E a tabela nao tem mais onde guardar metadado legivel, nem por engano.
    colunas = {c.name for c in Credential.__table__.columns}
    assert colunas == {"id", "encrypted_data", "created_at", "updated_at", "deleted_at"}


def test_roundtrip_completo(session: Session, chave: bytes) -> None:
    credential = repo.create_credential(
        session,
        chave,
        _entrada(
            url="https://github.com",
            notes="conta pessoal",
            totp_secret="JBSWY3DPEHPK3PXP",
        ),
    )
    aberta = repo.reveal(chave, credential)
    assert aberta.service_name == "github"
    assert aberta.login == "renan"
    assert aberta.password == "senha-do-github"
    assert aberta.url == "https://github.com"
    assert aberta.notes == "conta pessoal"
    assert aberta.totp_secret == "JBSWY3DPEHPK3PXP"


def test_campos_opcionais_ficam_nulos(session: Session, chave: bytes) -> None:
    aberta = repo.reveal(chave, repo.create_credential(session, chave, _entrada()))
    assert aberta.url is None
    assert aberta.notes is None
    assert aberta.totp_secret is None


def test_chave_errada_nao_abre_credencial(session: Session, chave: bytes) -> None:
    credential = repo.create_credential(session, chave, _entrada())
    with pytest.raises(DecryptionError):
        repo.reveal(b"\x00" * 32, credential)


def test_par_servico_login_duplicado_e_recusado(session: Session, chave: bytes) -> None:
    repo.create_credential(session, chave, _entrada())
    session.commit()
    with pytest.raises(DuplicateCredentialError, match="Já existe"):
        repo.create_credential(session, chave, _entrada(password="outra"))


def test_mesmo_servico_com_login_diferente_e_permitido(
    session: Session, chave: bytes
) -> None:
    repo.create_credential(session, chave, _entrada(login="pessoal"))
    repo.create_credential(session, chave, _entrada(login="trabalho"))
    session.commit()
    assert repo.count_credentials(session) == 2


@pytest.mark.parametrize(
    ("campo", "valor"),
    [("service_name", "  "), ("login", ""), ("password", "")],
)
def test_campo_obrigatorio_vazio_e_recusado(
    session: Session, chave: bytes, campo: str, valor: str
) -> None:
    with pytest.raises(ValueError):
        repo.create_credential(session, chave, _entrada(**{campo: valor}))


def test_espacos_nas_bordas_sao_removidos(session: Session, chave: bytes) -> None:
    credential = repo.create_credential(
        session, chave, _entrada(service_name="  github  ", login="  renan  ")
    )
    # O metadado so existe dentro do blob: a prova passa por decifrar.
    aberta = repo.reveal(chave, credential)
    assert aberta.service_name == "github"
    assert aberta.login == "renan"


def test_senha_com_espacos_e_preservada(session: Session, chave: bytes) -> None:
    """Espaço faz parte da senha e não pode ser aparado."""
    aberta = repo.reveal(
        chave, repo.create_credential(session, chave, _entrada(password="  com espaço  "))
    )
    assert aberta.password == "  com espaço  "


# ---------------------------------------------------------------------------
# Leitura e busca
# ---------------------------------------------------------------------------


@pytest.fixture
def povoado(session: Session, chave: bytes) -> None:
    for servico, login, url in [
        ("GitHub", "renan", "https://github.com"),
        ("github", "outro", None),
        ("Gitlab", "renan", "https://gitlab.com"),
        ("Banco 100%", "cliente", None),
        ("aws", "admin_root", "https://console.aws.amazon.com"),
    ]:
        repo.create_credential(
            session, chave, CredentialInput(servico, login, "x", url=url)
        )
    session.commit()


def test_lista_vem_ordenada(session: Session, chave: bytes, povoado) -> None:
    nomes = [c.service_name.lower() for c in repo.list_credentials(session, chave)]
    assert nomes == sorted(nomes)


def test_busca_ignora_maiusculas(session: Session, chave: bytes, povoado) -> None:
    assert len(repo.search_credentials(session, chave, "GITHUB")) == 2
    assert len(repo.search_credentials(session, chave, "github")) == 2


def test_busca_casa_login_e_url(session: Session, chave: bytes, povoado) -> None:
    assert len(repo.search_credentials(session, chave, "admin_root")) == 1
    assert len(repo.search_credentials(session, chave, "gitlab.com")) == 1


def test_busca_vazia_devolve_tudo(session: Session, chave: bytes, povoado) -> None:
    assert len(repo.search_credentials(session, chave, "   ")) == 5


def test_curinga_do_like_e_escapado(session: Session, chave: bytes, povoado) -> None:
    """`%` numa busca tem de ser literal, não "qualquer coisa"."""
    assert len(repo.search_credentials(session, chave, "%")) == 1
    assert repo.search_credentials(session, chave, "%")[0].service_name == "Banco 100%"


def test_underscore_do_like_e_escapado(session: Session, chave: bytes, povoado) -> None:
    """`_` casaria qualquer caractere; aqui tem de casar só o literal."""
    assert len(repo.search_credentials(session, chave, "admin_root")) == 1
    assert repo.search_credentials(session, chave, "admin_xroot") == []


def test_busca_sem_resultado(session: Session, chave: bytes, povoado) -> None:
    assert repo.search_credentials(session, chave, "nao-existe-isso") == []


def test_get_por_id_inexistente(session: Session, chave: bytes) -> None:
    with pytest.raises(CredentialNotFoundError, match="#999"):
        repo.get_credential(session, 999)


def test_find_por_servico_e_login_ignora_caixa(session: Session, chave: bytes, povoado) -> None:
    assert repo.find_by_service_login(session, chave, "GITLAB", "RENAN").login == "renan"


def test_find_inexistente(session: Session, chave: bytes, povoado) -> None:
    with pytest.raises(CredentialNotFoundError):
        repo.find_by_service_login(session, chave, "gitlab", "ninguem")


# ---------------------------------------------------------------------------
# Atualização
# ---------------------------------------------------------------------------


def test_update_troca_a_senha(session: Session, chave: bytes) -> None:
    credential = repo.create_credential(session, chave, _entrada())
    blob_antigo = credential.encrypted_data

    repo.update_credential(session, chave, credential, password="senha-nova")

    assert credential.encrypted_data != blob_antigo
    assert repo.reveal(chave, credential).password == "senha-nova"


def test_update_preserva_o_que_nao_foi_informado(session: Session, chave: bytes) -> None:
    """O bug clássico: omitir um campo apagá-lo."""
    credential = repo.create_credential(
        session, chave, _entrada(url="https://github.com", notes="importante")
    )
    repo.update_credential(session, chave, credential, login="novo-login")

    aberta = repo.reveal(chave, credential)
    assert aberta.login == "novo-login"
    assert aberta.url == "https://github.com"
    assert aberta.notes == "importante"
    assert aberta.password == "senha-do-github"


def test_none_explicito_apaga_o_campo(session: Session, chave: bytes) -> None:
    """`None` apaga; omitir preserva. É a razão de o sentinela UNSET existir."""
    credential = repo.create_credential(session, chave, _entrada(notes="apagar isto"))
    repo.update_credential(session, chave, credential, notes=None)
    assert repo.reveal(chave, credential).notes is None


def test_unset_e_distinto_de_none() -> None:
    assert UNSET is not None


def test_update_para_par_ja_existente_e_recusado(session: Session, chave: bytes) -> None:
    repo.create_credential(session, chave, _entrada(login="a"))
    segunda = repo.create_credential(session, chave, _entrada(login="b"))
    session.commit()
    with pytest.raises(DuplicateCredentialError):
        repo.update_credential(session, chave, segunda, login="a")


@pytest.mark.parametrize(("campo", "valor"), [("service_name", " "), ("login", ""), ("password", "")])
def test_update_com_valor_vazio_e_recusado(
    session: Session, chave: bytes, campo: str, valor: str
) -> None:
    credential = repo.create_credential(session, chave, _entrada())
    with pytest.raises(ValueError):
        repo.update_credential(session, chave, credential, **{campo: valor})


def test_update_re_cifra_com_nonce_novo(session: Session, chave: bytes) -> None:
    """Reescrever a MESMA senha tem de gerar blob diferente (nonce novo)."""
    credential = repo.create_credential(session, chave, _entrada())
    blob_antigo = credential.encrypted_data
    repo.update_credential(session, chave, credential, password="senha-do-github")
    assert credential.encrypted_data != blob_antigo


# ---------------------------------------------------------------------------
# Remoção
# ---------------------------------------------------------------------------


def test_delete_remove(session: Session, chave: bytes) -> None:
    credential = repo.create_credential(session, chave, _entrada())
    credential_id = credential.id
    repo.delete_credential(session, credential)
    session.commit()

    assert repo.count_credentials(session) == 0
    with pytest.raises(CredentialNotFoundError):
        repo.get_credential(session, credential_id)


def test_delete_nao_afeta_as_outras(session: Session, chave: bytes, povoado) -> None:
    todas = repo.list_credentials(session, chave)
    repo.delete_credential(session, repo.get_credential(session, todas[0].id))
    session.commit()
    assert repo.count_credentials(session) == 4
