"""Regressões de uma revisão adversarial do código.

Cada teste aqui existe porque uma revisão cética derrubou uma garantia que o
código *afirmava* ter. Sem estes testes, todas as correções seriam reversíveis
por uma refatoração distraída, e a suíte continuaria verde.

O critério de cada um: se a proteção for removida, este teste **falha**. Isso foi
verificado desativando a correção e vendo o teste ficar vermelho — um teste que
passa nos dois estados não prova nada.
"""

from __future__ import annotations

import pyotp
import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session
from typer.testing import CliRunner

from tests.conftest import KDF_TESTE, SENHA_MESTRA
from vault.cli.main import app
from vault.core import crypto
from vault.core.kdf import KdfParams, derive_encryption_key, generate_salt
from vault.core.master_password import create_vault, get_vault_config, unlock
from vault.core.schema import CredentialPayload, PayloadSerializer
from vault.db import repository as repo
from vault.db.models import Credential
from vault.db.repository import CredentialInput
from vault.exceptions import DecryptionError, DuplicateCredentialError

runner = CliRunner()


# ===========================================================================
# 1. Perda do vault por downgrade do Alembic
# ===========================================================================
#
# `downgrade` derruba as colunas kdf_* e key_check; o `upgrade` seguinte as
# recria com os valores PADRÃO. Como o hash Argon2 (formato PHC) carrega os
# próprios parâmetros, a autenticação continua passando — o vault aceitava a
# senha certa, derivava a chave errada, e gravava uma sentinela nova por cima,
# tornando o diagnóstico correto inalcançável para sempre.


def _simular_perda_dos_parametros(session: Session) -> None:
    """Reproduz o estado deixado por um downgrade+upgrade: kdf_* nos padrões."""
    config = get_vault_config(session)
    config.key_check = None
    config.kdf_time_cost = 3
    config.kdf_memory_cost = 65536
    config.kdf_parallelism = 4
    session.flush()


@pytest.fixture
def vault_com_parametros_proprios(session: Session):
    """Vault criado com parâmetros diferentes dos padrões, e uma credencial."""
    params = KdfParams(time_cost=2, memory_cost=16, parallelism=2)
    config = create_vault(session, SENHA_MESTRA, params=params)
    chave = unlock(session, SENHA_MESTRA)
    repo.create_credential(
        session,
        chave,
        CredentialInput("github", "renan", "senha-que-nao-pode-sumir"),
    )
    session.flush()
    return config


def test_perda_dos_parametros_e_detectada_em_vez_de_aceita(
    session: Session, vault_com_parametros_proprios
) -> None:
    """`unlock` tem de FALHAR, e não devolver uma chave errada com ar de sucesso."""
    _simular_perda_dos_parametros(session)

    with pytest.raises(DecryptionError) as erro:
        unlock(session, SENHA_MESTRA)

    mensagem = str(erro.value)
    assert "downgrade" in mensagem
    assert "PHC" in mensagem  # aponta onde os parâmetros originais sobreviveram


def test_perda_dos_parametros_nao_grava_sentinela_da_chave_errada(
    session: Session, vault_com_parametros_proprios
) -> None:
    """A sentinela não pode ser carimbada com a chave errada.

    Se fosse, o segundo login passaria — a sentinela atestaria a chave errada —
    e a mensagem de diagnóstico ficaria inalcançável para sempre.
    """
    _simular_perda_dos_parametros(session)

    with pytest.raises(DecryptionError):
        unlock(session, SENHA_MESTRA)

    assert get_vault_config(session).key_check is None

    # E continua falhando na segunda tentativa, em vez de "curar" para o estado errado.
    with pytest.raises(DecryptionError):
        unlock(session, SENHA_MESTRA)


def test_login_nao_reescreve_o_hash_com_os_parametros_errados(
    session: Session, vault_com_parametros_proprios
) -> None:
    """O hash PHC é a última cópia dos parâmetros originais; não pode ser perdido."""
    phc_antes = get_vault_config(session).master_password_hash
    assert "m=16,t=2,p=2" in phc_antes

    _simular_perda_dos_parametros(session)
    with pytest.raises(DecryptionError):
        unlock(session, SENHA_MESTRA)

    assert get_vault_config(session).master_password_hash == phc_antes


def test_vault_antigo_legitimo_sem_sentinela_ainda_abre(
    session: Session, kdf_rapido: KdfParams
) -> None:
    """O caso legítimo continua funcionando: vault da Fase 3/4 adota a sentinela."""
    create_vault(session, SENHA_MESTRA, params=kdf_rapido)
    chave = unlock(session, SENHA_MESTRA)
    repo.create_credential(session, chave, CredentialInput("github", "renan", "s3nha"))

    config = get_vault_config(session)
    config.key_check = None  # como um vault criado antes da coluna existir
    session.flush()

    nova_chave = unlock(session, SENHA_MESTRA)
    assert nova_chave == chave
    assert config.key_check is not None
    assert crypto.verify_key_check(nova_chave, config.key_check)


def test_vault_vazio_sem_sentinela_adota_sem_reclamar(
    session: Session, kdf_rapido: KdfParams
) -> None:
    """Sem credenciais não há o que perder, e não há como validar: adota."""
    create_vault(session, SENHA_MESTRA, params=kdf_rapido)
    config = get_vault_config(session)
    config.key_check = None
    session.flush()

    assert unlock(session, SENHA_MESTRA)
    assert config.key_check is not None


def test_verify_key_check_recusa_sentinela_ausente() -> None:
    """A ausência é decisão da chamadora, não um `True` silencioso."""
    with pytest.raises(ValueError, match="exige a sentinela"):
        crypto.verify_key_check(b"\x01" * 32, None)


# ===========================================================================
# 2. `vault delete` sem autenticação
# ===========================================================================


def test_delete_exige_a_senha_mestra_correta(
    cli_regressao: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sem isto, quem pega um terminal destravado apaga o vault inteiro."""
    runner.invoke(app, ["init"])
    runner.invoke(app, ["add", "github", "renan", "--generate", "--show"])

    monkeypatch.setenv("VAULT_MASTER_PASSWORD", "SENHA-TOTALMENTE-ERRADA-9999")
    resultado = runner.invoke(app, ["delete", "1", "--yes"])

    assert resultado.exit_code == 1
    assert "incorreta" in resultado.output

    monkeypatch.setenv("VAULT_MASTER_PASSWORD", SENHA_MESTRA)
    assert "github" in runner.invoke(app, ["list"]).output


def test_delete_com_a_senha_certa_funciona(cli_regressao: CliRunner) -> None:
    runner.invoke(app, ["init"])
    runner.invoke(app, ["add", "github", "renan", "--generate", "--show"])

    assert runner.invoke(app, ["delete", "1", "--yes"]).exit_code == 0
    assert "Nenhuma credencial" in runner.invoke(app, ["list"]).output


# ===========================================================================
# 3. `vault passwd` que dizia ter trocado sem trocar
# ===========================================================================


def test_passwd_recusa_senha_nova_igual_a_atual(
    cli_regressao: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Com VAULT_MASTER_PASSWORD definida, as duas leituras davam a mesma senha.

    O comando gerava salt novo, re-cifrava tudo com a MESMA senha e anunciava
    "Senha mestra trocada" — quem estivesse rotacionando após um vazamento
    continuava com a senha vazada, sem nenhum erro.
    """
    runner.invoke(app, ["init"])

    # O cenário exato do defeito: a MESMA variável servindo às duas leituras.
    monkeypatch.setenv("VAULT_NEW_MASTER_PASSWORD", SENHA_MESTRA)
    resultado = runner.invoke(app, ["passwd"])

    assert resultado.exit_code == 1
    assert "igual à atual" in resultado.output
    assert "VAULT_NEW_MASTER_PASSWORD" in resultado.output


def test_passwd_sem_a_variavel_nova_nao_usa_a_antiga(
    cli_regressao: CliRunner,
) -> None:
    """Sem `VAULT_NEW_MASTER_PASSWORD`, o comando para em vez de reusar a atual.

    Era esse o silêncio do defeito original: as duas leituras caíam na mesma
    variável e o comando anunciava sucesso sem trocar nada.
    """
    runner.invoke(app, ["init"])
    resultado = runner.invoke(app, ["passwd"])

    assert resultado.exit_code == 1
    assert "VAULT_NEW_MASTER_PASSWORD" in resultado.output
    assert "trocada" not in resultado.output


def test_passwd_troca_de_verdade_com_a_variavel_certa(
    cli_regressao: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.invoke(app, ["init"])
    runner.invoke(app, ["add", "github", "renan", "--generate", "--show"])

    monkeypatch.setenv("VAULT_NEW_MASTER_PASSWORD", "Senha-Nova-De-Verdade-2026")
    trocado = runner.invoke(app, ["passwd"])
    assert trocado.exit_code == 0, trocado.output

    # A senha antiga deixa de valer...
    assert runner.invoke(app, ["get", "github", "--show"]).exit_code == 1

    # ...e a nova vale, com o conteúdo intacto.
    monkeypatch.setenv("VAULT_MASTER_PASSWORD", "Senha-Nova-De-Verdade-2026")
    recuperado = runner.invoke(app, ["get", "github", "--login", "renan", "--show"])
    assert recuperado.exit_code == 0, recuperado.output


# ===========================================================================
# 4. Credenciais que só diferem na caixa
# ===========================================================================


def test_par_que_so_difere_na_caixa_e_barrado_na_criacao(
    session: Session, chave: bytes
) -> None:
    """A UniqueConstraint do banco é case-sensitive e deixava as duas entrarem."""
    repo.create_credential(session, chave, CredentialInput("github", "renan", "a"))
    session.flush()

    with pytest.raises(DuplicateCredentialError, match="maiúsculas"):
        repo.create_credential(session, chave, CredentialInput("GitHub", "Renan", "b"))


def test_par_colidente_existente_da_erro_de_dominio_e_nao_traceback(
    session: Session, chave: bytes
) -> None:
    """Vault legado pode já ter o par. `get` tem de explicar, não estourar.

    Antes: `MultipleResultsFound`, que não é `VaultError` — a CLI não capturava e
    o usuário levava um traceback do SQLAlchemy. As duas credenciais ficavam
    permanentemente inacessíveis por `vault get`.

    O cenário continua possível **e ficou mais fácil** com o Zero-Knowledge: a
    `UniqueConstraint(service_name, login)` sumiu junto com as colunas, então
    nada no banco impede o par. A única barreira é `_colisao_case_insensitive`,
    que roda na aplicação — qualquer cliente que não a execute grava o par em
    silêncio. Por isso as duas linhas aqui são inseridas **direto**, cifradas na
    mão: é exatamente o que um vault escrito por outro cliente pareceria.
    """
    for servico in ("github", "GitHub"):
        payload = CredentialPayload(service_name=servico, login="renan", password="x")
        session.add(
            Credential(
                encrypted_data=crypto.encrypt(
                    chave,
                    PayloadSerializer.dump(payload).decode("utf-8"),
                    aad=crypto.AAD_CREDENTIAL,
                )
            )
        )
    session.flush()

    with pytest.raises(DuplicateCredentialError) as erro:
        repo.find_by_service_login(session, chave, "github", "renan")

    assert "maiúsculas" in str(erro.value)
    assert "#" in str(erro.value)  # traz os ids para o usuário resolver


def test_update_para_par_colidente_e_barrado(session: Session, chave: bytes) -> None:
    repo.create_credential(session, chave, CredentialInput("github", "renan", "a"))
    segunda = repo.create_credential(
        session, chave, CredentialInput("github", "outro", "b")
    )
    session.flush()

    with pytest.raises(DuplicateCredentialError, match="maiúsculas"):
        repo.update_credential(session, chave, segunda, login="RENAN")


# ===========================================================================
# 5. Mensagem de duplicata nomeando o par errado
# ===========================================================================


def test_mensagem_de_duplicata_nomeia_o_valor_pretendido(
    session: Session, chave: bytes
) -> None:
    """A f-string lia o objeto DEPOIS do rollback do savepoint, com o valor antigo.

    O usuário tentava usar `ana`, e a mensagem apontava `bob` — o registro que ele
    estava editando. Ele concluiria que o próprio registro está duplicado e iria
    procurar um fantasma.
    """
    repo.create_credential(session, chave, CredentialInput("mail", "ana", "a"))
    bob = repo.create_credential(session, chave, CredentialInput("mail", "bob", "b"))
    session.flush()

    with pytest.raises(DuplicateCredentialError) as erro:
        repo.update_credential(session, chave, bob, login="ana")

    assert "'ana'" in str(erro.value)
    assert "'bob'" not in str(erro.value)


# ===========================================================================
# 6. Clipboard que prometia limpar e não limpava
# ===========================================================================


def test_flush_pending_limpa_o_que_estava_agendado(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No shell e na TUI o Timer daemon morria com o processo, sem limpar."""
    from vault.core import clipboard

    area = {"conteudo": ""}
    monkeypatch.setattr(clipboard.pyperclip, "copy", lambda t: area.__setitem__("conteudo", t))
    monkeypatch.setattr(clipboard.pyperclip, "paste", lambda: area["conteudo"])

    clipboard.copy_with_autoclear("senha-secreta", 3600)  # prazo longo de propósito
    assert area["conteudo"] == "senha-secreta"

    clipboard.flush_pending()
    assert area["conteudo"] == ""


def test_flush_pending_nao_apaga_o_que_o_usuario_copiou_depois(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vault.core import clipboard

    area = {"conteudo": ""}
    monkeypatch.setattr(clipboard.pyperclip, "copy", lambda t: area.__setitem__("conteudo", t))
    monkeypatch.setattr(clipboard.pyperclip, "paste", lambda: area["conteudo"])

    clipboard.copy_with_autoclear("senha-secreta", 3600)
    area["conteudo"] = "trabalho do usuário"  # ele copiou outra coisa

    clipboard.flush_pending()
    assert area["conteudo"] == "trabalho do usuário"


# ===========================================================================
# 7. TOTP: o caso POSITIVO, que não existia
# ===========================================================================


def test_totp_com_codigo_valido_destrava_pela_cli(
    cli_regressao: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """O teste anterior só cobria o caminho negativo.

    Ele passava mesmo com `_pedir_totp_se_necessario` substituído por
    `lambda: None` — ou seja, passaria com o plumbing de VAULT_TOTP_CODE morto.
    Testar o caso positivo primeiro é o que prova que o mecanismo existe.
    """
    runner.invoke(app, ["init"])
    ativacao = runner.invoke(app, ["totp", "enable"])
    assert ativacao.exit_code == 0, ativacao.output

    segredo = next(
        linha.split(":", 1)[1].strip()
        for linha in ativacao.output.splitlines()
        if linha.startswith("Segredo (guarde offline)")
    )

    monkeypatch.setenv("VAULT_TOTP_CODE", pyotp.TOTP(segredo).now())
    adicionado = runner.invoke(app, ["add", "github", "renan", "--generate", "--show"])
    assert adicionado.exit_code == 0, adicionado.output
    assert "guardada" in adicionado.output


def test_totp_com_codigo_invalido_e_recusado_pela_cli(
    cli_regressao: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.invoke(app, ["init"])
    ativacao = runner.invoke(app, ["totp", "enable"])
    segredo = next(
        linha.split(":", 1)[1].strip()
        for linha in ativacao.output.splitlines()
        if linha.startswith("Segredo (guarde offline)")
    )

    # Um código deliberadamente diferente do válido — sem depender de sorte.
    valido = pyotp.TOTP(segredo).now()
    invalido = f"{(int(valido) + 500000) % 1000000:06d}"
    monkeypatch.setenv("VAULT_TOTP_CODE", invalido)

    negado = runner.invoke(app, ["add", "github", "renan", "--generate", "--show"])
    assert negado.exit_code == 1
    assert "inválido" in negado.output.lower()


# ===========================================================================
# 8. Chave derivada com salt novo abre o que foi cifrado com ela
# ===========================================================================


def test_credencial_cifrada_e_ilegivel_com_parametros_alterados(
    session: Session, vault_com_parametros_proprios
) -> None:
    """Fixa a premissa por trás de tudo acima: parâmetros diferentes, chave outra."""
    config = get_vault_config(session)
    chave_certa = derive_encryption_key(
        SENHA_MESTRA,
        config.salt,
        KdfParams(time_cost=2, memory_cost=16, parallelism=2),
    )
    chave_com_padroes = derive_encryption_key(
        SENHA_MESTRA, config.salt, KdfParams(time_cost=3, memory_cost=65536, parallelism=4)
    )
    assert chave_certa != chave_com_padroes

    credencial = session.scalars(select(Credential)).one()
    assert repo.reveal(chave_certa, credencial).password == "senha-que-nao-pode-sumir"
    with pytest.raises(DecryptionError):
        repo.reveal(chave_com_padroes, credencial)


def test_salt_novo_gera_chave_nova() -> None:
    params = KdfParams(time_cost=1, memory_cost=8, parallelism=1)
    a = derive_encryption_key(SENHA_MESTRA, generate_salt(), params)
    b = derive_encryption_key(SENHA_MESTRA, generate_salt(), params)
    assert a != b


# ===========================================================================
# Fixture local
# ===========================================================================


@pytest.fixture
def cli_regressao(
    engine: Engine, database_url: str, monkeypatch: pytest.MonkeyPatch
) -> CliRunner:
    """CLI apontada para o banco de teste, com KDF barato e senha no ambiente."""
    from vault.config.settings import reset_settings_cache

    monkeypatch.setenv("DATABASE_URL", database_url)
    reset_settings_cache()
    monkeypatch.setenv("VAULT_MASTER_PASSWORD", SENHA_MESTRA)
    monkeypatch.setattr(
        "vault.core.master_password.KdfParams.from_settings",
        classmethod(lambda cls: KDF_TESTE),
    )
    monkeypatch.setattr(
        "vault.cli.main.clipboard.copy_with_autoclear",
        lambda texto, segundos: _timer_imediato(),
    )
    # Garante que o banco está de fato acessível pela URL configurada.
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return runner


def _timer_imediato():
    import threading

    timer = threading.Timer(0, lambda: None)
    timer.start()
    return timer
