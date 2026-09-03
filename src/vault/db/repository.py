"""Repositório de credenciais: CRUD (Fase 5) e busca (Fase 8).

Fronteira do módulo, e é o ponto principal do desenho:

- **Nada em texto puro atravessa a fronteira do banco.** Cifrar e decifrar
  acontece aqui dentro. Nenhuma camada acima (CLI, TUI) monta blob na mão nem
  escolhe AAD — se escolhesse, mais cedo ou mais tarde alguém cifraria uma nota
  com o rótulo de senha e o dado só falharia meses depois.
- **Listar não decifra.** `list_credentials` devolve metadados; `reveal` é a
  operação explícita que abre um segredo. Assim a tela de lista não precisa da
  chave e nenhuma senha passa por perto sem alguém ter pedido.

**Sobre transações: um repositório nunca chama `session.rollback()`.** A primeira
versão chamava, ao traduzir `IntegrityError` em `DuplicateCredentialError`, e o
efeito foi feio: o rollback desfaz a transação **inteira** do chamador — inclusive
trabalho que não é desta função — e, quando o `session_scope` externo tentava
comitar depois, a sessão já estava em estado inválido (`PendingRollbackError`) e a
conexão voltava suja para o pool. Na suíte contra Postgres isso aparecia como
`deadlock detected` intermitente no `DROP TABLE` do teste seguinte: uma conexão
presa em transação aberta segurando lock.

A ferramenta certa é o SAVEPOINT (`session.begin_nested()`): a operação que falhou
é revertida, a transação do chamador continua utilizável, e quem decide abortar
tudo é quem abriu a transação.

Sobre `LIKE`: `%` e `_` são curingas. Uma busca por `100%` sem escape casaria
qualquer coisa começando com `100`. O escape é feito em `_escape_like`, e a
comparação usa `lower()` dos dois lados — `ILIKE` seria mais direto, mas só
existe no Postgres, e a suíte roda em SQLite.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vault.core import crypto
from vault.core.totp import normalize_secret
from vault.db.models import Credential
from vault.exceptions import CredentialNotFoundError, DuplicateCredentialError


@dataclass(frozen=True, slots=True)
class CredentialInput:
    """Dados em claro para criar ou atualizar uma credencial."""

    service_name: str
    login: str
    password: str
    url: str | None = None
    notes: str | None = None
    totp_secret: str | None = None

    def validated(self) -> CredentialInput:
        service = self.service_name.strip()
        login = self.login.strip()
        if not service:
            raise ValueError("O nome do serviço não pode ser vazio.")
        if not login:
            raise ValueError("O login não pode ser vazio.")
        if not self.password:
            raise ValueError("A senha não pode ser vazia.")
        segredo = normalize_secret(self.totp_secret) if self.totp_secret else None
        return CredentialInput(
            service_name=service,
            login=login,
            password=self.password,
            url=(self.url or "").strip() or None,
            notes=self.notes if self.notes else None,
            totp_secret=segredo,
        )


@dataclass(frozen=True, slots=True)
class DecryptedCredential:
    """Uma credencial já aberta. Existe só em memória, nunca é persistida."""

    id: int
    service_name: str
    login: str
    url: str | None
    password: str
    notes: str | None
    totp_secret: str | None
    created_at: datetime
    updated_at: datetime


def _escape_like(term: str) -> str:
    """Neutraliza os curingas do LIKE para que a busca seja literal."""
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def create_credential(
    session: Session, key: bytes, data: CredentialInput
) -> Credential:
    """Cifra e grava uma credencial nova."""
    dados = data.validated()

    colidente = _colisao_case_insensitive(session, dados.service_name, dados.login)
    if colidente is not None:
        raise DuplicateCredentialError(
            f"Já existe a credencial #{colidente.id} "
            f"({colidente.service_name}/{colidente.login}), que difere de "
            f"{dados.service_name!r}/{dados.login!r} apenas em maiúsculas e "
            "minúsculas. Duas assim tornariam `vault get` ambíguo.\n"
            "Use `vault update` para alterar a existente."
        )

    credential = Credential(
        service_name=dados.service_name,
        login=dados.login,
        url=dados.url,
        encrypted_password=crypto.encrypt(
            key, dados.password, aad=crypto.AAD_PASSWORD
        ),
        encrypted_notes=crypto.encrypt_optional(
            key, dados.notes, aad=crypto.AAD_NOTES
        ),
        encrypted_totp_secret=crypto.encrypt_optional(
            key, dados.totp_secret, aad=crypto.AAD_TOTP
        ),
    )
    # SAVEPOINT, e não `session.rollback()`. Ver a nota sobre transações no topo.
    try:
        with session.begin_nested():
            session.add(credential)
            session.flush()
    except IntegrityError as exc:
        raise DuplicateCredentialError(
            f"Já existe uma credencial para {dados.service_name!r} com o login "
            f"{dados.login!r}. Use `vault update` para alterá-la."
        ) from exc

    return credential


def get_credential(session: Session, credential_id: int) -> Credential:
    credential = session.get(Credential, credential_id)
    if credential is None:
        raise CredentialNotFoundError(
            f"Credencial #{credential_id} não existe. Use `vault list` para ver as suas."
        )
    return credential


def find_by_service_login(
    session: Session, service_name: str, login: str
) -> Credential:
    """Busca exata pelo par (serviço, login), ignorando maiúsculas/minúsculas.

    Usa `.all()`, e não `.one_or_none()`, porque a busca é *case-insensitive* mas
    a `UniqueConstraint` do banco é *case-sensitive*: `github/renan` e
    `GitHub/renan` são duas linhas legítimas para o Postgres e ambas casam com a
    mesma busca. Com `one_or_none()` isso levantava `MultipleResultsFound`, que
    não é `VaultError` — a CLI não capturava, o usuário levava um traceback do
    SQLAlchemy na cara, e aquelas credenciais ficavam permanentemente
    inacessíveis por `vault get`.

    Agora vira um erro de domínio com os ids, e o usuário resolve. A criação
    também passou a barrar o par colidente (ver `_colisao_case_insensitive`), de
    modo que novos vaults não chegam nesse estado.
    """
    stmt = select(Credential).where(
        func.lower(Credential.service_name) == service_name.strip().lower(),
        func.lower(Credential.login) == login.strip().lower(),
    )
    achados = list(session.scalars(stmt))

    if not achados:
        raise CredentialNotFoundError(
            f"Nenhuma credencial de {service_name!r} com o login {login!r}."
        )
    if len(achados) > 1:
        detalhe = ", ".join(
            f"#{c.id} ({c.service_name}/{c.login})" for c in achados
        )
        raise DuplicateCredentialError(
            f"{len(achados)} credenciais casam com {service_name!r}/{login!r}, "
            f"diferindo apenas em maiúsculas/minúsculas: {detalhe}.\n"
            "Use `vault get` com o nome exato de uma delas, ou renomeie uma com "
            "`vault update`."
        )
    return achados[0]


def _colisao_case_insensitive(
    session: Session, service_name: str, login: str, *, ignorar_id: int | None = None
) -> Credential | None:
    """Credencial existente cujo par (serviço, login) só difere na caixa.

    A `UniqueConstraint` do banco é *case-sensitive* e não barra
    `GitHub/renan` ao lado de `github/renan`. Deixar entrar cria um par que a
    busca não consegue desambiguar. Barramos na aplicação, com mensagem clara.
    """
    stmt = select(Credential).where(
        func.lower(Credential.service_name) == service_name.strip().lower(),
        func.lower(Credential.login) == login.strip().lower(),
    )
    if ignorar_id is not None:
        stmt = stmt.where(Credential.id != ignorar_id)
    return session.scalars(stmt).first()


def list_credentials(session: Session) -> list[Credential]:
    """Todas as credenciais, ordenadas. Não decifra nada."""
    stmt = select(Credential).order_by(
        func.lower(Credential.service_name), func.lower(Credential.login)
    )
    return list(session.scalars(stmt))


def search_credentials(session: Session, query: str) -> list[Credential]:
    """Busca por substring em serviço, login e URL. Não decifra nada.

    Busca vazia devolve tudo — é o comportamento que a TUI espera ao limpar o
    campo, e é menos surpreendente que devolver lista vazia.
    """
    termo = query.strip()
    if not termo:
        return list_credentials(session)

    padrao = f"%{_escape_like(termo.lower())}%"
    stmt = (
        select(Credential)
        .where(
            or_(
                func.lower(Credential.service_name).like(padrao, escape="\\"),
                func.lower(Credential.login).like(padrao, escape="\\"),
                func.lower(func.coalesce(Credential.url, "")).like(
                    padrao, escape="\\"
                ),
            )
        )
        .order_by(func.lower(Credential.service_name), func.lower(Credential.login))
    )
    return list(session.scalars(stmt))


def reveal(key: bytes, credential: Credential) -> DecryptedCredential:
    """Abre todos os campos cifrados de uma credencial."""
    return DecryptedCredential(
        id=credential.id,
        service_name=credential.service_name,
        login=credential.login,
        url=credential.url,
        password=crypto.decrypt(
            key, credential.encrypted_password, aad=crypto.AAD_PASSWORD
        ),
        notes=crypto.decrypt_optional(
            key, credential.encrypted_notes, aad=crypto.AAD_NOTES
        ),
        totp_secret=crypto.decrypt_optional(
            key, credential.encrypted_totp_secret, aad=crypto.AAD_TOTP
        ),
        created_at=credential.created_at,
        updated_at=credential.updated_at,
    )


#: Sentinela para distinguir "não mexer neste campo" de "apagar este campo".
#: Sem ela, `update_credential(..., notes=None)` seria ambíguo: manter as notas
#: ou apagá-las? Este é o bug clássico de toda função de update com opcionais.
UNSET: object = object()


def update_credential(
    session: Session,
    key: bytes,
    credential: Credential,
    *,
    service_name: str | object = UNSET,
    login: str | object = UNSET,
    password: str | object = UNSET,
    url: str | object | None = UNSET,
    notes: str | object | None = UNSET,
    totp_secret: str | object | None = UNSET,
) -> Credential:
    """Atualiza os campos informados. Omitir um campo o preserva.

    Passar `None` explicitamente em `url`, `notes` ou `totp_secret` **apaga** o
    campo. Ver a nota sobre `UNSET` acima.

    Todas as atribuições acontecem **dentro** do SAVEPOINT, e isso não é estilo.
    A primeira versão alterava os atributos e só depois abria o savepoint para o
    flush; quando o flush violava a constraint de unicidade, o savepoint revertia
    o banco mas o objeto Python continuava com o valor novo e a sessão seguia
    marcada como suja. O autoflush da operação seguinte então re-emitia o mesmo
    UPDATE inválido, e o erro reaparecia num ponto sem relação com a causa. Com
    as atribuições dentro do savepoint, o SQLAlchemy restaura o snapshot dos
    objetos ao revertê-lo, e a credencial volta ao estado anterior na memória
    também.
    """
    # Os valores PRETENDIDOS são capturados agora, antes do flush. Depois do
    # rollback do SAVEPOINT o objeto volta aos valores antigos do banco — ler
    # `credential.login` na mensagem de erro apontaria o login que já estava lá,
    # e não o que o usuário tentou usar. O usuário procuraria um fantasma.
    servico_pretendido = (
        str(service_name).strip() if service_name is not UNSET else credential.service_name
    )
    login_pretendido = str(login).strip() if login is not UNSET else credential.login

    if service_name is not UNSET or login is not UNSET:
        colidente = _colisao_case_insensitive(
            session, servico_pretendido, login_pretendido, ignorar_id=credential.id
        )
        if colidente is not None:
            raise DuplicateCredentialError(
                f"Já existe a credencial #{colidente.id} "
                f"({colidente.service_name}/{colidente.login}), que difere de "
                f"{servico_pretendido!r}/{login_pretendido!r} apenas em "
                "maiúsculas e minúsculas."
            )

    try:
        with session.begin_nested():
            if service_name is not UNSET:
                novo_servico = str(service_name).strip()
                if not novo_servico:
                    raise ValueError("O nome do serviço não pode ser vazio.")
                credential.service_name = novo_servico

            if login is not UNSET:
                novo_login = str(login).strip()
                if not novo_login:
                    raise ValueError("O login não pode ser vazio.")
                credential.login = novo_login

            if password is not UNSET:
                nova_senha = str(password)
                if not nova_senha:
                    raise ValueError("A senha não pode ser vazia.")
                credential.encrypted_password = crypto.encrypt(
                    key, nova_senha, aad=crypto.AAD_PASSWORD
                )

            if url is not UNSET:
                credential.url = (
                    (str(url).strip() or None) if url is not None else None
                )

            if notes is not UNSET:
                credential.encrypted_notes = crypto.encrypt_optional(
                    key,
                    None if notes is None else str(notes),
                    aad=crypto.AAD_NOTES,
                )

            if totp_secret is not UNSET:
                segredo = (
                    None if totp_secret is None else normalize_secret(str(totp_secret))
                )
                credential.encrypted_totp_secret = crypto.encrypt_optional(
                    key, segredo, aad=crypto.AAD_TOTP
                )

            session.flush()
    except IntegrityError as exc:
        raise DuplicateCredentialError(
            f"Já existe outra credencial para {servico_pretendido!r} com o "
            f"login {login_pretendido!r}."
        ) from exc

    return credential


def delete_credential(session: Session, credential: Credential) -> None:
    session.delete(credential)
    session.flush()


def count_credentials(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(Credential)) or 0)
