"""Repositório de credenciais: CRUD (Fase 5) e busca (Fase 8), Zero-Knowledge.

Fronteira do módulo, e é o ponto principal do desenho:

- **Nada em texto puro atravessa a fronteira do banco.** Cifrar e decifrar
  acontece aqui dentro. Nenhuma camada acima (CLI, TUI) monta blob na mão nem
  escolhe AAD — se escolhesse, mais cedo ou mais tarde alguém cifraria uma nota
  com o rótulo de senha e o dado só falharia meses depois.
- **A credencial inteira é UM blob opaco** (`Credential.encrypted_data`),
  serializado por `vault.core.schema.PayloadSerializer` e cifrado sob
  `crypto.AAD_CREDENTIAL`. O banco não sabe o nome do serviço, o login nem a URL.

## O que a arquitetura Zero-Knowledge custou, e por que não dá para evitar

A versão anterior prometia: *"Listar não decifra — a tela de lista não precisa da
chave e nenhuma senha passa por perto sem alguém ter pedido."* **Essa promessa
morreu com a migration `edb62ca16834`, e não por descuido.** Quando serviço,
login e URL deixam de existir em texto puro, não há nada para ordenar nem filtrar
em SQL: listar e buscar passam, por definição, a exigir a chave e a decifrar tudo.
`func.lower(Credential.service_name)` não tem substituto — a coluna não existe, e
o índice `ix_credentials_service_name` foi derrubado junto.

O que **ainda** dá para preservar é o resto da promessa, e é o que este módulo
faz: quem lista recebe `CredentialMetadata`, que **não carrega a senha, as notas
nem o segredo TOTP**. Os campos secretos são decifrados em memória durante a
varredura e descartados; só `reveal()` devolve um objeto com a senha dentro.
Isso não é cosmético: impede que uma lista renderizada, um log de debug ou um
`repr()` acidental derrame segredo de 200 credenciais de uma vez.

⚠️ **A proteção é da SAÍDA, não da memória.** Durante a varredura o payload
completo de cada credencial — senha inclusive — existe em memória como `str`
imutável, que `crypto.wipe` não alcança. `_varrer` é gerador justamente para
manter **um** payload vivo por vez em vez de N, mas isso reduz a janela, não a
elimina. *Memory dumping* está fora do escopo declarado no README, e com razão:
quem lê a memória do processo já tem a chave derivada.

O custo que sobra é real e está medido: uma busca é O(n) decifrações de AES-GCM.
Para a ordem de grandeza de um vault pessoal (centenas de credenciais) isso é
irrelevante. Se um dia virar problema, a saída **não** é voltar a gravar metadado
em claro — é um segundo blob por linha, um só para os campos buscáveis, para que
a varredura não precise tocar na senha. O schema atual (uma coluna `encrypted_data`,
igual no `web/prisma/schema.prisma`) não comporta isso sem nova migration.

## Unicidade passou a ser da aplicação, e isso não é opcional

A `UniqueConstraint(service_name, login)` sumiu com as colunas. **O banco não
barra mais nada**, então o `IntegrityError` que traduzíamos em
`DuplicateCredentialError` nunca mais acontece. A checagem virou
`_colisao_case_insensitive`, que varre e decifra antes de gravar. Ela é a única
barreira: removê-la não faz o banco reclamar depois — faz duas credenciais iguais
entrarem em silêncio e `vault get` ficar ambíguo para sempre.

## Exclusão é FÍSICA aqui, e `deleted_at` é do vault web

`delete_credential` apaga a linha. A primeira versão deste refactor marcava
`deleted_at` — o motivo de ter mudado, com a medição que decidiu, está no
docstring da própria função. Resumo: a senha apagada sobrevivia à troca de senha
mestra, para sempre, enquanto a CLI dizia "apagada".

**Toda leitura ainda filtra `deleted_at IS NULL`**, e `_vivas()` existe para que
esse filtro fique num lugar só. Não é sobra: o vault web
(`web/prisma/schema.prisma`) tem a mesma coluna e a usa como tombstone de
sincronização. Se um dia os dois lados dividirem o banco, a linha que o web
marcou não pode aparecer aqui.

A exceção deliberada é `change_master_password`, que re-cifra **sem** o filtro:
pular uma linha marcada a tornaria indecifrável para sempre, porque a chave
velha deixa de existir na troca.

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

Sobre a busca por substring: ela é feita em Python, com `in` sobre texto já
decifrado e rebaixado para minúsculas. Não há mais `LIKE`, e portanto **não há
mais curinga para escapar** — `100%` e `admin_root` são literais naturalmente.
O antigo `_escape_like` foi removido por isso; os testes que provavam o escape
continuam valendo como prova de que a busca é literal.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vault.core import crypto
from vault.core.schema import CredentialPayload, PayloadSerializer
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
class CredentialMetadata:
    """Identificação de uma credencial, **sem nenhum segredo dentro**.

    É o que `list_credentials`, `search_credentials` e `find_by_service_login`
    devolvem. Montar isto exige decifrar o blob (ver a nota no topo do módulo),
    mas a senha, as notas e o segredo TOTP são descartados na hora e nunca
    entram no objeto — então uma lista, um log ou um `repr()` não derramam
    segredo. Para abrir os segredos existe `reveal()`, que é explícito.
    """

    id: int
    service_name: str
    login: str
    url: str | None
    has_totp: bool
    created_at: datetime
    updated_at: datetime


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


def _vivas() -> object:
    """Filtro único de exclusão lógica. Toda leitura passa por aqui."""
    return Credential.deleted_at.is_(None)


def _guardar_payload(
    key: bytes, credential: Credential, payload: CredentialPayload
) -> None:
    """Serializa, cifra e grava o payload no blob opaco."""
    credential.encrypted_data = crypto.encrypt(
        key, PayloadSerializer.dump(payload).decode("utf-8"), aad=crypto.AAD_CREDENTIAL
    )


def _abrir_payload(key: bytes, credential: Credential) -> CredentialPayload:
    """Decifra o blob opaco de volta para o payload.

    Deixa `DecryptionError` subir: chave errada ou blob adulterado não é um
    detalhe a engolir — é exatamente o que o AEAD existe para detectar.
    """
    return PayloadSerializer.load(
        crypto.decrypt(key, credential.encrypted_data, aad=crypto.AAD_CREDENTIAL)
    )


def _metadados(credential: Credential, payload: CredentialPayload) -> CredentialMetadata:
    return CredentialMetadata(
        id=credential.id,
        service_name=payload.service_name,
        login=payload.login,
        url=payload.url,
        has_totp=payload.totp_secret is not None,
        created_at=credential.created_at,
        updated_at=credential.updated_at,
    )


def _ordem(meta: CredentialMetadata) -> tuple[str, str]:
    """Mesma ordenação de antes (serviço, login, sem caixa) — agora em Python."""
    return (meta.service_name.lower(), meta.login.lower())


def _varrer(
    session: Session, key: bytes
) -> Iterator[tuple[Credential, CredentialPayload]]:
    """Decifra as credenciais vivas uma a uma, na ordem do id.

    É o único ponto que decifra em massa. Quem chama filtra ou ordena depois.

    **Gerador, e não lista, de propósito.** A versão anterior devolvia
    `list[...]`, o que deixava o `CredentialPayload` COMPLETO de toda credencial
    — senha, notas e TOTP — vivo em memória ao mesmo tempo, como `str` imutável
    que `crypto.wipe` não alcança. Num vault de 200 credenciais, buscar por uma
    materializava as 200 senhas de uma vez. A TUI torna isso concreto: ela chama
    a busca a cada `Input.Changed`, ou seja **a cada tecla digitada**.

    Como gerador, o interpretador mantém um payload por vez e o anterior fica
    elegível para coleta. Não é proteção contra *memory dumping* — isso está
    fora do escopo declarado no README, e um atacante com a memória do processo
    já tem a chave. É reduzir a janela pelo custo de uma palavra.
    """
    stmt = select(Credential).where(_vivas()).order_by(Credential.id)
    for credential in session.scalars(stmt):
        yield credential, _abrir_payload(key, credential)


def create_credential(
    session: Session, key: bytes, data: CredentialInput
) -> Credential:
    """Cifra e grava uma credencial nova."""
    dados = data.validated()

    colidente = _colisao_case_insensitive(session, key, dados.service_name, dados.login)
    if colidente is not None:
        raise DuplicateCredentialError(
            f"Já existe a credencial #{colidente.id} "
            f"({colidente.service_name}/{colidente.login}), que difere de "
            f"{dados.service_name!r}/{dados.login!r} apenas em maiúsculas e "
            "minúsculas. Duas assim tornariam `vault get` ambíguo.\n"
            "Use `vault update` para alterar a existente."
        )

    payload = CredentialPayload(
        service_name=dados.service_name,
        login=dados.login,
        password=dados.password,
        url=dados.url,
        notes=dados.notes,
        totp_secret=dados.totp_secret,
    )
    credential = Credential(encrypted_data=b"")
    _guardar_payload(key, credential, payload)

    # SAVEPOINT, e não `session.rollback()`. Ver a nota sobre transações no topo.
    with session.begin_nested():
        session.add(credential)
        session.flush()

    return credential


def get_credential(session: Session, credential_id: int) -> Credential:
    """Busca por id. Não decifra — devolve a linha para as operações de escrita."""
    credential = session.get(Credential, credential_id)
    if credential is None or credential.deleted_at is not None:
        raise CredentialNotFoundError(
            f"Credencial #{credential_id} não existe. Use `vault list` para ver as suas."
        )
    return credential


def find_by_service_login(
    session: Session, key: bytes, service_name: str, login: str
) -> CredentialMetadata:
    """Busca exata pelo par (serviço, login), ignorando maiúsculas/minúsculas.

    Devolve **todos** os casos antes de decidir, e não o primeiro, porque a
    unicidade agora é só da aplicação: um vault criado por uma versão anterior —
    ou por um cliente que não fizesse a checagem — pode ter `github/renan` e
    `GitHub/renan` lado a lado. Com o "primeiro que aparecer", uma das duas
    ficaria permanentemente inacessível por `vault get` e ninguém saberia por quê.
    Aqui vira erro de domínio com os ids, e o usuário resolve.
    """
    alvo_servico = service_name.strip().lower()
    alvo_login = login.strip().lower()
    achados = [
        _metadados(c, p)
        for c, p in _varrer(session, key)
        if p.service_name.lower() == alvo_servico and p.login.lower() == alvo_login
    ]

    if not achados:
        raise CredentialNotFoundError(
            f"Nenhuma credencial de {service_name!r} com o login {login!r}."
        )
    if len(achados) > 1:
        detalhe = ", ".join(f"#{m.id} ({m.service_name}/{m.login})" for m in achados)
        raise DuplicateCredentialError(
            f"{len(achados)} credenciais casam com {service_name!r}/{login!r}, "
            f"diferindo apenas em maiúsculas/minúsculas: {detalhe}.\n"
            "Use `vault get` com o nome exato de uma delas, ou renomeie uma com "
            "`vault update`."
        )
    return achados[0]


def _colisao_case_insensitive(
    session: Session,
    key: bytes,
    service_name: str,
    login: str,
    *,
    ignorar_id: int | None = None,
) -> CredentialMetadata | None:
    """Credencial existente cujo par (serviço, login) só difere na caixa.

    **Esta função é a única barreira de unicidade que sobrou.** O banco perdeu a
    `UniqueConstraint` junto com as colunas em texto puro, então não há rede
    embaixo: se isto não barrar, o par duplicado entra calado.
    """
    alvo_servico = service_name.strip().lower()
    alvo_login = login.strip().lower()
    for c, p in _varrer(session, key):
        if ignorar_id is not None and c.id == ignorar_id:
            continue
        if p.service_name.lower() == alvo_servico and p.login.lower() == alvo_login:
            return _metadados(c, p)
    return None


def list_credentials(session: Session, key: bytes) -> list[CredentialMetadata]:
    """Todas as credenciais vivas, ordenadas por serviço e login.

    Precisa da chave: sem ela não há nome de serviço para ordenar. Ver a nota
    sobre o custo do Zero-Knowledge no topo do módulo. O que volta **não contém
    senha**.
    """
    return sorted((_metadados(c, p) for c, p in _varrer(session, key)), key=_ordem)


def search_credentials(
    session: Session, key: bytes, query: str
) -> list[CredentialMetadata]:
    """Busca por substring em serviço, login e URL. O que volta não contém senha.

    Busca vazia devolve tudo — é o comportamento que a TUI espera ao limpar o
    campo, e é menos surpreendente que devolver lista vazia.

    A comparação é literal: `%` e `_` são caracteres comuns aqui, não curingas,
    porque não existe mais `LIKE` no caminho. A senha e as notas **não** entram
    na busca, de propósito: casar por conteúdo de senha vazaria a senha pelo
    resultado da busca.
    """
    termo = query.strip().lower()
    if not termo:
        return list_credentials(session, key)

    achados = [
        _metadados(c, p)
        for c, p in _varrer(session, key)
        if termo in p.service_name.lower()
        or termo in p.login.lower()
        or termo in (p.url or "").lower()
    ]
    return sorted(achados, key=_ordem)


def reveal(key: bytes, credential: Credential) -> DecryptedCredential:
    """Abre a credencial inteira, segredos incluídos. É a operação explícita."""
    payload = _abrir_payload(key, credential)
    return DecryptedCredential(
        id=credential.id,
        service_name=payload.service_name,
        login=payload.login,
        url=payload.url,
        password=payload.password,
        notes=payload.notes,
        totp_secret=payload.totp_secret,
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

    O payload é aberto, alterado e re-cifrado **inteiro** — é o que o blob único
    impõe. Consequência que vale saber: toda alteração, mesmo só da URL, gera
    nonce novo e texto cifrado novo para a credencial inteira. Isso é bom para
    a privacidade (o tamanho e o conteúdo do blob não denunciam qual campo mudou)
    e significa que não existe atualização parcial no disco.

    O histórico de senhas (`payload.history`) é **preservado como está**. Esta
    função não acrescenta entradas: quem decide registrar histórico é a camada
    que sabe o porquê da troca, e inventar isso aqui gravaria senha antiga em
    toda alteração de URL.

    A atribuição acontece **dentro** do SAVEPOINT, e isso não é estilo. A primeira
    versão alterava os atributos e só depois abria o savepoint para o flush;
    quando o flush falhava, o savepoint revertia o banco mas o objeto Python
    continuava com o valor novo e a sessão seguia marcada como suja. O autoflush
    da operação seguinte então re-emitia o mesmo UPDATE inválido, e o erro
    reaparecia num ponto sem relação com a causa.
    """
    atual = _abrir_payload(key, credential)

    # Os valores PRETENDIDOS são resolvidos e validados ANTES de tocar no objeto,
    # para que a mensagem de erro cite o que o usuário tentou usar, e não o que
    # já estava gravado — procurar um fantasma é pior que não achar nada.
    if service_name is not UNSET:
        novo_servico = str(service_name).strip()
        if not novo_servico:
            raise ValueError("O nome do serviço não pode ser vazio.")
    else:
        novo_servico = atual.service_name

    if login is not UNSET:
        novo_login = str(login).strip()
        if not novo_login:
            raise ValueError("O login não pode ser vazio.")
    else:
        novo_login = atual.login

    if password is not UNSET:
        nova_senha = str(password)
        if not nova_senha:
            raise ValueError("A senha não pode ser vazia.")
    else:
        nova_senha = atual.password

    if service_name is not UNSET or login is not UNSET:
        colidente = _colisao_case_insensitive(
            session, key, novo_servico, novo_login, ignorar_id=credential.id
        )
        if colidente is not None:
            raise DuplicateCredentialError(
                f"Já existe a credencial #{colidente.id} "
                f"({colidente.service_name}/{colidente.login}), que difere de "
                f"{novo_servico!r}/{novo_login!r} apenas em "
                "maiúsculas e minúsculas."
            )

    novo = replace(
        atual,
        service_name=novo_servico,
        login=novo_login,
        password=nova_senha,
        url=(
            atual.url
            if url is UNSET
            else ((str(url).strip() or None) if url is not None else None)
        ),
        notes=(
            atual.notes if notes is UNSET else (None if notes is None else str(notes))
        ),
        totp_secret=(
            atual.totp_secret
            if totp_secret is UNSET
            else (None if totp_secret is None else normalize_secret(str(totp_secret)))
        ),
    )

    with session.begin_nested():
        _guardar_payload(key, credential, novo)
        session.flush()

    return credential


def delete_credential(session: Session, credential: Credential) -> None:
    """Exclusão **física**: a linha sai do banco.

    ## Por que não é exclusão lógica, tendo `deleted_at` no schema

    A primeira versão deste refactor marcava `deleted_at` e mantinha a linha —
    parecia o uso natural da coluna nova. Uma revisão adversarial mediu o que
    isso significava na prática, em 22/09/2026, e o resultado decidiu a questão:

        apos `vault delete`:  list -> []   count -> 0
        a linha ainda existe no banco?     -> True
        a senha antiga ainda abre?         -> 'SENHA-VAZADA-QUE-EU-QUERO-SUMIR'
        apos `vault passwd`, ela abre com a CHAVE NOVA? -> a mesma senha

    O caso que importa é o único motivo real de alguém apagar uma credencial:
    **a senha vazou.** O usuário troca no site, roda `vault delete`, lê
    "Credencial apagada" e acredita que a senha comprometida saiu do vault. Ela
    continuava no arquivo `.db`, em todo backup feito desde então, e
    `change_master_password` a **re-cifrava com a chave nova** a cada rotação —
    sobrevivendo indefinidamente, sem nenhum comando que a listasse ou removesse.

    Num gerenciador de senhas, "apaguei" tem de significar apagado. A alternativa
    seria manter o soft delete e trocar o texto da CLI para "ocultar", mas isso
    entrega menos do que o usuário pediu justamente na hora em que ele mais
    precisa que tenha sido feito.

    **`deleted_at` continua no modelo, e não é sobra:** o vault web
    (`web/prisma/schema.prisma`) tem a mesma coluna e precisa dela como
    *tombstone* de sincronização — sem marcar a exclusão, um dispositivo que
    apagou não tem como contar isso ao outro, e a credencial ressuscita no
    próximo sync. Esta CLI é local e não sincroniza, então aqui o registro não
    serve para nada e o custo dele é o fantasma acima. As leituras continuam
    filtrando por `_vivas()` de propósito: se um dia os dois lados dividirem o
    mesmo banco, a linha marcada pelo web não pode aparecer aqui.
    """
    session.delete(credential)
    session.flush()


def purge_all_credentials(session: Session) -> int:
    """Apaga **de verdade** todas as linhas, vivas e já excluídas. Devolve quantas.

    Existe para o `vault destroy`, e é o único caminho de exclusão física. Não
    decifra nada de propósito: destruir o vault inteiro não precisa da chave, e
    exigi-la só criaria um jeito de ficar com lixo cifrado impossível de remover
    caso a senha mestra se perca.

    Não use isto para apagar uma credencial: `delete_credential` é lógico e tem
    volta; este não tem.
    """
    linhas = list(session.scalars(select(Credential)))
    for linha in linhas:
        session.delete(linha)
    session.flush()
    return len(linhas)


def count_credentials(session: Session) -> int:
    """Quantas credenciais vivas. Não decifra nada — é contagem no banco."""
    return int(
        session.scalar(select(func.count()).select_from(Credential).where(_vivas())) or 0
    )
