"use client";

import { useCallback, useEffect, useState } from "react";

import {
  abrirVault,
  cifrarPayload,
  conferirChave,
  decifrarPayload,
  derivarChaves,
  ErroDeCripto,
} from "@/lib/crypto";

/** O que vai cifrado dentro de `encryptedData` — o servidor nunca vê isto. */
type VaultPayload = {
  serviceName: string;
  login: string;
  password: string;
  url?: string;
};

/** O que a API devolve: id e blob opaco, nada mais. */
type VaultRecord = { id: string; encryptedData: string; version: number };

type VaultItem = VaultPayload & { id: string };

type Config = {
  initialized: boolean;
  salt?: string;
  kdfIterations?: number;
  wrappedVaultKey?: string;
  keyCheck?: string;
};

/**
 * Parâmetros fixados no primeiro unlock bem-sucedido.
 *
 * O servidor serve `salt` e `kdfIterations` sem autenticação — isso é correto e
 * necessário, o cliente precisa deles antes de ter qualquer chave. O que **não**
 * é aceitável é que eles mudem depois. Fixar aqui detecta troca por quem ganhou
 * escrita no banco.
 */
const CHAVE_PIN = "secure-vault:pin:v1";

type Pin = { salt: string; kdfIterations: number };

function lerPin(): Pin | null {
  try {
    const cru = localStorage.getItem(CHAVE_PIN);
    return cru ? (JSON.parse(cru) as Pin) : null;
  } catch {
    return null;
  }
}

function gravarPin(pin: Pin): void {
  try {
    localStorage.setItem(CHAVE_PIN, JSON.stringify(pin));
  } catch {
    // Aba anônima ou storage bloqueado: seguir sem pin é pior que falhar? Não —
    // o piso de iterações continua valendo, que é a defesa que importa. O pin é
    // camada extra, e perdê-la não pode impedir o dono de abrir o próprio vault.
  }
}

export default function VaultApp() {
  const [config, setConfig] = useState<Config | null>(null);
  const [masterPassword, setMasterPassword] = useState("");
  const [chaveVault, setChaveVault] = useState<CryptoKey | null>(null);
  const [vault, setVault] = useState<VaultItem[]>([]);
  const [naoAbriram, setNaoAbriram] = useState(0);
  const [search, setSearch] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [erro, setErro] = useState<string | null>(null);

  const [isAdding, setIsAdding] = useState(false);
  const [serviceName, setServiceName] = useState("");
  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const [url, setUrl] = useState("");

  useEffect(() => {
    fetch("/api/vault/config")
      .then((r) => r.json())
      .then(setConfig)
      .catch(() => setErro("Não foi possível falar com o servidor."));
  }, []);

  const carregarVault = useCallback(async (chave: CryptoKey) => {
    const res = await fetch("/api/vault");
    if (res.status === 401) {
      setChaveVault(null);
      setErro("Sessão expirada. Destranque de novo.");
      return;
    }
    if (!res.ok) throw new Error("Falha ao ler o vault.");

    const registros: VaultRecord[] = await res.json();
    const abertos: VaultItem[] = [];
    let falharam = 0;

    for (const registro of registros) {
      try {
        const payload = await decifrarPayload<VaultPayload>(chave, registro.encryptedData);
        abertos.push({ ...payload, id: registro.id });
      } catch {
        // ⛔ NUNCA descartar em silêncio. A versão anterior fazia
        // `decrypted.filter(Boolean)`: com zero sobreviventes a tela dizia
        // "No items found" — a mesma tela de vault vazio. Chave errada,
        // rebaixamento de KDF, vault meio-migrado e blob adulterado produziam
        // todos o mesmo resultado, e o desfecho realista era o dono recadastrar
        // tudo sob parâmetros escolhidos pelo atacante.
        falharam++;
      }
    }

    setVault(abertos);
    setNaoAbriram(falharam);
  }, []);

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setErro(null);
    setIsLoading(true);
    try {
      if (!config?.initialized || !config.salt || !config.kdfIterations) {
        throw new Error("Vault não inicializado. Rode `npm run vault:init`.");
      }

      const pin = lerPin();
      if (
        pin &&
        (pin.salt !== config.salt || pin.kdfIterations !== config.kdfIterations)
      ) {
        throw new Error(
          "Os parâmetros do vault MUDARAM desde o último acesso neste navegador. " +
            "Isso não acontece sozinho. Não digite sua senha até entender o motivo."
        );
      }

      // `derivarChaves` recusa sozinha qualquer valor abaixo do piso.
      const { authValue, chaveEnvelope } = await derivarChaves(
        masterPassword,
        config.salt,
        config.kdfIterations
      );

      const login = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ authValue }),
      });
      if (!login.ok) {
        const corpo = await login.json().catch(() => ({}));
        throw new Error(corpo.error ?? "Credenciais inválidas.");
      }

      const chave = await abrirVault(chaveEnvelope, config.wrappedVaultKey!);

      // Sentinela ANTES de renderizar qualquer coisa. O `authValue` não serve
      // para isto: ele prova que o servidor aceitou você, não que a sua chave
      // abre os dados. Sob rebaixamento de KDF os dois discordam.
      if (!(await conferirChave(chave, config.keyCheck!))) {
        throw new Error(
          "A chave derivada não abre este vault. Os dados podem ter sido " +
            "alterados por fora da aplicação."
        );
      }

      gravarPin({ salt: config.salt, kdfIterations: config.kdfIterations });
      setChaveVault(chave);
      setMasterPassword("");
      await carregarVault(chave);
    } catch (erroAberto) {
      setErro(
        erroAberto instanceof ErroDeCripto || erroAberto instanceof Error
          ? erroAberto.message
          : "Falha ao destrancar."
      );
    } finally {
      setIsLoading(false);
    }
  };

  const trancar = async () => {
    await fetch("/api/auth/logout", { method: "POST" }).catch(() => {});
    setChaveVault(null);
    setVault([]);
    setNaoAbriram(0);
    setMasterPassword("");
  };

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chaveVault) return;
    setIsLoading(true);
    setErro(null);
    try {
      const encryptedData = await cifrarPayload<VaultPayload>(chaveVault, {
        serviceName,
        login,
        password,
        url: url || undefined,
      });
      const res = await fetch("/api/vault", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ encryptedData }),
      });
      if (!res.ok) throw new Error("Falha ao salvar.");
      await carregarVault(chaveVault);
      setIsAdding(false);
      setServiceName("");
      setLogin("");
      setPassword("");
      setUrl("");
    } catch (e) {
      setErro(e instanceof Error ? e.message : "Falha ao salvar.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!chaveVault) return;
    if (!confirm("Apagar esta credencial?")) return;
    try {
      await fetch("/api/vault/" + id, { method: "DELETE" });
      await carregarVault(chaveVault);
    } catch (e) {
      setErro(e instanceof Error ? e.message : "Falha ao apagar.");
    }
  };

  const filtrado = vault.filter(
    (item) =>
      item.serviceName.toLowerCase().includes(search.toLowerCase()) ||
      item.login.toLowerCase().includes(search.toLowerCase()) ||
      (item.url && item.url.toLowerCase().includes(search.toLowerCase()))
  );

  if (!chaveVault) {
    return (
      <div className="min-h-screen bg-gray-950 text-white flex flex-col items-center justify-center p-4">
        <div className="w-full max-w-md bg-gray-900 p-8 rounded-xl shadow-xl border border-gray-800">
          <h1 className="text-3xl font-bold mb-2 text-center">Secure Vault</h1>
          <p className="text-gray-400 text-center mb-8">Zero-Knowledge Web Client</p>

          {config && !config.initialized ? (
            <div className="text-sm text-gray-300 space-y-3">
              <p className="text-yellow-400 font-medium">Vault ainda não criado.</p>
              <p>
                A inicialização é local, de propósito — uma rota pública de criação
                deixaria qualquer um trancar o dono para fora antes do primeiro acesso.
              </p>
              <code className="block bg-gray-800 rounded px-3 py-2">npm run vault:init</code>
            </div>
          ) : (
            <form onSubmit={handleUnlock} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Senha mestra</label>
                <input
                  type="password"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-blue-500"
                  value={masterPassword}
                  onChange={(e) => setMasterPassword(e.target.value)}
                  required
                  autoFocus
                />
              </div>
              <button
                type="submit"
                disabled={isLoading || !config}
                className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-bold py-2 px-4 rounded-lg transition-colors"
              >
                {isLoading ? "Destrancando…" : "Destrancar"}
              </button>
            </form>
          )}

          {erro && (
            <p className="mt-4 text-sm text-red-400 border border-red-900/50 bg-red-950/30 rounded-lg p-3">
              {erro}
            </p>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-950 text-white p-8">
      <div className="max-w-4xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold">Meu vault</h1>
          <button onClick={trancar} className="text-gray-400 hover:text-white">
            Trancar
          </button>
        </div>

        {naoAbriram > 0 && (
          <div className="mb-6 text-sm text-yellow-300 border border-yellow-900/50 bg-yellow-950/30 rounded-lg p-3">
            <strong>
              {naoAbriram} de {naoAbriram + vault.length} registros não puderam ser abertos.
            </strong>{" "}
            Isso não é vault vazio: ou o dado foi alterado por fora da aplicação, ou foi
            gravado por outra versão. Não recadastre nada até entender o motivo.
          </div>
        )}

        {erro && (
          <div className="mb-6 text-sm text-red-400 border border-red-900/50 bg-red-950/30 rounded-lg p-3">
            {erro}
          </div>
        )}

        <div className="flex justify-between items-center mb-6 gap-4">
          <input
            type="text"
            placeholder="Buscar no vault…"
            className="flex-1 bg-gray-900 border border-gray-800 rounded-lg px-4 py-2 focus:outline-none focus:border-blue-500"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <button
            onClick={() => setIsAdding(!isAdding)}
            className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg font-medium"
          >
            {isAdding ? "Cancelar" : "+ Adicionar"}
          </button>
        </div>

        {isAdding && (
          <form
            onSubmit={handleAdd}
            className="bg-gray-900 p-6 rounded-xl border border-gray-800 mb-6 space-y-4"
          >
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Serviço</label>
                <input
                  required
                  type="text"
                  value={serviceName}
                  onChange={(e) => setServiceName(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  URL (opcional)
                </label>
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Login</label>
                <input
                  required
                  type="text"
                  value={login}
                  onChange={(e) => setLogin(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Senha</label>
                <input
                  required
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2"
                />
              </div>
            </div>
            <button
              type="submit"
              disabled={isLoading}
              className="bg-green-600 hover:bg-green-700 w-full py-2 rounded-lg font-medium mt-4"
            >
              {isLoading ? "Salvando…" : "Salvar credencial"}
            </button>
          </form>
        )}

        <div className="space-y-4">
          {filtrado.map((item) => (
            <div
              key={item.id}
              className="bg-gray-900 p-4 rounded-xl border border-gray-800 flex justify-between items-center"
            >
              <div>
                <h3 className="font-bold text-lg">{item.serviceName}</h3>
                <p className="text-gray-400 text-sm">{item.login}</p>
                {item.url && (
                  <a
                    href={item.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-blue-400 text-xs hover:underline"
                  >
                    {item.url}
                  </a>
                )}
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => navigator.clipboard.writeText(item.password)}
                  className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded text-sm text-gray-300"
                >
                  Copiar senha
                </button>
                <button
                  onClick={() => handleDelete(item.id)}
                  className="px-3 py-1 bg-red-900/30 hover:bg-red-900/60 text-red-400 rounded text-sm"
                >
                  Apagar
                </button>
              </div>
            </div>
          ))}
          {filtrado.length === 0 && !isLoading && naoAbriram === 0 && (
            <div className="text-center py-12 text-gray-500">
              {vault.length === 0 ? "Vault vazio." : "Nada corresponde à busca."}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
