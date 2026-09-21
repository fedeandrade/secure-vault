"use client";

import { useState, useEffect } from "react";
import { deriveKey, encryptPayload, decryptPayload } from "@/lib/crypto";

export default function VaultApp() {
  const [masterPassword, setMasterPassword] = useState("");
  const [cryptoKey, setCryptoKey] = useState<CryptoKey | null>(null);
  const [records, setRecords] = useState<any[]>([]);
  const [decryptedVault, setDecryptedVault] = useState<any[]>([]);
  const [search, setSearch] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  // Form states
  const [isAdding, setIsAdding] = useState(false);
  const [serviceName, setServiceName] = useState("");
  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const [url, setUrl] = useState("");

  const SALT = "secure-vault-global-salt"; // Hardcoded for this simple MVP

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const key = await deriveKey(masterPassword, SALT);
      setCryptoKey(key);
      await fetchVault(key);
    } catch (err) {
      alert("Failed to unlock");
    } finally {
      setIsLoading(false);
    }
  };

  const fetchVault = async (key: CryptoKey) => {
    setIsLoading(true);
    try {
      const res = await fetch("/api/vault");
      if (res.ok) {
        const data = await res.json();
        setRecords(data);
        
        // Decrypt in memory
        const decrypted = await Promise.all(
          data.map(async (record: any) => {
            try {
              const payload = await decryptPayload(key, record.encryptedData);
              return { ...payload, id: record.id };
            } catch (e) {
              console.error("Decryption failed for record", record.id);
              return null;
            }
          })
        );
        setDecryptedVault(decrypted.filter(Boolean));
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!cryptoKey) return;
    
    setIsLoading(true);
    try {
      const payload = { serviceName, login, password, url };
      const encryptedData = await encryptPayload(cryptoKey, payload);
      
      const res = await fetch("/api/vault", {
        method: "POST",
        body: JSON.stringify({ encryptedData }),
        headers: { "Content-Type": "application/json" }
      });
      
      if (res.ok) {
        await fetchVault(cryptoKey);
        setIsAdding(false);
        setServiceName(""); setLogin(""); setPassword(""); setUrl("");
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!cryptoKey) return;
    if (!confirm("Delete this credential?")) return;
    try {
      await fetch("/api/vault/" + id, { method: "DELETE" });
      await fetchVault(cryptoKey);
    } catch(e) { console.error(e) }
  }

  // Filter local vault based on search
  const filteredVault = decryptedVault.filter(item => 
    item.serviceName.toLowerCase().includes(search.toLowerCase()) || 
    item.login.toLowerCase().includes(search.toLowerCase()) ||
    (item.url && item.url.toLowerCase().includes(search.toLowerCase()))
  );

  if (!cryptoKey) {
    return (
      <div className="min-h-screen bg-gray-950 text-white flex flex-col items-center justify-center p-4">
        <div className="w-full max-w-md bg-gray-900 p-8 rounded-xl shadow-xl border border-gray-800">
          <h1 className="text-3xl font-bold mb-2 text-center">Secure Vault</h1>
          <p className="text-gray-400 text-center mb-8">Zero-Knowledge Web Client</p>
          <form onSubmit={handleUnlock} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">Master Password</label>
              <input 
                type="password"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-blue-500"
                value={masterPassword}
                onChange={e => setMasterPassword(e.target.value)}
                required
              />
            </div>
            <button 
              type="submit" 
              disabled={isLoading}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-lg transition-colors"
            >
              {isLoading ? 'Unlocking...' : 'Unlock Vault'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-950 text-white p-8">
      <div className="max-w-4xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold">My Vault</h1>
          <button 
            onClick={() => { setCryptoKey(null); setMasterPassword(""); setDecryptedVault([]); }}
            className="text-gray-400 hover:text-white"
          >
            Lock
          </button>
        </div>

        <div className="flex justify-between items-center mb-6 gap-4">
          <input 
            type="text" 
            placeholder="Search vault..."
            className="flex-1 bg-gray-900 border border-gray-800 rounded-lg px-4 py-2 focus:outline-none focus:border-blue-500"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          <button 
            onClick={() => setIsAdding(!isAdding)}
            className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg font-medium"
          >
            {isAdding ? 'Cancel' : '+ Add Item'}
          </button>
        </div>

        {isAdding && (
          <form onSubmit={handleAdd} className="bg-gray-900 p-6 rounded-xl border border-gray-800 mb-6 space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Service Name</label>
                <input required type="text" value={serviceName} onChange={e => setServiceName(e.target.value)} className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">URL (optional)</label>
                <input type="text" value={url} onChange={e => setUrl(e.target.value)} className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Login/Username</label>
                <input required type="text" value={login} onChange={e => setLogin(e.target.value)} className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Password</label>
                <input required type="password" value={password} onChange={e => setPassword(e.target.value)} className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2" />
              </div>
            </div>
            <button type="submit" disabled={isLoading} className="bg-green-600 hover:bg-green-700 w-full py-2 rounded-lg font-medium mt-4">
              {isLoading ? 'Saving...' : 'Save Credential'}
            </button>
          </form>
        )}

        <div className="space-y-4">
          {filteredVault.map(item => (
            <div key={item.id} className="bg-gray-900 p-4 rounded-xl border border-gray-800 flex justify-between items-center group">
              <div>
                <h3 className="font-bold text-lg">{item.serviceName}</h3>
                <p className="text-gray-400 text-sm">{item.login}</p>
                {item.url && <a href={item.url} target="_blank" rel="noreferrer" className="text-blue-400 text-xs hover:underline">{item.url}</a>}
              </div>
              <div className="flex gap-2">
                <button 
                  onClick={() => navigator.clipboard.writeText(item.password)} 
                  className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded text-sm text-gray-300"
                >
                  Copy Password
                </button>
                <button 
                  onClick={() => handleDelete(item.id)}
                  className="px-3 py-1 bg-red-900/30 hover:bg-red-900/60 text-red-400 rounded text-sm"
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
          {filteredVault.length === 0 && !isLoading && (
             <div className="text-center py-12 text-gray-500">No items found.</div>
          )}
        </div>
      </div>
    </div>
  );
}
