export async function deriveKey(masterPassword: string, salt: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(masterPassword),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations: 600000,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function encryptPayload(key: CryptoKey, payload: any): Promise<string> {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(JSON.stringify(payload))
  );

  const cipherArray = Array.from(new Uint8Array(cipherBuffer));
  const ivArray = Array.from(iv);
  
  // Combine IV and Ciphertext for easy storage (e.g. iv.ciphertext in base64)
  const ivBase64 = btoa(String.fromCharCode(...ivArray));
  const cipherBase64 = btoa(String.fromCharCode(...cipherArray));
  
  return ivBase64 + "." + cipherBase64;
}

export async function decryptPayload(key: CryptoKey, encryptedData: string): Promise<any> {
  const dec = new TextDecoder();
  const [ivBase64, cipherBase64] = encryptedData.split(".");
  
  const ivString = atob(ivBase64);
  const cipherString = atob(cipherBase64);
  
  const iv = new Uint8Array(ivString.length);
  for (let i = 0; i < ivString.length; i++) {
    iv[i] = ivString.charCodeAt(i);
  }
  
  const ciphertext = new Uint8Array(cipherString.length);
  for (let i = 0; i < cipherString.length; i++) {
    ciphertext[i] = cipherString.charCodeAt(i);
  }

  const plainBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );

  return JSON.parse(dec.decode(plainBuffer));
}
