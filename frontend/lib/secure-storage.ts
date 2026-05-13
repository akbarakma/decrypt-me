const dbName = "decrypt-me-secure-storage";
const storeName = "keys";
const wrappingKeyId = "fernet-key-wrapper";
const savedFernetKeyName = "decrypt-me:fernet-key";

type SavedPayload = {
  version: 1;
  iv: string;
  ciphertext: string;
};

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export async function saveEncryptedFernetKey(value: string): Promise<void> {
  const key = await getOrCreateWrappingKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, textEncoder.encode(value));
  const payload: SavedPayload = {
    version: 1,
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  };

  localStorage.setItem(savedFernetKeyName, JSON.stringify(payload));
}

export async function loadEncryptedFernetKey(): Promise<string | null> {
  const rawPayload = localStorage.getItem(savedFernetKeyName);
  if (!rawPayload) {
    return null;
  }

  try {
    const payload = JSON.parse(rawPayload) as SavedPayload;
    if (payload.version !== 1) {
      return null;
    }

    const key = await getOrCreateWrappingKey();
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(payload.iv) },
      key,
      base64ToBytes(payload.ciphertext)
    );

    return textDecoder.decode(decrypted);
  } catch {
    localStorage.removeItem(savedFernetKeyName);
    return null;
  }
}

export function clearEncryptedFernetKey(): void {
  localStorage.removeItem(savedFernetKeyName);
}

export function hasSavedFernetKey(): boolean {
  return localStorage.getItem(savedFernetKeyName) !== null;
}

async function getOrCreateWrappingKey(): Promise<CryptoKey> {
  const existingKey = await readStoredWrappingKey();
  if (existingKey) {
    return existingKey;
  }

  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  await writeStoredWrappingKey(key);
  return key;
}

async function readStoredWrappingKey(): Promise<CryptoKey | null> {
  const db = await openStorageDb();

  try {
    const result = await new Promise<unknown>((resolve, reject) => {
      const transaction = db.transaction(storeName, "readonly");
      const request = transaction.objectStore(storeName).get(wrappingKeyId);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
    });

    return isCryptoKey(result) ? result : null;
  } finally {
    db.close();
  }
}

async function writeStoredWrappingKey(key: CryptoKey): Promise<void> {
  const db = await openStorageDb();

  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction(storeName, "readwrite");
      const request = transaction.objectStore(storeName).put(key, wrappingKeyId);
      request.onerror = () => reject(request.error);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
    });
  } finally {
    db.close();
  }
}

function openStorageDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(dbName, 1);

    request.onerror = () => reject(request.error);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(storeName);
    };
    request.onsuccess = () => resolve(request.result);
  });
}

function isCryptoKey(value: unknown): value is CryptoKey {
  return (
    typeof value === "object" &&
    value !== null &&
    "type" in value &&
    "algorithm" in value &&
    "usages" in value
  );
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length)) as Uint8Array<ArrayBuffer>;
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
