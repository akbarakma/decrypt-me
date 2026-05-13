import CryptoJS from "crypto-js";

export type AlgorithmId =
  | "fernet"
  | "aes-gcm"
  | "aes-cbc"
  | "aes-ctr"
  | "cryptojs-aes-passphrase"
  | "base64"
  | "hex";
export type KeyMode = "passphrase" | "raw";
export type TextEncoding = "base64" | "hex" | "utf8";
export type FernetTokenEncoding = "token" | "hex";
export type HashName = "SHA-256" | "SHA-384" | "SHA-512";
export type KeySize = 128 | 192 | 256;

export type DecryptConfig = {
  algorithm: AlgorithmId;
  ciphertext: string;
  ciphertextEncoding: TextEncoding;
  fernetTokenEncoding: FernetTokenEncoding;
  keyMode: KeyMode;
  key: string;
  rawKeyEncoding: TextEncoding;
  iv: string;
  ivEncoding: TextEncoding;
  salt: string;
  saltEncoding: TextEncoding;
  iterations: number;
  hash: HashName;
  keySize: KeySize;
  ctrLength: number;
};

export const algorithmOptions: { id: AlgorithmId; label: string; note: string }[] = [
  {
    id: "fernet",
    label: "Fernet token",
    note: "For Python cryptography Fernet tokens. Uses base64url token parsing, HMAC-SHA256 verification, and AES-128-CBC."
  },
  {
    id: "aes-gcm",
    label: "AES-GCM",
    note: "Needs ciphertext, key, and a nonce/IV. Auth tag is usually appended to the ciphertext."
  },
  {
    id: "aes-cbc",
    label: "AES-CBC",
    note: "Needs ciphertext, key, and IV. Most payloads use PKCS#7 padding."
  },
  {
    id: "aes-ctr",
    label: "AES-CTR",
    note: "Needs ciphertext, key, counter/IV, and counter length."
  },
  {
    id: "cryptojs-aes-passphrase",
    label: "CryptoJS/OpenSSL AES passphrase",
    note: "For Base64 values from CryptoJS AES.encrypt(message, password). Uses OpenSSL EVP_BytesToKey with MD5 — weak by modern standards; decrypt-only."
  },
  {
    id: "base64",
    label: "Base64 decode",
    note: "Not encryption, but useful when the payload is only encoded."
  },
  {
    id: "hex",
    label: "Hex decode",
    note: "Not encryption, but useful when the payload is only encoded."
  }
];

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const strictTextDecoder = new TextDecoder("utf-8", { fatal: true });

type Bytes = Uint8Array<ArrayBuffer>;

function asBytes(bytes: Uint8Array): Bytes {
  return new Uint8Array(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)) as Bytes;
}

function getSubtle(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("Web Crypto is not available in this environment.");
  }
  return subtle;
}

export async function decryptPayload(config: DecryptConfig): Promise<string> {
  const ciphertext = config.ciphertext.trim();

  if (!ciphertext) {
    throw new Error("Encrypted data is required.");
  }

  if (config.algorithm === "base64") {
    return textDecoder.decode(decodeBase64(ciphertext, "Base64 input"));
  }

  if (config.algorithm === "hex") {
    return textDecoder.decode(decodeHex(ciphertext));
  }

  if (config.algorithm === "cryptojs-aes-passphrase") {
    if (!config.key) {
      throw new Error("Passphrase is required.");
    }

    const decrypted = CryptoJS.AES.decrypt(ciphertext, config.key).toString(CryptoJS.enc.Utf8);
    if (!decrypted) {
      throw new Error("CryptoJS could not decrypt this payload. Check the passphrase and ciphertext format.");
    }
    return decrypted;
  }

  if (config.algorithm === "fernet") {
    return decryptFernetToken(ciphertext, config.key, config.fernetTokenEncoding);
  }

  const subtle = getSubtle();
  const encryptedBytes = decodeByEncoding(ciphertext, config.ciphertextEncoding, "encrypted data");
  const key = await buildAesKey(config);
  const iv = decodeByEncoding(config.iv.trim(), config.ivEncoding, "IV/nonce");

  if (iv.byteLength === 0) {
    throw new Error("IV/nonce is required for this algorithm.");
  }

  const algorithm = toWebCryptoAlgorithm(config.algorithm, iv, config.ctrLength);
  const decrypted = await subtle.decrypt(algorithm, key, encryptedBytes);
  return textDecoder.decode(decrypted);
}

async function decryptFernetToken(
  token: string,
  keyValue: string,
  tokenEncoding: FernetTokenEncoding
): Promise<string> {
  if (!keyValue) {
    throw new Error("Fernet key is required.");
  }

  const subtle = getSubtle();
  const keyBytes = decodeBase64Url(keyValue, "Fernet key");
  if (keyBytes.byteLength !== 32) {
    throw new Error("Fernet key must be a URL-safe Base64 encoded 32-byte key.");
  }

  let tokenText: string;
  if (tokenEncoding === "hex") {
    try {
      tokenText = strictTextDecoder.decode(decodeHex(token));
    } catch {
      throw new Error("Hex-encoded Fernet token is not valid UTF-8.");
    }
  } else {
    tokenText = token;
  }
  const tokenBytes = decodeBase64Url(tokenText, "Fernet token");
  const minimumTokenLength = 1 + 8 + 16 + 16 + 32;
  if (tokenBytes.byteLength < minimumTokenLength) {
    throw new Error("Fernet token is too short.");
  }

  if (tokenBytes[0] !== 0x80) {
    throw new Error("Unsupported Fernet token version.");
  }

  const hmacStart = tokenBytes.byteLength - 32;
  const signedData = tokenBytes.slice(0, hmacStart);
  const tokenHmac = tokenBytes.slice(hmacStart);
  const signingKey = keyBytes.slice(0, 16);
  const encryptionKey = keyBytes.slice(16, 32);
  const iv = tokenBytes.slice(9, 25);
  const encryptedBytes = tokenBytes.slice(25, hmacStart);

  if (encryptedBytes.byteLength === 0 || encryptedBytes.byteLength % 16 !== 0) {
    throw new Error("Invalid Fernet ciphertext length.");
  }

  const hmacKey = await subtle.importKey("raw", signingKey, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const isAuthentic = await subtle.verify("HMAC", hmacKey, tokenHmac, signedData);
  if (!isAuthentic) {
    throw new Error("Fernet HMAC verification failed. Check the token and key.");
  }

  const aesKey = await subtle.importKey("raw", encryptionKey, "AES-CBC", false, ["decrypt"]);
  const decrypted = await subtle.decrypt({ name: "AES-CBC", iv }, aesKey, encryptedBytes);
  return textDecoder.decode(decrypted);
}

export function decodeByEncoding(value: string, encoding: TextEncoding, label: string): Bytes {
  if (!value) {
    throw new Error(`${label} is required.`);
  }

  if (encoding === "base64") {
    return decodeBase64(value, label);
  }

  if (encoding === "hex") {
    return decodeHex(value);
  }

  return asBytes(textEncoder.encode(value));
}

async function buildAesKey(config: DecryptConfig): Promise<CryptoKey> {
  const subtle = getSubtle();
  const keyAlgorithm = aesKeyAlgorithmName(config.algorithm);

  if (!config.key) {
    throw new Error(config.keyMode === "raw" ? "Raw key is required." : "Passphrase is required.");
  }

  if (config.keyMode === "raw") {
    const rawKey = decodeByEncoding(config.key.trim(), config.rawKeyEncoding, "raw key");
    if (![16, 24, 32].includes(rawKey.byteLength)) {
      throw new Error("Raw AES key must be 16, 24, or 32 bytes.");
    }
    return subtle.importKey("raw", rawKey, keyAlgorithm, false, ["decrypt"]);
  }

  const salt = decodeByEncoding(config.salt.trim(), config.saltEncoding, "salt");
  if (!Number.isInteger(config.iterations) || config.iterations < 1) {
    throw new Error("PBKDF2 iterations must be a positive number.");
  }

  const baseKey = await subtle.importKey("raw", textEncoder.encode(config.key), "PBKDF2", false, ["deriveKey"]);

  return subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: config.iterations,
      hash: config.hash
    },
    baseKey,
    {
      name: keyAlgorithm,
      length: config.keySize
    },
    false,
    ["decrypt"]
  );
}

function toWebCryptoAlgorithm(
  algorithm: AlgorithmId,
  iv: Bytes,
  ctrLength: number
): AesGcmParams | AesCbcParams | AesCtrParams {
  if (algorithm === "aes-gcm") {
    return { name: "AES-GCM", iv };
  }

  if (algorithm === "aes-cbc") {
    return { name: "AES-CBC", iv };
  }

  if (algorithm === "aes-ctr") {
    if (!Number.isInteger(ctrLength) || ctrLength < 1 || ctrLength > 128) {
      throw new Error("AES-CTR counter length must be between 1 and 128.");
    }

    return { name: "AES-CTR", counter: iv, length: ctrLength };
  }

  throw new Error("Unsupported encryption setting.");
}

function aesKeyAlgorithmName(algorithm: AlgorithmId): "AES-GCM" | "AES-CBC" | "AES-CTR" {
  if (algorithm === "aes-gcm") return "AES-GCM";
  if (algorithm === "aes-cbc") return "AES-CBC";
  if (algorithm === "aes-ctr") return "AES-CTR";
  throw new Error("Unsupported AES algorithm.");
}

function decodeBase64(value: string, label = "Base64 input"): Bytes {
  const normalized = value.replace(/\s+/g, "");

  try {
    const binary = atob(normalized);
    const bytes = new Uint8Array(new ArrayBuffer(binary.length)) as Bytes;
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    throw new Error(`Invalid ${label}.`);
  }
}

function decodeBase64Url(value: string, label: string): Bytes {
  const normalized = value.trim().replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  const paddingLength = (4 - (normalized.length % 4)) % 4;
  return decodeBase64(normalized + "=".repeat(paddingLength), label);
}

function decodeHex(value: string): Bytes {
  const normalized = value.replace(/\s+/g, "");

  if (!/^(?:[0-9a-fA-F]{2})*$/.test(normalized)) {
    throw new Error("Invalid hex input.");
  }

  const bytes = new Uint8Array(new ArrayBuffer(normalized.length / 2)) as Bytes;
  for (let index = 0; index < normalized.length; index += 2) {
    bytes[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }
  return bytes;
}
