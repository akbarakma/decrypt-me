import { expect, it } from "vitest";
import { decryptPayload, type DecryptConfig } from "../lib/decrypt";
import { parseJsonResult } from "../lib/json";

const baseConfig: DecryptConfig = {
  algorithm: "aes-gcm",
  ciphertext: "",
  ciphertextEncoding: "base64",
  fernetTokenEncoding: "token",
  keyMode: "raw",
  key: "MDEyMzQ1Njc4OWFiY2RlZg==",
  rawKeyEncoding: "base64",
  iv: "YWJjZGVmZ2hpamts",
  ivEncoding: "base64",
  salt: "",
  saltEncoding: "base64",
  iterations: 100000,
  hash: "SHA-256",
  keySize: 256,
  ctrLength: 64
};

it("decrypts an AES-GCM payload", async () => {
  const plaintext = "{\"ok\":true}";
  const keyBytes = Uint8Array.from(Buffer.from(baseConfig.key, "base64"));
  const ivBytes = Uint8Array.from(Buffer.from(baseConfig.iv, "base64"));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: ivBytes }, key, new TextEncoder().encode(plaintext));

  const decrypted = await decryptPayload({
    ...baseConfig,
    ciphertext: Buffer.from(encrypted).toString("base64")
  });

  expect(decrypted).toBe(plaintext);
});

const aesBlockIv = Buffer.from("abcdefghijklmnop", "utf8").toString("base64");

it("decrypts an AES-CBC payload", async () => {
  const plaintext = "{\"cbc\":true}";
  const keyBytes = Uint8Array.from(Buffer.from(baseConfig.key, "base64"));
  const ivBytes = Uint8Array.from(Buffer.from(aesBlockIv, "base64"));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-CBC", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-CBC", iv: ivBytes }, key, new TextEncoder().encode(plaintext));

  const decrypted = await decryptPayload({
    ...baseConfig,
    algorithm: "aes-cbc",
    ciphertext: Buffer.from(encrypted).toString("base64"),
    iv: aesBlockIv
  });

  expect(decrypted).toBe(plaintext);
});

it("decrypts an AES-CTR payload", async () => {
  const plaintext = "{\"ctr\":true}";
  const keyBytes = Uint8Array.from(Buffer.from(baseConfig.key, "base64"));
  const ivBytes = Uint8Array.from(Buffer.from(aesBlockIv, "base64"));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-CTR", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-CTR", counter: ivBytes, length: 64 },
    key,
    new TextEncoder().encode(plaintext)
  );

  const decrypted = await decryptPayload({
    ...baseConfig,
    algorithm: "aes-ctr",
    ciphertext: Buffer.from(encrypted).toString("base64"),
    iv: aesBlockIv,
    ctrLength: 64
  });

  expect(decrypted).toBe(plaintext);
});

it("rejects AES-CTR with out-of-range counter length", async () => {
  await expect(
    decryptPayload({
      ...baseConfig,
      algorithm: "aes-ctr",
      ciphertext: "AAAA",
      ctrLength: 0
    })
  ).rejects.toThrow("AES-CTR counter length must be between 1 and 128.");
});

it("rejects invalid raw AES key lengths", async () => {
  await expect(
    decryptPayload({
      ...baseConfig,
      ciphertext: "AAAA",
      key: "short",
      rawKeyEncoding: "utf8"
    })
  ).rejects.toThrow("Raw AES key must be 16, 24, or 32 bytes.");
});

it("decrypts a Fernet token", async () => {
  const keyBytes = new TextEncoder().encode("0123456789abcdef0123456789abcdef");
  const token = await createFernetToken(keyBytes, "{\"fernet\":true}");

  const decrypted = await decryptPayload({
    ...baseConfig,
    algorithm: "fernet",
    ciphertext: token,
    fernetTokenEncoding: "token",
    key: toBase64Url(keyBytes)
  });

  expect(decrypted).toBe("{\"fernet\":true}");
});

it("decrypts a hex-encoded Fernet token copied from bytea output", async () => {
  const keyBytes = new TextEncoder().encode("0123456789abcdef0123456789abcdef");
  const token = await createFernetToken(keyBytes, "{\"hex\":true}");

  const decrypted = await decryptPayload({
    ...baseConfig,
    algorithm: "fernet",
    ciphertext: Buffer.from(token, "utf8").toString("hex").toUpperCase(),
    fernetTokenEncoding: "hex",
    key: toBase64Url(keyBytes)
  });

  expect(decrypted).toBe("{\"hex\":true}");
});

it("explains when hex-wrapped Fernet is treated as a normal token", async () => {
  const keyBytes = new TextEncoder().encode("0123456789abcdef0123456789abcdef");
  const token = await createFernetToken(keyBytes, "secret");

  await expect(
    decryptPayload({
      ...baseConfig,
      algorithm: "fernet",
      ciphertext: Buffer.from(token, "utf8").toString("hex"),
      fernetTokenEncoding: "token",
      key: toBase64Url(keyBytes)
    })
  ).rejects.toThrow("Unsupported Fernet token version.");
});

it("rejects Fernet tokens with invalid HMAC", async () => {
  const keyBytes = new TextEncoder().encode("0123456789abcdef0123456789abcdef");
  const token = await createFernetToken(keyBytes, "secret");
  const tamperedBytes = fromBase64Url(token);
  tamperedBytes[tamperedBytes.byteLength - 1] ^= 1;
  const tamperedToken = toBase64Url(tamperedBytes);

  await expect(
    decryptPayload({
      ...baseConfig,
      algorithm: "fernet",
      ciphertext: tamperedToken,
      fernetTokenEncoding: "token",
      key: toBase64Url(keyBytes)
    })
  ).rejects.toThrow("Fernet HMAC verification failed.");
});

it("distinguishes non-JSON plaintext", () => {
  expect(parseJsonResult("plain text")).toEqual({ ok: false });
});

it("formats valid JSON", () => {
  const result = parseJsonResult("{\"name\":\"Ada\",\"items\":[1,2]}");

  expect(result.ok).toBe(true);
  if (result.ok) {
    expect(result.formatted).toContain("\n  \"name\": \"Ada\"");
  }
});

async function createFernetToken(keyBytes: Uint8Array, plaintext: string): Promise<string> {
  const signingKey = keyBytes.slice(0, 16);
  const encryptionKey = keyBytes.slice(16, 32);
  const timestamp = new Uint8Array(8);
  const iv = new TextEncoder().encode("abcdefghijklmnop");
  const aesKey = await crypto.subtle.importKey("raw", encryptionKey, "AES-CBC", false, ["encrypt"]);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aesKey, new TextEncoder().encode(plaintext))
  );
  const signedData = concatBytes(new Uint8Array([0x80]), timestamp, iv, ciphertext);
  const hmacKey = await crypto.subtle.importKey("raw", signingKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, signedData));

  return toBase64Url(concatBytes(signedData, hmac));
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const totalLength = chunks.reduce((total, chunk) => total + chunk.byteLength, 0);
  const result = new Uint8Array(new ArrayBuffer(totalLength)) as Uint8Array<ArrayBuffer>;
  let offset = 0;

  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return result;
}

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

function fromBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(Buffer.from(normalized, "base64"));
}
