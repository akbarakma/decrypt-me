import { afterEach, beforeEach, expect, it } from "vitest";
import {
  clearEncryptedFernetKey,
  hasSavedFernetKey,
  loadEncryptedFernetKey,
  saveEncryptedFernetKey
} from "../lib/secure-storage";

beforeEach(() => {
  localStorage.clear();
});

afterEach(async () => {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase("decrypt-me-secure-storage");
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    request.onblocked = () => resolve();
  });
});

it("returns null when nothing is stored", async () => {
  expect(hasSavedFernetKey()).toBe(false);
  expect(await loadEncryptedFernetKey()).toBeNull();
});

it("saves and loads a key through the wrapping flow", async () => {
  await saveEncryptedFernetKey("super-secret-fernet-key");

  expect(hasSavedFernetKey()).toBe(true);
  expect(await loadEncryptedFernetKey()).toBe("super-secret-fernet-key");
});

it("ciphertext stored in localStorage is not the plaintext key", async () => {
  await saveEncryptedFernetKey("super-secret-fernet-key");

  const raw = localStorage.getItem("decrypt-me:fernet-key") ?? "";
  expect(raw).not.toContain("super-secret-fernet-key");
});

it("clears the saved key", async () => {
  await saveEncryptedFernetKey("temp");
  clearEncryptedFernetKey();

  expect(hasSavedFernetKey()).toBe(false);
  expect(await loadEncryptedFernetKey()).toBeNull();
});

it("returns null and wipes corrupted payload", async () => {
  localStorage.setItem("decrypt-me:fernet-key", "{not-json");

  expect(await loadEncryptedFernetKey()).toBeNull();
  expect(localStorage.getItem("decrypt-me:fernet-key")).toBeNull();
});

it("returns null for an unknown payload version", async () => {
  localStorage.setItem(
    "decrypt-me:fernet-key",
    JSON.stringify({ version: 99, iv: "AAAA", ciphertext: "AAAA" })
  );

  expect(await loadEncryptedFernetKey()).toBeNull();
});
