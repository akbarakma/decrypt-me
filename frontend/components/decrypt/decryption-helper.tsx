"use client";

import { Check, ChevronsLeft, ChevronsRight, Copy, Eraser, KeyRound, LockKeyhole, Play, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { JsonTree } from "@/components/json/json-tree";
import {
  algorithmOptions,
  decryptPayload,
  type AlgorithmId,
  type DecryptConfig,
  type FernetTokenEncoding,
  type HashName,
  type KeyMode,
  type KeySize,
  type TextEncoding
} from "@/lib/decrypt";
import { parseJsonResult } from "@/lib/json";
import {
  clearEncryptedFernetKey,
  hasSavedFernetKey,
  loadEncryptedFernetKey,
  saveEncryptedFernetKey
} from "@/lib/secure-storage";

const defaultConfig: DecryptConfig = {
  algorithm: "fernet",
  ciphertext: "",
  ciphertextEncoding: "base64",
  fernetTokenEncoding: "hex",
  keyMode: "raw",
  key: "",
  rawKeyEncoding: "base64",
  iv: "",
  ivEncoding: "base64",
  salt: "",
  saltEncoding: "base64",
  iterations: 100000,
  hash: "SHA-256",
  keySize: 256,
  ctrLength: 64
};

const textEncodings: TextEncoding[] = ["base64", "hex", "utf8"];
const hashOptions: HashName[] = ["SHA-256", "SHA-384", "SHA-512"];
const keySizes: KeySize[] = [128, 192, 256];

export function DecryptionHelper() {
  const [config, setConfig] = useState<DecryptConfig>(defaultConfig);
  const [output, setOutput] = useState("");
  const [error, setError] = useState("");
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [copied, setCopied] = useState<"plain" | "json" | null>(null);
  const [rememberFernetKey, setRememberFernetKey] = useState(false);
  const [isInputCollapsed, setIsInputCollapsed] = useState(false);

  const selectedAlgorithm = useMemo(
    () => algorithmOptions.find((option) => option.id === config.algorithm) ?? algorithmOptions[0],
    [config.algorithm]
  );
  const parsedJson = useMemo(() => parseJsonResult(output), [output]);
  const usesFernet = config.algorithm === "fernet";
  const usesAes = config.algorithm === "aes-gcm" || config.algorithm === "aes-cbc" || config.algorithm === "aes-ctr";
  const usesCryptoJs = config.algorithm === "cryptojs-aes-passphrase";
  const usesKey = usesFernet || usesAes || usesCryptoJs;
  const usesPassphraseDerivation = usesAes && config.keyMode === "passphrase";
  const usesRawKey = usesAes && config.keyMode === "raw";

  useEffect(() => {
    let isMounted = true;

    if (hasSavedFernetKey()) {
      loadEncryptedFernetKey().then((savedKey) => {
        if (isMounted && savedKey) {
          setConfig((current) => (current.algorithm === "fernet" ? { ...current, key: savedKey } : current));
          setRememberFernetKey(true);
        }
      });
    }

    return () => {
      isMounted = false;
    };
  }, []);

  const updateConfig = <Key extends keyof DecryptConfig>(key: Key, value: DecryptConfig[Key]) => {
    setConfig((current) => ({ ...current, [key]: value }));
  };

  const handleDecrypt = async () => {
    setError("");
    setOutput("");
    setCopied(null);
    setIsDecrypting(true);

    try {
      const decrypted = await decryptPayload(config);
      setOutput(decrypted);
      if (config.algorithm === "fernet" && config.key) {
        if (rememberFernetKey) {
          await saveEncryptedFernetKey(config.key);
        } else if (hasSavedFernetKey()) {
          clearEncryptedFernetKey();
        }
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Decryption failed.");
    } finally {
      setIsDecrypting(false);
    }
  };

  const handleClear = () => {
    setConfig(defaultConfig);
    setOutput("");
    setError("");
    setCopied(null);
  };

  const handleClearSavedFernetKey = () => {
    clearEncryptedFernetKey();
    setRememberFernetKey(false);
  };

  const copyText = async (value: string, target: "plain" | "json") => {
    await navigator.clipboard.writeText(value);
    setCopied(target);
    window.setTimeout(() => setCopied(null), 1200);
  };

  return (
    <main className="min-h-screen overflow-x-hidden px-4 py-5 sm:px-6 lg:px-8">
      <section className="mx-auto flex w-full max-w-[108rem] flex-col gap-5">
        <header className="flex flex-col gap-3 border-b border-white/10 pb-5 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-brass/30 bg-brass/10 px-3 py-1 text-xs uppercase tracking-[0.18em] text-brass">
              <LockKeyhole className="h-3.5 w-3.5" aria-hidden="true" />
              local browser tool
            </div>
            <h1 className="text-4xl font-semibold tracking-normal text-paper sm:text-5xl">Decrypt Me</h1>
          </div>
          <p className="max-w-2xl text-sm leading-6 text-white/65">
            Paste a payload, choose the matching settings, and decrypt locally. Unknown schemes still need their exact
            metadata: algorithm, key format, IV/nonce, salt, and encoding.
          </p>
        </header>

        <div
          className={
            isInputCollapsed
              ? "grid gap-5 lg:grid-cols-[5rem_minmax(0,1fr)]"
              : "grid gap-5 lg:grid-cols-[minmax(28rem,0.85fr)_minmax(0,1.15fr)]"
          }
        >
          <section className="min-w-0 rounded-lg border border-white/10 bg-panel/85 p-4 shadow-hard-glow backdrop-blur">
            <div className="mb-4 flex items-center justify-between gap-3">
              <div className={isInputCollapsed ? "xl:hidden" : ""}>
                <h2 className="text-lg font-semibold text-paper">Input</h2>
                <p className="text-sm text-white/50">Match the dropdown to how the payload was encrypted.</p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  className="inline-flex h-10 w-10 items-center justify-center rounded-md border border-white/10 text-white/70 transition hover:border-brass/40 hover:text-brass"
                  onClick={() => setIsInputCollapsed((current) => !current)}
                  title={isInputCollapsed ? "Expand input" : "Shrink input"}
                  type="button"
                >
                  {isInputCollapsed ? (
                    <ChevronsRight className="h-4 w-4" aria-hidden="true" />
                  ) : (
                    <ChevronsLeft className="h-4 w-4" aria-hidden="true" />
                  )}
                </button>
                <button
                  className={`h-10 w-10 items-center justify-center rounded-md border border-white/10 text-white/70 transition hover:border-brass/40 hover:text-brass ${
                    isInputCollapsed ? "hidden" : "inline-flex"
                  }`}
                  onClick={handleClear}
                  title="Clear"
                  type="button"
                >
                  <Eraser className="h-4 w-4" aria-hidden="true" />
                </button>
              </div>
            </div>

            {isInputCollapsed && (
              <button
                className="hidden min-h-[32rem] w-full items-center justify-center rounded-md border border-dashed border-white/10 bg-black/20 text-xs font-semibold uppercase tracking-[0.18em] text-white/45 transition hover:border-brass/40 hover:text-brass lg:flex"
                onClick={() => setIsInputCollapsed(false)}
                type="button"
              >
                <span className="[writing-mode:vertical-rl]">Input</span>
              </button>
            )}

            <div className={`grid gap-4 ${isInputCollapsed ? "lg:hidden" : ""}`}>
              <label className="grid gap-2">
                <span className="text-sm font-medium text-white/80">Encrypted data</span>
                <textarea
                  className="min-h-56 max-w-full resize-y overflow-auto whitespace-pre-wrap break-all rounded-md border border-white/10 bg-black/30 px-3 py-3 text-sm leading-6 text-paper outline-none transition placeholder:text-white/25 focus:border-brass/60"
                  onChange={(event) => updateConfig("ciphertext", event.currentTarget.value)}
                  placeholder="Paste encrypted text here"
                  value={config.ciphertext}
                />
              </label>

              <label className="grid gap-2">
                <span className="text-sm font-medium text-white/80">Encryption setting</span>
                <select
                  className="h-11 rounded-md border border-white/10 bg-black/30 px-3 text-sm text-paper outline-none transition focus:border-brass/60"
                  onChange={(event) => updateConfig("algorithm", event.currentTarget.value as AlgorithmId)}
                  value={config.algorithm}
                >
                  {algorithmOptions.map((option) => (
                    <option key={option.id} value={option.id}>
                      {option.label}
                    </option>
                  ))}
                </select>
                <span className="text-xs leading-5 text-white/45">{selectedAlgorithm.note}</span>
              </label>

              {usesAes && (
                <div className="grid gap-4 rounded-lg border border-white/10 bg-black/20 p-3">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <SelectField
                      label="Ciphertext encoding"
                      onChange={(value) => updateConfig("ciphertextEncoding", value as TextEncoding)}
                      options={textEncodings}
                      value={config.ciphertextEncoding}
                    />
                    <SelectField
                      label="Key mode"
                      onChange={(value) => updateConfig("keyMode", value as KeyMode)}
                      options={["raw", "passphrase"]}
                      value={config.keyMode}
                    />
                  </div>

                  <label className="grid gap-2">
                    <span className="flex items-center gap-2 text-sm font-medium text-white/80">
                      <KeyRound className="h-4 w-4 text-brass" aria-hidden="true" />
                      {config.keyMode === "raw" ? "Raw key" : "Passphrase"}
                    </span>
                    <input
                      className="h-11 rounded-md border border-white/10 bg-black/30 px-3 text-sm text-paper outline-none transition placeholder:text-white/25 focus:border-brass/60"
                      onChange={(event) => updateConfig("key", event.currentTarget.value)}
                      placeholder={config.keyMode === "raw" ? "Base64, hex, or UTF-8 key bytes" : "Password or phrase"}
                      type={config.keyMode === "raw" ? "text" : "password"}
                      value={config.key}
                    />
                  </label>

                  {usesRawKey && (
                    <SelectField
                      label="Raw key encoding"
                      onChange={(value) => updateConfig("rawKeyEncoding", value as TextEncoding)}
                      options={textEncodings}
                      value={config.rawKeyEncoding}
                    />
                  )}

                  {usesPassphraseDerivation && (
                    <div className="grid gap-3 sm:grid-cols-2">
                      <label className="grid gap-2">
                        <span className="text-sm font-medium text-white/80">Salt</span>
                        <input
                          className="h-11 rounded-md border border-white/10 bg-black/30 px-3 text-sm text-paper outline-none transition placeholder:text-white/25 focus:border-brass/60"
                          onChange={(event) => updateConfig("salt", event.currentTarget.value)}
                          placeholder="PBKDF2 salt"
                          value={config.salt}
                        />
                      </label>
                      <SelectField
                        label="Salt encoding"
                        onChange={(value) => updateConfig("saltEncoding", value as TextEncoding)}
                        options={textEncodings}
                        value={config.saltEncoding}
                      />
                      <NumberField
                        label="PBKDF2 iterations"
                        min={1}
                        onChange={(value) => updateConfig("iterations", value)}
                        value={config.iterations}
                      />
                      <SelectField
                        label="PBKDF2 hash"
                        onChange={(value) => updateConfig("hash", value as HashName)}
                        options={hashOptions}
                        value={config.hash}
                      />
                      <SelectField
                        label="Derived key size"
                        onChange={(value) => updateConfig("keySize", Number(value) as KeySize)}
                        options={keySizes.map(String)}
                        value={String(config.keySize)}
                      />
                    </div>
                  )}

                  <div className="grid gap-3 sm:grid-cols-2">
                    <label className="grid gap-2">
                      <span className="text-sm font-medium text-white/80">
                        {config.algorithm === "aes-ctr" ? "Counter / IV" : "IV / nonce"}
                      </span>
                      <input
                        className="h-11 rounded-md border border-white/10 bg-black/30 px-3 text-sm text-paper outline-none transition placeholder:text-white/25 focus:border-brass/60"
                        onChange={(event) => updateConfig("iv", event.currentTarget.value)}
                        placeholder="Usually Base64 or hex"
                        value={config.iv}
                      />
                    </label>
                    <SelectField
                      label="IV encoding"
                      onChange={(value) => updateConfig("ivEncoding", value as TextEncoding)}
                      options={textEncodings}
                      value={config.ivEncoding}
                    />
                    {config.algorithm === "aes-ctr" && (
                      <NumberField
                        label="Counter length"
                        max={128}
                        min={1}
                        onChange={(value) => updateConfig("ctrLength", value)}
                        value={config.ctrLength}
                      />
                    )}
                  </div>
                </div>
              )}

              {usesFernet && (
                <div className="grid gap-4 rounded-lg border border-white/10 bg-black/20 p-3">
                  <SelectField
                    label="Fernet token encoding"
                    onChange={(value) => updateConfig("fernetTokenEncoding", value as FernetTokenEncoding)}
                    options={["hex", "token"]}
                    value={config.fernetTokenEncoding}
                  />
                  <label className="grid gap-2">
                    <span className="flex items-center gap-2 text-sm font-medium text-white/80">
                      <KeyRound className="h-4 w-4 text-brass" aria-hidden="true" />
                      Fernet key
                    </span>
                    <input
                      className="h-11 rounded-md border border-white/10 bg-black/30 px-3 text-sm text-paper outline-none transition placeholder:text-white/25 focus:border-brass/60"
                      onChange={(event) => updateConfig("key", event.currentTarget.value)}
                      placeholder="Paste the URL-safe Base64 Fernet key"
                      type="password"
                      value={config.key}
                    />
                    <div className="flex flex-col gap-2 text-xs leading-5 text-white/45 sm:flex-row sm:items-center sm:justify-between">
                      <label className="inline-flex items-center gap-2 text-white/65">
                        <input
                          checked={rememberFernetKey}
                          className="h-3.5 w-3.5 accent-brass"
                          onChange={(event) => setRememberFernetKey(event.currentTarget.checked)}
                          type="checkbox"
                        />
                        Remember key on this device (wrapped, not XSS-proof)
                      </label>
                      <button
                        className="self-start rounded-md border border-white/10 px-2.5 py-1 text-white/65 transition hover:border-red-300/40 hover:text-red-100 sm:self-auto"
                        onClick={handleClearSavedFernetKey}
                        type="button"
                      >
                        Remove saved key
                      </button>
                    </div>
                    <span className="text-xs leading-5 text-white/45">
                      Use hex for copied PostgreSQL bytea values like 674141..., or token for normal gAAAA... Fernet
                      text.
                    </span>
                  </label>
                </div>
              )}

              {usesCryptoJs && (
                <div className="grid gap-4 rounded-lg border border-white/10 bg-black/20 p-3">
                  <label className="grid gap-2">
                    <span className="flex items-center gap-2 text-sm font-medium text-white/80">
                      <KeyRound className="h-4 w-4 text-brass" aria-hidden="true" />
                      Passphrase
                    </span>
                    <input
                      className="h-11 rounded-md border border-white/10 bg-black/30 px-3 text-sm text-paper outline-none transition placeholder:text-white/25 focus:border-brass/60"
                      onChange={(event) => updateConfig("key", event.currentTarget.value)}
                      placeholder="Password used with CryptoJS AES.encrypt"
                      type="password"
                      value={config.key}
                    />
                  </label>
                </div>
              )}

              <button
                className="inline-flex h-12 items-center justify-center gap-2 rounded-md bg-brass px-4 font-semibold text-ink transition hover:bg-[#e2bd72] disabled:cursor-not-allowed disabled:opacity-60"
                disabled={isDecrypting}
                onClick={handleDecrypt}
                type="button"
              >
                <Play className="h-4 w-4" aria-hidden="true" />
                {isDecrypting ? "Decrypting..." : usesKey ? "Decrypt" : "Decode"}
              </button>
            </div>
          </section>

          <section className="min-w-0 overflow-hidden rounded-lg border border-white/10 bg-[#101514]/90 p-4 shadow-hard-glow backdrop-blur">
            <div className="mb-4 flex items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-semibold text-paper">Result</h2>
                <p className="text-sm text-white/50">JSON is detected automatically after decryption.</p>
              </div>
              {output && (
                <button
                  className="inline-flex h-10 items-center gap-2 rounded-md border border-white/10 px-3 text-sm text-white/75 transition hover:border-brass/40 hover:text-brass"
                  onClick={() => copyText(output, "plain")}
                  type="button"
                >
                  {copied === "plain" ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                  Copy
                </button>
              )}
            </div>

            {error && (
              <div className="mb-4 flex items-start gap-3 rounded-lg border border-red-400/25 bg-red-500/10 p-3 text-sm text-red-100">
                <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                <p>{error}</p>
              </div>
            )}

            {!output && !error && (
              <div className="flex min-h-[28rem] items-center justify-center rounded-lg border border-dashed border-white/10 bg-black/15 p-8 text-center text-sm leading-6 text-white/45">
                Decrypted text will appear here. If it is JSON, the tree viewer will unlock each object and array.
              </div>
            )}

            {output && parsedJson.ok && (
              <div className="grid min-w-0 gap-4">
                <div className="flex items-center justify-between gap-3">
                  <h3 className="text-sm font-semibold uppercase tracking-[0.16em] text-brass">JSON tree</h3>
                  <button
                    className="inline-flex h-9 items-center gap-2 rounded-md border border-white/10 px-3 text-xs text-white/75 transition hover:border-brass/40 hover:text-brass"
                    onClick={() => copyText(parsedJson.formatted, "json")}
                    type="button"
                  >
                    {copied === "json" ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                    Copy JSON
                  </button>
                </div>
                <div className="min-w-0">
                  <JsonTree value={parsedJson.value} />
                </div>
                <div className="min-w-0">
                  <h3 className="mb-2 text-sm font-semibold uppercase tracking-[0.16em] text-brass">Formatted JSON</h3>
                  <pre className="max-h-[32rem] w-full overflow-auto whitespace-pre rounded-lg border border-white/10 bg-black/25 p-4 text-sm leading-6 text-paper">
                    {parsedJson.formatted}
                  </pre>
                </div>
              </div>
            )}

            {output && !parsedJson.ok && (
              <div className="min-w-0">
                <pre className="min-h-[32rem] w-full overflow-auto whitespace-pre rounded-lg border border-white/10 bg-black/25 p-4 text-sm leading-6 text-paper">
                  {output}
                </pre>
              </div>
            )}
          </section>
        </div>
      </section>
    </main>
  );
}

type SelectFieldProps = {
  label: string;
  options: string[];
  value: string;
  onChange: (value: string) => void;
};

function SelectField({ label, options, value, onChange }: SelectFieldProps) {
  return (
    <label className="grid gap-2">
      <span className="text-sm font-medium text-white/80">{label}</span>
      <select
        className="h-11 rounded-md border border-white/10 bg-black/30 px-3 text-sm text-paper outline-none transition focus:border-brass/60"
        onChange={(event) => onChange(event.currentTarget.value)}
        value={value}
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}

type NumberFieldProps = {
  label: string;
  value: number;
  min: number;
  max?: number;
  onChange: (value: number) => void;
};

function NumberField({ label, value, min, max, onChange }: NumberFieldProps) {
  return (
    <label className="grid gap-2">
      <span className="text-sm font-medium text-white/80">{label}</span>
      <input
        className="h-11 rounded-md border border-white/10 bg-black/30 px-3 text-sm text-paper outline-none transition focus:border-brass/60"
        max={max}
        min={min}
        onChange={(event) => onChange(Number(event.currentTarget.value))}
        type="number"
        value={value}
      />
    </label>
  );
}
