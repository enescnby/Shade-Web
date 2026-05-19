import { get, set, del, keys } from "idb-keyval";

/**
 * Encrypted-at-rest vault built on IndexedDB + AES-GCM.
 *
 * - The master AES-GCM key is generated on first use and stored as a
 *   non-extractable CryptoKey directly in IndexedDB. Browsers persist
 *   non-extractable CryptoKeys without ever exposing the raw bytes to JS.
 * - Every named slot stores `{ iv, data }` where `data` is the AES-GCM
 *   ciphertext (auth tag appended) of a JSON-serialised value.
 * - `clearVault()` wipes every slot AND the master key. After logout
 *   nothing on the device can be recovered — even if the IndexedDB
 *   blobs are exfiltrated from a backup.
 */

const VAULT_KEY_SLOT = "vault_master_key";
const VAULT_PREFIX = "vault::";

interface EncryptedBlob {
  iv: Uint8Array;
  data: ArrayBuffer;
}

async function getOrCreateMasterKey(): Promise<CryptoKey> {
  const existing = await get<CryptoKey>(VAULT_KEY_SLOT);
  if (existing) return existing;
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false, // non-extractable — raw bytes never leave the SubtleCrypto boundary
    ["encrypt", "decrypt"],
  );
  await set(VAULT_KEY_SLOT, key);
  return key;
}

async function encryptJson(value: unknown, key: CryptoKey): Promise<EncryptedBlob> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(JSON.stringify(value)),
  );
  return { iv, data };
}

async function decryptJson<T>(blob: EncryptedBlob, key: CryptoKey): Promise<T> {
  // Re-copy the IV into a fresh Uint8Array<ArrayBuffer> so its underlying buffer
  // can't be a SharedArrayBuffer (which lib.dom typings forbid for SubtleCrypto).
  const iv = new Uint8Array(blob.iv);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    blob.data,
  );
  return JSON.parse(new TextDecoder().decode(plain)) as T;
}

export async function vaultPut<T>(slot: string, value: T): Promise<void> {
  const key = await getOrCreateMasterKey();
  const blob = await encryptJson(value, key);
  await set(VAULT_PREFIX + slot, blob);
}

export async function vaultGet<T>(slot: string): Promise<T | null> {
  const key = await get<CryptoKey>(VAULT_KEY_SLOT);
  if (!key) return null;
  const blob = await get<EncryptedBlob>(VAULT_PREFIX + slot);
  if (!blob) return null;
  try {
    return await decryptJson<T>(blob, key);
  } catch (e) {
    console.warn(`[vault] failed to decrypt slot=${slot}:`, e);
    return null;
  }
}

export async function vaultDelete(slot: string): Promise<void> {
  await del(VAULT_PREFIX + slot);
}

/**
 * Hard-wipe everything: master key + every encrypted slot. Called on logout.
 * After this returns, vaultGet for any slot returns null.
 */
export async function clearVault(): Promise<void> {
  const all = await keys();
  const targets = all.filter(
    (k) => k === VAULT_KEY_SLOT || (typeof k === "string" && k.startsWith(VAULT_PREFIX)),
  );
  await Promise.all(targets.map((k) => del(k)));
}

/* ───────────────────────── slot identifiers ──────────────────────────── */

export const VAULT_SLOTS = {
  AUTH: "auth",
  MESSAGES: "messages",
  SENDER_KEYS: "sender_keys",
} as const;
