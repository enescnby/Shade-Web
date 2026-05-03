import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { bytesToHex, hexToBytes } from "./utils";

// Android uses "Shade-Message-Key-v{keyVersion}" — current version is 1
function deriveMessageKey(privKeyHex: string, peerPubKeyHex: string, keyVersion = 1): Uint8Array {
  const shared = x25519.getSharedSecret(hexToBytes(privKeyHex), hexToBytes(peerPubKeyHex));
  const info = new TextEncoder().encode(`Shade-Message-Key-v${keyVersion}`);
  return hkdf(sha256, shared, new Uint8Array(0), info, 32);
}

export interface EncryptedMessage {
  ciphertext: Uint8Array; // full AEAD output — auth tag appended inside (matches Android)
  nonce: Uint8Array;
}

export function encryptMessage(
  plaintext: string,
  senderPrivHex: string,
  receiverPubHex: string,
): EncryptedMessage {
  const key = deriveMessageKey(senderPrivHex, receiverPubHex);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cipher = chacha20poly1305(key, nonce);
  // @noble appends 16-byte auth tag — keep it inside ciphertext, matching Android's format
  const ciphertext = cipher.encrypt(new TextEncoder().encode(plaintext));
  return { ciphertext, nonce };
}

// ciphertext already contains the auth tag appended (Android convention).
// keyVersion MUST match the version Android encrypted with — currently v1.
export function decryptMessage(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  receiverPrivHex: string,
  senderPubHex: string,
  keyVersion = 1,
): string {
  try {
    const key = deriveMessageKey(receiverPrivHex, senderPubHex, keyVersion);
    const cipher = chacha20poly1305(key, nonce);
    return new TextDecoder().decode(cipher.decrypt(ciphertext));
  } catch {
    return "[şifresi çözülemeyen mesaj]";
  }
}

/**
 * Gönderen: ham piksel baytlarını sunucuya yüklemeden önce şifreler (Android ile uyumlu format).
 * Anahtar ve nonce boyutu `decryptImageAttachment` ile çift yönlü aynıdır.
 */
export function encryptImageAttachment(
  plainImageBytes: Uint8Array,
  senderPrivHex: string,
  receiverPubHex: string,
  keyVersion = 1,
): { ciphertext: Uint8Array<ArrayBuffer>; nonceHex: string } {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = deriveMessageKey(senderPrivHex, receiverPubHex, keyVersion);
  const cipher = chacha20poly1305(key, nonce);
  const ct = cipher.encrypt(plainImageBytes);
  const ciphertext = new Uint8Array(ct.byteLength);
  ciphertext.set(ct);
  return { ciphertext, nonceHex: bytesToHex(nonce) };
}

/**
 * Tam boy foto sunucuda ChaCha20-Poly1305 ile saklanır; `ImageMessageContent.imageNonceHex`
 * içindeki 12 baytlık IETF ChaCha nonce (24 hex karakter). Anahtar, metin mesajlarıyla aynı
 * HKDF türevi (`Shade-Message-Key-v*`, konu tarafının X25519 public + bizim priv).
 */
export function decryptImageAttachment(
  ciphertext: Uint8Array,
  nonceHex: string,
  ourPrivHex: string,
  peerEncryptionPubHex: string,
  keyVersion = 1,
): Uint8Array<ArrayBuffer> | null {
  const h = nonceHex.trim().replace(/^0x/i, "");
  if (h.length !== 24 || !/^[\da-fA-F]+$/i.test(h)) return null;

  try {
    const nonce = hexToBytes(h);
    if (nonce.length !== 12) return null;

    const key = deriveMessageKey(ourPrivHex, peerEncryptionPubHex, keyVersion);
    const cipher = chacha20poly1305(key, nonce);

    /* Yeni tek-sahiplik Uint8 — Blob(strict TS) uyumu */
    const out = cipher.decrypt(ciphertext);
    const copy = new Uint8Array(out.byteLength);
    copy.set(out);
    return copy;
  } catch {
    return null;
  }
}
