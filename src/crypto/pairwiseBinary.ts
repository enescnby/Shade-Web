import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hexToBytes } from "./utils";

/** Pairwise AEAD over arbitrary bytes — SKDM blobları için (mesaj metni için `messageCrypto`). */
function derivePairwiseKey(senderPrivHex: string, receiverPubHex: string, keyVersion = 1): Uint8Array {
  const shared = x25519.getSharedSecret(hexToBytes(senderPrivHex), hexToBytes(receiverPubHex));
  const info = new TextEncoder().encode(`Shade-Message-Key-v${keyVersion}`);
  return hkdf(sha256, shared, new Uint8Array(0), info, 32);
}

export function encryptPairwiseBinary(
  plaintext: Uint8Array,
  senderPrivHex: string,
  receiverPubHex: string,
  keyVersion = 1,
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const key = derivePairwiseKey(senderPrivHex, receiverPubHex, keyVersion);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cipher = chacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(plaintext);
  return { ciphertext, nonce };
}

export function decryptPairwiseBinary(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  receiverPrivHex: string,
  senderPubHex: string,
  keyVersion = 1,
): Uint8Array | null {
  try {
    const key = derivePairwiseKey(receiverPrivHex, senderPubHex, keyVersion);
    const cipher = chacha20poly1305(key, nonce);
    return cipher.decrypt(ciphertext);
  } catch {
    return null;
  }
}
