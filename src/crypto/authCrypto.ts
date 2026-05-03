import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hexToBytes, bytesToHex, decode } from "./utils";

export interface EphemeralKeyPair {
  privKey: Uint8Array;
  pubKey: Uint8Array;
  pubKeyHex: string;
}

export interface DecryptedCredentials {
  x25519_priv: string;
  ed25519_priv: string;
  shade_id: string;
  user_id: string;
}

export function generateEphemeralKeyPair(): EphemeralKeyPair {
  const privKey = x25519.utils.randomSecretKey();
  const pubKey = x25519.getPublicKey(privKey);
  return { privKey, pubKey, pubKeyHex: bytesToHex(pubKey) };
}

export function deriveTransferKey(
  ownPrivKey: Uint8Array,
  peerPubKeyHex: string,
): Uint8Array {
  const ownPubKey = x25519.getPublicKey(ownPrivKey);
  console.log("[authCrypto] deriveTransferKey");
  console.log("  web_ephemeral_pub (ours):", bytesToHex(ownPubKey));
  console.log("  android_x25519_pub (peer):", peerPubKeyHex);

  const sharedSecret = x25519.getSharedSecret(
    ownPrivKey,
    hexToBytes(peerPubKeyHex),
  );
  console.log("  sharedSecret:", bytesToHex(sharedSecret));

  const info = new TextEncoder().encode("shade-web-auth-v1");
  const transferKey = hkdf(sha256, sharedSecret, undefined, info, 32);
  console.log("  transferKey:", bytesToHex(transferKey));
  return transferKey;
}

export function decryptCredentials(
  transferKey: Uint8Array,
  ciphertextHex: string,
  nonceHex: string,
): DecryptedCredentials {
  console.log("[authCrypto] decryptCredentials");
  console.log("  transferKey:", bytesToHex(transferKey));
  console.log("  nonce:", nonceHex, `(${nonceHex.length / 2} bytes)`);
  console.log("  ciphertext:", ciphertextHex, `(${ciphertextHex.length / 2} bytes)`);

  const nonceBytes = hexToBytes(nonceHex);
  const ciphertextBytes = hexToBytes(ciphertextHex);

  console.log("  nonce length (bytes):", nonceBytes.length, "(expected 12)");
  console.log("  ciphertext length (bytes):", ciphertextBytes.length, "(payload + 16 byte Poly1305 tag)");

  const cipher = chacha20poly1305(transferKey, nonceBytes);
  const plaintext = cipher.decrypt(ciphertextBytes);
  const json = decode(plaintext);
  console.log("  decrypted JSON:", json);
  return JSON.parse(json);
}
