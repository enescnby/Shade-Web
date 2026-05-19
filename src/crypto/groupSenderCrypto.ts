import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hashes as edHashes, sign, verify, keygen } from "@noble/ed25519";

edHashes.sha512 = sha512;

function hkdfChain(chainKey: Uint8Array, label: string): Uint8Array {
  const info = new TextEncoder().encode(label);
  return hkdf(sha256, chainKey, new Uint8Array(0), info, 32);
}

/** Kotlin `ByteBuffer.putInt` / `putLong` with `ByteOrder.BIG_ENDIAN` ile uyumlu */
function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
}

function u64be(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, false);
  return b;
}

const enc = new TextEncoder();

/**
 * Canonical AAD (Android ile aynı):
 * `group_id UTF-8 || sender_device_id UTF-8 || keyId_be4 || chainIndex_be8`.
 */
export function buildGroupMessageAad(
  groupId: string,
  senderDeviceId: string,
  senderKeyId: number,
  chainIndex: bigint,
): Uint8Array {
  const parts = [enc.encode(groupId), enc.encode(senderDeviceId), u32be(senderKeyId), u64be(chainIndex)];
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** İmza girdisi: ciphertext(||tag) || nonce || group_id UTF-8 || keyId_be4 || chainIndex_be8 */
export function buildGroupSignaturePreimage(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  groupId: string,
  senderKeyId: number,
  chainIndex: bigint,
): Uint8Array {
  const gid = enc.encode(groupId);
  const tail = new Uint8Array(ciphertext.length + nonce.length + gid.length + 4 + 8);
  let o = 0;
  tail.set(ciphertext, o);
  o += ciphertext.length;
  tail.set(nonce, o);
  o += nonce.length;
  tail.set(gid, o);
  o += gid.length;
  tail.set(u32be(senderKeyId), o);
  o += 4;
  tail.set(u64be(chainIndex), o);
  return tail;
}

export interface OwnSenderKeyState {
  groupId: string;
  keyId: number;
  chainKey: Uint8Array;
  /** Bir sonraki gönderilecek mesajın zincir indeksi */
  chainIndex: bigint;
  signingPriv: Uint8Array;
  signingPub: Uint8Array;
}

export function createOwnSenderKey(groupId: string, keyId: number): OwnSenderKeyState {
  const chainKey = crypto.getRandomValues(new Uint8Array(32));
  const { secretKey, publicKey } = keygen();
  return {
    groupId,
    keyId,
    chainKey,
    chainIndex: 0n,
    signingPriv: secretKey,
    signingPub: publicKey,
  };
}

export interface EncryptGroupBodyResult {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  signature: Uint8Array;
  /** Güncellenmiş gönderici durumu — başarılı gönderimden sonra kaydet */
  nextOwn: OwnSenderKeyState;
}

export function encryptGroupBody(
  own: OwnSenderKeyState,
  plaintextUtf8: Uint8Array,
  senderDeviceId: string,
): EncryptGroupBodyResult {
  const msgKey = hkdfChain(own.chainKey, "msg");
  const newChainKey = hkdfChain(own.chainKey, "chain");
  const aad = buildGroupMessageAad(own.groupId, senderDeviceId, own.keyId, own.chainIndex);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const cipher = chacha20poly1305(msgKey, nonce, aad);
  const ciphertext = cipher.encrypt(plaintextUtf8);
  const sigMsg = buildGroupSignaturePreimage(ciphertext, nonce, own.groupId, own.keyId, own.chainIndex);
  const signature = sign(sigMsg, own.signingPriv);

  const nextOwn: OwnSenderKeyState = {
    ...own,
    chainKey: newChainKey,
    chainIndex: own.chainIndex + 1n,
  };

  return { ciphertext, nonce, signature, nextOwn };
}

export interface PeerSenderKeyState {
  chainKey: Uint8Array;
  chainIndex: bigint;
  signingPub: Uint8Array;
}

/** Aldığımız SKDM ile kurulan karşı taraf zinciri */
export function peerStateFromSkdm(skdm: {
  chain_key: Uint8Array;
  chain_index: bigint;
  signing_public_key: Uint8Array;
}): PeerSenderKeyState {
  return {
    chainKey: skdm.chain_key,
    chainIndex: skdm.chain_index,
    signingPub: skdm.signing_public_key,
  };
}

export interface DecryptGroupBodyOk {
  plaintext: Uint8Array;
  nextPeer: PeerSenderKeyState;
}

export type DecryptGroupBodyFailure =
  | { kind: "out_of_order"; peerChainIndex: bigint }
  | { kind: "signature_invalid" }
  | { kind: "aead_failed" };

export type DecryptGroupBodyResult =
  | ({ ok: true } & DecryptGroupBodyOk)
  | ({ ok: false } & DecryptGroupBodyFailure);

/**
 * Gelen grup şifre çözümü. Sözleşme §12:
 *  - `payload.chain_index < peer.chain_index` → out-of-order, drop.
 *  - `payload.chain_index > peer.chain_index` → zinciri catch-up ile ileri sar.
 *  - Aksi halde imzayı doğrula, AEAD ile çöz, peer ratchet'ini ilerlet.
 */
export function decryptGroupBody(
  peer: PeerSenderKeyState,
  groupId: string,
  senderDeviceId: string,
  senderKeyId: number,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  signature: Uint8Array,
  payloadChainIndex: bigint,
): DecryptGroupBodyResult {
  let chainKey = peer.chainKey;
  let chainIndex = peer.chainIndex;

  // Geri sayma matematiksel olarak imkânsız (HKDF tek yönlü). Sözleşme drop diyor.
  if (payloadChainIndex < chainIndex) {
    return { ok: false, kind: "out_of_order", peerChainIndex: chainIndex };
  }

  while (chainIndex < payloadChainIndex) {
    chainKey = hkdfChain(chainKey, "chain");
    chainIndex += 1n;
  }

  const msgKey = hkdfChain(chainKey, "msg");
  const aad = buildGroupMessageAad(groupId, senderDeviceId, senderKeyId, payloadChainIndex);
  const sigMsg = buildGroupSignaturePreimage(ciphertext, nonce, groupId, senderKeyId, payloadChainIndex);

  try {
    if (!verify(signature, sigMsg, peer.signingPub)) {
      return { ok: false, kind: "signature_invalid" };
    }
  } catch {
    return { ok: false, kind: "signature_invalid" };
  }

  try {
    const cipher = chacha20poly1305(msgKey, nonce, aad);
    const plaintext = cipher.decrypt(ciphertext);
    const nextChainKey = hkdfChain(chainKey, "chain");
    const nextPeer: PeerSenderKeyState = {
      chainKey: nextChainKey,
      chainIndex: chainIndex + 1n,
      signingPub: peer.signingPub,
    };
    return { ok: true, plaintext, nextPeer };
  } catch {
    return { ok: false, kind: "aead_failed" };
  }
}
