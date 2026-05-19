import type { OwnSenderKeyState, PeerSenderKeyState } from "../crypto/groupSenderCrypto";
import { createOwnSenderKey, peerStateFromSkdm } from "../crypto/groupSenderCrypto";
import { bytesToHex, hexToBytes } from "../crypto/utils";
import type { SenderKeyDistributionDecoded } from "../proto";
import { vaultDelete, vaultGet, vaultPut, VAULT_SLOTS } from "../store/vaultStore";

/** `group_id \\0 sender_user_id \\0 sender_device_id \\0 key_id` */
export function peerStorageKey(
  groupId: string,
  senderUserId: string,
  senderDeviceId: string,
  keyId: number,
): string {
  return `${groupId}\0${senderUserId}\0${senderDeviceId}\0${keyId}`;
}

const ownKeys = new Map<string, OwnSenderKeyState>();
const peerKeys = new Map<string, PeerSenderKeyState>();
const groupMembers = new Map<string, Array<{ user_id: string; shade_id: string }>>();
/**
 * Android'in `SkdmDispatchDao` muadili: `(group, peerUser, peerDevice, ownKeyId)` → işaret.
 * Anahtar formatı `peerStorageKey` ile aynı.
 */
const dispatchLedger = new Set<string>();
/** Linked-devices SKDM ledger satırında peer_device_id olarak kullanılan sabit (Android ile aynı). */
export const LINKED_DEVICES_DISPATCH_ID = "__linked_devices__";

let hydrated = false;
let hydratePromise: Promise<void> | null = null;
let persistTimer: ReturnType<typeof setTimeout> | null = null;

interface PersistedOwnSenderKey {
  groupId: string;
  keyId: number;
  chainKeyHex: string;
  chainIndex: string;
  signingPrivHex: string;
  signingPubHex: string;
}

interface PersistedPeerSenderKey {
  groupId: string;
  senderUserId: string;
  senderDeviceId: string;
  keyId: number;
  chainKeyHex: string;
  chainIndex: string;
  signingPubHex: string;
}

interface SenderKeyVaultSnapshot {
  own: PersistedOwnSenderKey[];
  peers: PersistedPeerSenderKey[];
  /** Eski tek-boolean ledger (eski oturumlardan kalıntı; okunur, yazılmaz) */
  lastSkdm?: Array<{ groupId: string; keyId: number }>;
  /** Yeni per-peer dispatch ledger (Android `SkdmDispatchDao` ile uyumlu). */
  dispatch?: Array<{
    groupId: string;
    peerUserId: string;
    peerDeviceId: string;
    keyId: number;
  }>;
  groupMembers: Array<{
    groupId: string;
    members: Array<{ user_id: string; shade_id: string }>;
  }>;
}

function touchPersist(): void {
  if (!hydrated) return;
  if (persistTimer) clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    void persistSenderKeyStore();
  }, 250);
}

function serializeOwn(groupId: string, state: OwnSenderKeyState): PersistedOwnSenderKey {
  return {
    groupId,
    keyId: state.keyId,
    chainKeyHex: bytesToHex(state.chainKey),
    chainIndex: state.chainIndex.toString(),
    signingPrivHex: bytesToHex(state.signingPriv),
    signingPubHex: bytesToHex(state.signingPub),
  };
}

function deserializeOwn(row: PersistedOwnSenderKey): OwnSenderKeyState {
  return {
    groupId: row.groupId,
    keyId: row.keyId,
    chainKey: hexToBytes(row.chainKeyHex),
    chainIndex: BigInt(row.chainIndex),
    signingPriv: hexToBytes(row.signingPrivHex),
    signingPub: hexToBytes(row.signingPubHex),
  };
}

function serializePeer(
  groupId: string,
  senderUserId: string,
  senderDeviceId: string,
  keyId: number,
  state: PeerSenderKeyState,
): PersistedPeerSenderKey {
  return {
    groupId,
    senderUserId,
    senderDeviceId,
    keyId,
    chainKeyHex: bytesToHex(state.chainKey),
    chainIndex: state.chainIndex.toString(),
    signingPubHex: bytesToHex(state.signingPub),
  };
}

function deserializePeer(row: PersistedPeerSenderKey): void {
  peerKeys.set(
    peerStorageKey(row.groupId, row.senderUserId, row.senderDeviceId, row.keyId),
    {
      chainKey: hexToBytes(row.chainKeyHex),
      chainIndex: BigInt(row.chainIndex),
      signingPub: hexToBytes(row.signingPubHex),
    },
  );
}

async function persistSenderKeyStore(): Promise<void> {
  const dispatch: SenderKeyVaultSnapshot["dispatch"] = [];
  for (const key of dispatchLedger) {
    const parts = key.split("\0");
    if (parts.length !== 4) continue;
    const [groupId, peerUserId, peerDeviceId, keyIdStr] = parts;
    dispatch.push({ groupId, peerUserId, peerDeviceId, keyId: Number(keyIdStr) });
  }

  const snap: SenderKeyVaultSnapshot = {
    own: [...ownKeys.entries()].map(([groupId, state]) => serializeOwn(groupId, state)),
    peers: [],
    dispatch,
    groupMembers: [...groupMembers.entries()].map(([groupId, members]) => ({
      groupId,
      members,
    })),
  };

  for (const key of peerKeys.keys()) {
    const parts = key.split("\0");
    if (parts.length !== 4) continue;
    const [groupId, senderUserId, senderDeviceId, keyIdStr] = parts;
    const peer = peerKeys.get(key);
    if (!peer) continue;
    snap.peers.push(
      serializePeer(groupId, senderUserId, senderDeviceId, Number(keyIdStr), peer),
    );
  }

  await vaultPut(VAULT_SLOTS.SENDER_KEYS, snap);
}

function applyVaultSnapshot(snap: SenderKeyVaultSnapshot): void {
  ownKeys.clear();
  peerKeys.clear();
  groupMembers.clear();
  dispatchLedger.clear();

  for (const row of snap.own) {
    if (!row.groupId) continue;
    ownKeys.set(row.groupId, deserializeOwn(row));
  }
  for (const row of snap.peers) {
    if (!row.groupId || !row.senderUserId || !row.senderDeviceId) continue;
    deserializePeer(row);
  }
  if (snap.dispatch) {
    for (const row of snap.dispatch) {
      if (!row.groupId || !row.peerUserId || !row.peerDeviceId) continue;
      dispatchLedger.add(peerStorageKey(row.groupId, row.peerUserId, row.peerDeviceId, row.keyId));
    }
  }
  for (const { groupId, members } of snap.groupMembers ?? []) {
    if (groupId) groupMembers.set(groupId, members);
  }
}

/** Oturum yenilemeden önce vault’tan sender key durumunu yükler. */
export function hydrateSenderKeyStore(): Promise<void> {
  if (hydrated) return Promise.resolve();
  if (hydratePromise) return hydratePromise;

  hydratePromise = (async () => {
    const snap = await vaultGet<SenderKeyVaultSnapshot>(VAULT_SLOTS.SENDER_KEYS);
    if (snap) applyVaultSnapshot(snap);
    hydrated = true;
  })();

  return hydratePromise;
}

export function setGroupMembers(
  groupId: string,
  members: Array<{ user_id: string; shade_id: string }>,
): void {
  groupMembers.set(groupId, members);
  touchPersist();
}

export function getGroupMembers(groupId: string): Array<{ user_id: string; shade_id: string }> {
  return groupMembers.get(groupId) ?? [];
}

/** Android `markSkdmDispatched` muadili. `peerDeviceId` boşsa user id'yi placeholder olarak kullanır. */
export function markSkdmDispatched(
  groupId: string,
  peerUserId: string,
  peerDeviceId: string,
  ownKeyId: number,
): void {
  const dev = peerDeviceId || peerUserId;
  dispatchLedger.add(peerStorageKey(groupId, peerUserId, dev, ownKeyId));
  touchPersist();
}

/** Android `isSkdmDispatched`. */
export function isSkdmDispatched(
  groupId: string,
  peerUserId: string,
  peerDeviceId: string,
  ownKeyId: number,
): boolean {
  const dev = peerDeviceId || peerUserId;
  return dispatchLedger.has(peerStorageKey(groupId, peerUserId, dev, ownKeyId));
}

/** Anahtar rotasyonu sonrası eski key_id satırlarını temizler. */
export function purgeStaleDispatched(groupId: string, keepKeyId: number): void {
  let changed = false;
  for (const key of [...dispatchLedger]) {
    if (!key.startsWith(`${groupId}\0`)) continue;
    const parts = key.split("\0");
    if (parts.length !== 4) continue;
    if (Number(parts[3]) === keepKeyId) continue;
    dispatchLedger.delete(key);
    changed = true;
  }
  if (changed) touchPersist();
}

export function getOwnSenderKey(groupId: string): OwnSenderKeyState | undefined {
  return ownKeys.get(groupId);
}

/** İlk gönderimden önce oluşturulur veya döndürülür */
export function getOrCreateOwnSenderKey(groupId: string): OwnSenderKeyState {
  let k = ownKeys.get(groupId);
  if (!k) {
    k = createOwnSenderKey(groupId, 0);
    ownKeys.set(groupId, k);
    touchPersist();
  }
  return k;
}

export function setOwnSenderKey(groupId: string, state: OwnSenderKeyState): void {
  ownKeys.set(groupId, state);
  touchPersist();
}

export function rotateOwnSenderKey(groupId: string): OwnSenderKeyState {
  const prev = ownKeys.get(groupId);
  const nextKeyId = (prev?.keyId ?? -1) + 1;
  const fresh = createOwnSenderKey(groupId, nextKeyId);
  ownKeys.set(groupId, fresh);
  // Eski key_id ile yapılan tüm dispatch'ler artık geçersiz.
  purgeStaleDispatched(groupId, nextKeyId);
  touchPersist();
  return fresh;
}

export function deleteGroupCrypto(groupId: string): void {
  ownKeys.delete(groupId);
  for (const key of [...peerKeys.keys()]) {
    if (key.startsWith(`${groupId}\0`)) peerKeys.delete(key);
  }
  for (const key of [...dispatchLedger]) {
    if (key.startsWith(`${groupId}\0`)) dispatchLedger.delete(key);
  }
  groupMembers.delete(groupId);
  touchPersist();
}

/**
 * SKDM'i peer key olarak yükler. **Asla geri sarmaz**: mevcut peer state'in
 * chainIndex'i SKDM'in chainIndex'inden büyükse (web zaten daha ileri
 * mesajları işlemiş), yeni SKDM yok sayılır. Bu kontrol backend SKDM replay'i
 * ile race olmasını engeller.
 *
 * Dönüş: `true` = peer tablosuna yeni bir kayıt eklendi (caller reciprocate
 * kararı verebilir), `false` = eski/zaten bilinen SKDM.
 */
export function installPeerFromSkdm(skdmPlain: SenderKeyDistributionDecoded): boolean {
  const key = peerStorageKey(
    skdmPlain.group_id,
    skdmPlain.sender_user_id,
    skdmPlain.sender_device_id,
    skdmPlain.key_id,
  );
  const existing = peerKeys.get(key);
  if (existing && existing.chainIndex > skdmPlain.chain_index) {
    return false;
  }
  const peer = peerStateFromSkdm({
    chain_key: skdmPlain.chain_key,
    chain_index: skdmPlain.chain_index,
    signing_public_key: skdmPlain.signing_public_key,
  });
  peerKeys.set(key, peer);
  touchPersist();
  return existing === undefined;
}

export function getPeerSenderKey(
  groupId: string,
  senderUserId: string,
  senderDeviceId: string,
  keyId: number,
): PeerSenderKeyState | undefined {
  return peerKeys.get(peerStorageKey(groupId, senderUserId, senderDeviceId, keyId));
}

export interface ResolvedGroupPeer {
  peer: PeerSenderKeyState;
  /** AAD ve `setPeerSenderKey` için kullanılacak gönderici cihaz kimliği */
  cryptoDeviceId: string;
}

/**
 * GKD’deki `sender_device_id` ile payload’da boş/eksik alan uyumsuzluğunda peer bulur.
 * ChaCha AAD göndericinin gerçek cihaz kimliğini kullanır (payload boşsa SKDM’deki değer).
 */
export function resolvePeerSenderKeyForGroupMessage(
  groupId: string,
  senderUserId: string,
  payloadDeviceId: string,
  keyId: number,
): ResolvedGroupPeer | undefined {
  const fromPayload = payloadDeviceId.trim();
  if (fromPayload) {
    const exact = getPeerSenderKey(groupId, senderUserId, fromPayload, keyId);
    if (exact) return { peer: exact, cryptoDeviceId: fromPayload };
  }

  const entries = listPeerEntriesForSender(groupId, senderUserId, keyId);
  if (entries.length === 1) {
    const { deviceId, peer } = entries[0];
    return { peer, cryptoDeviceId: fromPayload || deviceId };
  }

  return undefined;
}

/** Aynı gönderici + key_id için bilinen tüm cihaz kimlikleri (çoklu cihaz echo). */
export function listPeerDeviceIdsForSender(
  groupId: string,
  senderUserId: string,
  keyId: number,
): string[] {
  return listPeerEntriesForSender(groupId, senderUserId, keyId).map((e) => e.deviceId);
}

export function listPeerEntriesForSender(
  groupId: string,
  senderUserId: string,
  keyId: number,
): Array<{ deviceId: string; peer: PeerSenderKeyState }> {
  const prefix = `${groupId}\0${senderUserId}\0`;
  const suffix = `\0${keyId}`;
  const out: Array<{ deviceId: string; peer: PeerSenderKeyState }> = [];
  for (const key of peerKeys.keys()) {
    if (!key.startsWith(prefix) || !key.endsWith(suffix)) continue;
    const deviceId = key.slice(prefix.length, key.length - suffix.length);
    const peer = peerKeys.get(key);
    if (deviceId && peer) out.push({ deviceId, peer });
  }
  return out;
}

export function setPeerSenderKey(
  groupId: string,
  senderUserId: string,
  senderDeviceId: string,
  keyId: number,
  state: PeerSenderKeyState,
): void {
  peerKeys.set(peerStorageKey(groupId, senderUserId, senderDeviceId, keyId), state);
  touchPersist();
}

export function removePeerKeysForMember(groupId: string, memberUserId: string): void {
  let changed = false;
  for (const key of [...peerKeys.keys()]) {
    if (!key.startsWith(`${groupId}\0`)) continue;
    const parts = key.split("\0");
    const uid = parts[1];
    if (uid === memberUserId) {
      peerKeys.delete(key);
      changed = true;
    }
  }
  if (changed) touchPersist();
}

export function resetSenderKeyStore(): void {
  ownKeys.clear();
  peerKeys.clear();
  groupMembers.clear();
  dispatchLedger.clear();
  hydrated = false;
  hydratePromise = null;
  if (persistTimer) {
    clearTimeout(persistTimer);
    persistTimer = null;
  }
  void vaultDelete(VAULT_SLOTS.SENDER_KEYS);
}
