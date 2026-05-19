import { WS_URL } from "../env";
import {
  encodeWebSocketMessage,
  decodeWebSocketMessage,
  type DecodedWebSocketMessage,
  decodeSenderKeyDistribution,
  encodeSenderKeyDistribution,
  type EncryptedPayloadData,
  type DeliveryReceiptData,
  type SenderKeyDistributionDecoded,
} from "../proto";
import { useMessageStore, type MsgStatus, toGroupChatId, parseGroupIdFromChatId } from "../store/messageStore";
import { useAuthStore } from "../store/authStore";
import { getContactInfo, getContactByUserId, fetchContactByUserId } from "../api/contactsApi";
import { decryptMessage } from "../crypto/messageCrypto";
import { encryptPairwiseBinary, decryptPairwiseBinary } from "../crypto/pairwiseBinary";
import { encryptGroupBody, decryptGroupBody } from "../crypto/groupSenderCrypto";
import {
  deleteGroupCrypto,
  getGroupMembers,
  getOwnSenderKey,
  getOrCreateOwnSenderKey,
  installPeerFromSkdm,
  isSkdmDispatched,
  LINKED_DEVICES_DISPATCH_ID,
  markSkdmDispatched,
  removePeerKeysForMember,
  resolvePeerSenderKeyForGroupMessage,
  rotateOwnSenderKey,
  setGroupMembers,
  setOwnSenderKey,
  setPeerSenderKey,
} from "./senderKeyStore";
import { fetchUserKeys } from "../api/keysApi";
import { fetchGroup } from "../api/groupsApi";
import { drainMessageInboxAll, inboxRowToPayload } from "../api/inboxApi";

let ws: WebSocket | null = null;
let heartbeatTimer: ReturnType<typeof setInterval> | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectAttempts = 0;
let intentionallyClosed = false;
let activeAccessToken: string | null = null;

const HEARTBEAT_MS = 25_000;
const MAX_BACKOFF_MS = 30_000;

/** SKDM gelmeden önce gelen grup payload’ları (Android → Web echo sırası). */
const pendingGroupPayloads: EncryptedPayloadData[] = [];
const pendingGroupPayloadIds = new Set<string>();

function effectiveDeviceId(): string {
  const { deviceId, userId } = useAuthStore.getState();
  const d = deviceId?.trim();
  return d || userId || "";
}

function clearHeartbeat(): void {
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
}

function startHeartbeat(): void {
  clearHeartbeat();
  heartbeatTimer = setInterval(() => {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    try {
      const bytes = encodeWebSocketMessage({ kind: "ack", ack: { message_id: "" } });
      ws.send(new Uint8Array(bytes).buffer as ArrayBuffer);
    } catch (e) {
      console.warn("[chatService] heartbeat send failed:", e);
    }
  }, HEARTBEAT_MS);
}

function clearReconnect(): void {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
}

function scheduleReconnect(): void {
  if (intentionallyClosed || !activeAccessToken) return;
  clearReconnect();
  const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), MAX_BACKOFF_MS);
  reconnectAttempts += 1;
  console.info(`[chatService] reconnect in ${delay}ms (attempt ${reconnectAttempts})`);
  reconnectTimer = setTimeout(() => {
    if (intentionallyClosed || !activeAccessToken) return;
    openSocket(activeAccessToken);
  }, delay);
}

function sendWsBinary(bytes: Uint8Array): boolean {
  if (!ws || ws.readyState !== WebSocket.OPEN) return false;
  ws.send(new Uint8Array(bytes).buffer as ArrayBuffer);
  return true;
}

function wsSend(receipt: DeliveryReceiptData): void {
  const payload: DeliveryReceiptData = {
    ...receipt,
    group_id: receipt.group_id?.trim() ? receipt.group_id : undefined,
  };
  sendWsBinary(encodeWebSocketMessage({ kind: "receipt", receipt: payload }));
}

function wsSendPayloadAck(messageId: string): void {
  if (!messageId || !ws || ws.readyState !== WebSocket.OPEN) return;
  sendWsBinary(encodeWebSocketMessage({ kind: "ack", ack: { message_id: messageId } }));
}

async function resolveSenderShadeId(
  senderUserId: string,
  incomingShadeId: string,
  accessToken: string,
): Promise<string> {
  if (incomingShadeId?.trim()) return incomingShadeId;
  try {
    const k = await fetchUserKeys(senderUserId, accessToken);
    return k.core_guard_id?.trim() || senderUserId;
  } catch {
    return senderUserId;
  }
}

/** Android `HandleGroupKeyDistributionUseCase` — yalnızca recipient_user_id (+ opsiyonel device). */
function gkdRecipientMatchesSelf(gkd: import("../proto").GroupKeyDistributionData): boolean {
  const { userId, shadeId } = useAuthStore.getState();
  const rid = gkd.recipient_user_id?.trim() ?? "";
  if (!rid) return false;
  if (userId && rid !== userId && (!shadeId || rid !== shadeId)) return false;

  const targetDevice = gkd.recipient_device_id?.trim() ?? "";
  if (!targetDevice) return true;
  return targetDevice === effectiveDeviceId();
}

/** Android `decryptSkdmOrRetry` — göndericinin X25519 public key adayları. */
async function collectSenderPubKeysForGkd(
  senderId: string,
  groupId: string,
  accessToken: string,
): Promise<string[]> {
  const pubs: string[] = [];
  const add = (hex?: string) => {
    const p = hex?.trim();
    if (p && !pubs.includes(p)) pubs.push(p);
  };

  const cached = await fetchContactByUserId(senderId, accessToken);
  add(cached?.encryption_public_key);

  const refreshed = await fetchContactByUserId(senderId, accessToken, { bypassCache: true });
  add(refreshed?.encryption_public_key);

  const shadeId = getGroupMembers(groupId)
    .find((m) => m.user_id === senderId)
    ?.shade_id?.trim();
  if (shadeId) {
    try {
      const fromShade = await getContactInfo(shadeId, accessToken);
      add(fromShade.encryption_public_key);
    } catch {
      /* shade lookup isteğe bağlı */
    }
  }

  return pubs;
}

async function decryptGkdSkdm(
  gkd: import("../proto").GroupKeyDistributionData,
  accessToken: string,
): Promise<Uint8Array | null> {
  const { x25519PrivKeyHex } = useAuthStore.getState();
  if (!x25519PrivKeyHex) return null;

  const senderId = gkd.sender_user_id?.trim() ?? "";
  const groupId = gkd.group_id?.trim() ?? "";
  if (!senderId) return null;

  const tryDecrypt = (pubHex: string): Uint8Array | null =>
    decryptPairwiseBinary(
      new Uint8Array(gkd.encrypted_skdm),
      new Uint8Array(gkd.nonce),
      x25519PrivKeyHex,
      pubHex,
    );

  for (const pub of await collectSenderPubKeysForGkd(senderId, groupId, accessToken)) {
    const plain = tryDecrypt(pub);
    if (plain) return plain;
  }
  return null;
}

/** Android `SendSenderKeyDistributionUseCase.resolveRecipientContact`. */
async function resolveSkdmRecipientPubKey(
  groupId: string,
  recipientUserId: string,
  accessToken: string,
): Promise<string> {
  const fromKeys = await fetchContactByUserId(recipientUserId, accessToken, { bypassCache: true });
  if (fromKeys?.encryption_public_key) return fromKeys.encryption_public_key;

  const shadeId = getGroupMembers(groupId)
    .find((m) => m.user_id === recipientUserId)
    ?.shade_id?.trim();
  if (shadeId) {
    try {
      const fromShade = await getContactInfo(shadeId, accessToken);
      if (fromShade.encryption_public_key) return fromShade.encryption_public_key;
    } catch {
      /* grup üyesi shade lookup isteğe bağlı */
    }
  }

  const local = getContactByUserId(recipientUserId);
  if (local?.encryption_public_key) return local.encryption_public_key;

  throw new Error(`SKDM recipient key not found: ${recipientUserId}`);
}

function pendingMatchesSkdm(payload: EncryptedPayloadData, skdm: SenderKeyDistributionDecoded): boolean {
  const gid = payload.group_id?.trim() ?? "";
  if (gid !== skdm.group_id?.trim()) return false;
  if (payload.sender_id !== skdm.sender_user_id) return false;
  if ((payload.sender_key_id ?? 0) !== skdm.key_id) return false;
  const pdev = payload.sender_device_id?.trim() ?? "";
  const sdev = skdm.sender_device_id?.trim() ?? "";
  return !pdev || !sdev || pdev === sdev;
}

function clearPendingGroupPayloads(): void {
  pendingGroupPayloads.length = 0;
  pendingGroupPayloadIds.clear();
}

function enqueuePendingGroupPayload(payload: EncryptedPayloadData): void {
  if (pendingGroupPayloadIds.has(payload.message_id)) return;
  pendingGroupPayloadIds.add(payload.message_id);
  pendingGroupPayloads.push(payload);
}

function dequeuePendingGroupPayload(messageId: string): void {
  pendingGroupPayloadIds.delete(messageId);
  const idx = pendingGroupPayloads.findIndex((p) => p.message_id === messageId);
  if (idx >= 0) pendingGroupPayloads.splice(idx, 1);
}

async function flushPendingGroupPayloadsForSkdm(skdm: SenderKeyDistributionDecoded): Promise<void> {
  const gid = skdm.group_id?.trim();
  if (!gid) return;
  const pending = pendingGroupPayloads
    .filter((p) => pendingMatchesSkdm(p, skdm))
    .sort((a, b) => {
      const ai = a.chain_index ?? 0n;
      const bi = b.chain_index ?? 0n;
      if (ai < bi) return -1;
      if (ai > bi) return 1;
      return 0;
    });
  for (const p of pending) {
    dequeuePendingGroupPayload(p.message_id);
    await handleGroupPayload(p);
  }
}

async function enrichDmPayload(payload: EncryptedPayloadData): Promise<EncryptedPayloadData> {
  if (payload.sender_shade_id?.trim()) return payload;
  const c = getContactByUserId(payload.sender_id);
  if (c?.shade_id) return { ...payload, sender_shade_id: c.shade_id };
  return payload;
}

async function sendSingleSkdm(
  groupId: string,
  own: import("../crypto/groupSenderCrypto").OwnSenderKeyState,
  recipientUserId: string,
  accessToken: string,
): Promise<boolean> {
  const { userId, x25519PrivKeyHex } = useAuthStore.getState();
  const senderDeviceId = effectiveDeviceId();
  if (!userId || !x25519PrivKeyHex) return false;

  let peerPub: string;
  try {
    peerPub = await resolveSkdmRecipientPubKey(groupId, recipientUserId, accessToken);
  } catch (e) {
    console.warn("[chatService] SKDM peer key fetch failed", recipientUserId, e);
    return false;
  }

  const innerPlain: SenderKeyDistributionDecoded = {
    group_id: groupId,
    sender_user_id: userId,
    sender_device_id: senderDeviceId,
    key_id: own.keyId,
    chain_key: new Uint8Array(own.chainKey),
    signing_public_key: new Uint8Array(own.signingPub),
    chain_index: own.chainIndex,
  };
  const innerBytes = encodeSenderKeyDistribution(innerPlain);
  const { ciphertext, nonce } = encryptPairwiseBinary(innerBytes, x25519PrivKeyHex, peerPub);
  /**
   * recipient_device_id boş — sunucu tüm bağlı oturumlara iletir; Android
   * `HandleGroupKeyDistribution` yalnızca dolu ve farklı device id’yi reddeder.
   */
  return sendWsBinary(
    encodeWebSocketMessage({
      kind: "gkd",
      gkd: {
        group_id: groupId,
        sender_user_id: userId,
        sender_device_id: senderDeviceId,
        recipient_user_id: recipientUserId,
        recipient_device_id: "",
        encrypted_skdm: ciphertext,
        nonce,
      },
    }),
  );
}

/**
 * Android `DistributeSenderKeyUseCase.invoke` — dispatch ledger'a bakar,
 * yalnızca yeni `(group, peer, ownKeyId)` çiftleri için SKDM yollar.
 */
async function distributeSenderKey(
  groupId: string,
  own: import("../crypto/groupSenderCrypto").OwnSenderKeyState,
  accessToken: string,
  options: { force?: boolean; onlyUserId?: string } = {},
): Promise<number> {
  const { userId } = useAuthStore.getState();
  if (!userId) return 0;
  const members = getGroupMembers(groupId);
  const force = options.force ?? false;
  let sent = 0;
  for (const m of members) {
    if (!m.user_id || m.user_id === userId) continue;
    if (options.onlyUserId && m.user_id !== options.onlyUserId) continue;
    const peerDevicePlaceholder = m.user_id;
    if (!force && isSkdmDispatched(groupId, m.user_id, peerDevicePlaceholder, own.keyId)) continue;
    const ok = await sendSingleSkdm(groupId, own, m.user_id, accessToken);
    if (ok) {
      markSkdmDispatched(groupId, m.user_id, peerDevicePlaceholder, own.keyId);
      sent++;
    }
  }
  return sent;
}

/** Android `distributeToLinkedDevices` — kendi userId'mize SKDM (linked echo). */
async function distributeSkdmToLinkedDevices(
  groupId: string,
  own: import("../crypto/groupSenderCrypto").OwnSenderKeyState,
  accessToken: string,
  force = true,
): Promise<boolean> {
  const { userId } = useAuthStore.getState();
  if (!userId) return false;
  if (!force && isSkdmDispatched(groupId, userId, LINKED_DEVICES_DISPATCH_ID, own.keyId)) {
    return false;
  }
  const ok = await sendSingleSkdm(groupId, own, userId, accessToken);
  if (ok) markSkdmDispatched(groupId, userId, LINKED_DEVICES_DISPATCH_ID, own.keyId);
  return ok;
}

async function refreshGroupMembers(groupId: string, accessToken: string): Promise<void> {
  try {
    const g = await fetchGroup(accessToken, groupId);
    setGroupMembers(
      groupId,
      g.members.map((m) => ({ user_id: m.user_id, shade_id: m.shade_id })),
    );
    useMessageStore.getState().ensureGroupChat(groupId, g.name);
  } catch {
    /* grup silinmiş olabilir */
  }
}

export async function sendGroupTextMessage(groupId: string, text: string): Promise<boolean> {
  const { userId, shadeId, accessToken } = useAuthStore.getState();
  if (!userId || !shadeId || !accessToken) return false;

  // Üye listesi yoksa REST'ten tazele — Android'in `getCachedMembers` fallback'i.
  if (getGroupMembers(groupId).length === 0) {
    await refreshGroupMembers(groupId, accessToken);
  }

  const own = getOwnSenderKey(groupId) ?? getOrCreateOwnSenderKey(groupId);
  const senderDeviceId = effectiveDeviceId();

  /**
   * Android `SendGroupMessageUseCase`:
   *  2a. Linked devices her mesaj öncesi `force=true` ile yenilenir.
   *  2b. Üyelere ise dispatch ledger'a göre, yalnızca yeni `(peer, key_id)` için yollanır.
   */
  await distributeSkdmToLinkedDevices(groupId, own, accessToken, true);
  await distributeSenderKey(groupId, own, accessToken, { force: false });

  const plain = new TextEncoder().encode(text);
  const chainIndexUsed = own.chainIndex;
  const senderKeyIdUsed = own.keyId;

  const { ciphertext, nonce, signature, nextOwn } = encryptGroupBody(own, plain, senderDeviceId);
  setOwnSenderKey(groupId, nextOwn);

  const messageId = crypto.randomUUID();
  const now = Date.now();

  useMessageStore.getState().addMessage({
    message_id: messageId,
    chat_id: toGroupChatId(groupId),
    sender_shade_id: shadeId,
    sender_user_id: userId,
    content: text,
    timestamp: now,
    msg_type: "TEXT",
    status: "SENT",
  });

  return sendProtoMessage({
    message_id: messageId,
    sender_id: userId,
    sender_shade_id: shadeId,
    receiver_id: "",
    ciphertext,
    nonce,
    auth_tag: new Uint8Array(0),
    timestamp: now,
    type: 0,
    group_id: groupId,
    sender_device_id: senderDeviceId,
    sender_key_id: senderKeyIdUsed,
    chain_index: chainIndexUsed,
    signature,
  });
}

async function handleGroupPayload(payload: EncryptedPayloadData): Promise<void> {
  const gid = payload.group_id?.trim();
  if (!gid) return;

  const { accessToken, userId, shadeId } = useAuthStore.getState();
  const store = useMessageStore.getState();
  if (!accessToken || !userId || !shadeId) return;

  const myDevice = effectiveDeviceId();
  const fromDevice = payload.sender_device_id?.trim() ?? "";

  /** Android ReceiveGroupMessageUseCase — aynı cihaz echo’su (UI’da zaten var). */
  if (payload.sender_id === userId && fromDevice && fromDevice === myDevice) {
    if (store.hasMessage(payload.message_id)) {
      store.updateMessageStatus(payload.message_id, "DELIVERED");
    }
    return;
  }

  /** Aynı hesap, farklı cihaz echo (UI’da zaten var). */
  const isOwnGroupEcho =
    payload.sender_id === userId &&
    (!payload.sender_shade_id?.trim() || payload.sender_shade_id === shadeId);
  const skipDuplicateUi = isOwnGroupEcho && store.hasMessage(payload.message_id);

  const senderShadeId = await resolveSenderShadeId(payload.sender_id, payload.sender_shade_id, accessToken);
  const payloadResolved = { ...payload, sender_shade_id: senderShadeId };

  const keyId = payload.sender_key_id ?? 0;
  const chainIdx = payload.chain_index;
  const sig = payload.signature;

  if (!fromDevice || chainIdx === undefined || !sig || sig.length === 0) {
    console.warn("[chatService] grup payload eksik alan", {
      message_id: payload.message_id,
      sender_device_id: Boolean(fromDevice),
      chain_index: chainIdx !== undefined,
      signature: Boolean(sig?.length),
    });
    return;
  }

  const resolved = resolvePeerSenderKeyForGroupMessage(
    gid,
    payload.sender_id,
    fromDevice,
    keyId,
  );

  if (!resolved) {
    enqueuePendingGroupPayload(payload);
    console.info(
      "[chatService] unknown sender-key payload; buffering",
      {
        message_id: payload.message_id,
        group_id: gid,
        key_id: keyId,
        sender_id: payload.sender_id,
        sender_device_id: fromDevice || "(no sender_device_id)",
        own_user_id: userId,
        own_device_id: myDevice,
        is_own_user: payload.sender_id === userId,
      },
    );
    /**
     * Android `ReceiveGroupMessageUseCase` — SKDM Recovery:
     *  1. Olası kayıp GKD'leri inbox'tan al.
     *  2. Kendi SKDM'imizi göndericiye `force=true` ile yolla; karşı taraf
     *     buna mukabil kendi SKDM'sini geri yollar (contract §10).
     */
    if (payload.sender_id !== userId) {
      console.info("[chatService] triggering SKDM recovery for", payload.sender_id);
      try {
        await applyInboxDrain(accessToken);
      } catch (e) {
        console.warn("[chatService] inbox recovery drain failed:", e);
      }
      try {
        const own = getOwnSenderKey(gid) ?? getOrCreateOwnSenderKey(gid);
        const sent = await distributeSenderKey(gid, own, accessToken, {
          force: true,
          onlyUserId: payload.sender_id,
        });
        console.info("[chatService] recovery SKDM dispatched count:", sent);
      } catch (e) {
        console.warn("[chatService] SKDM recovery dispatch failed:", e);
      }
    } else {
      console.info(
        "[chatService] payload is from OWN user but unknown device — waiting for SKDM from that device",
        fromDevice,
      );
    }
    return;
  }

  const { peer, cryptoDeviceId } = resolved;

  const dec = decryptGroupBody(
    peer,
    gid,
    cryptoDeviceId,
    keyId,
    new Uint8Array(payload.ciphertext),
    new Uint8Array(payload.nonce),
    new Uint8Array(sig),
    chainIdx,
  );

  if (!dec.ok) {
    if (dec.kind === "out_of_order") {
      /**
       * Sunucu yeniden teslim, inbox/WS çakışması veya ters sıralı teslimat.
       * Aynı mesajın daha önce çözüldüğüne (peer ratchet ileride) emin olduğumuzdan
       * sessizce drop ediyoruz; tekrar gönderim varsa store'da zaten görünüyor.
       */
      console.info("[chatService] grup payload zinciri geride — drop", {
        message_id: payload.message_id,
        group_id: gid,
        sender_device_id: fromDevice,
        payload_chain_index: chainIdx.toString(),
        peer_chain_index: dec.peerChainIndex.toString(),
        key_id: keyId,
      });
    } else {
      console.warn(`[chatService] grup şifre çözümü başarısız (${dec.kind})`, {
        message_id: payload.message_id,
        group_id: gid,
        sender_id: payload.sender_id,
        sender_device_id: fromDevice,
        chain_index: chainIdx.toString(),
        key_id: keyId,
      });
    }
    return;
  }

  dequeuePendingGroupPayload(payload.message_id);
  setPeerSenderKey(gid, payload.sender_id, cryptoDeviceId, keyId, dec.nextPeer);

  if (skipDuplicateUi) {
    store.updateMessageStatus(payloadResolved.message_id, "DELIVERED");
    wsSend({
      message_id: payloadResolved.message_id,
      sender_id: userId,
      sender_shade_id: shadeId,
      receiver_id: payloadResolved.sender_id,
      status: 0,
      timestamp: Date.now(),
      group_id: gid,
    });
    return;
  }

  let content: string;
  try {
    content = new TextDecoder().decode(dec.plaintext);
  } catch {
    content = "[şifresi çözülemeyen mesaj]";
  }

  const msg_type = payloadResolved.type === 1 ? "IMAGE" : "TEXT";

  store.addMessage({
    message_id: payloadResolved.message_id,
    chat_id: toGroupChatId(gid),
    sender_shade_id: senderShadeId,
    sender_user_id: payloadResolved.sender_id,
    content,
    timestamp: payloadResolved.timestamp,
    msg_type,
    status: "DELIVERED",
  });

  wsSend({
    message_id: payloadResolved.message_id,
    sender_id: userId,
    sender_shade_id: shadeId,
    receiver_id: payloadResolved.sender_id,
    status: 0,
    timestamp: Date.now(),
    group_id: gid,
  });
}

function dispatchIncomingWsMessage(msg: DecodedWebSocketMessage, sendPayloadAck: boolean): void {
  if (msg.kind === "payload") {
    // Android `IncomingWebSocketMessageHandler.handlePayload` — yalnızca DM
    // mesajları için ACK gönderir; grup payload'larında delivery receipt
    // inbox temizliği için yeterli olduğundan ACK atılmaz.
    const isGroup = Boolean(msg.payload.group_id?.trim());
    if (sendPayloadAck && !isGroup) wsSendPayloadAck(msg.payload.message_id);
    void handleIncomingPayload(msg.payload);
    return;
  }
  if (msg.kind === "receipt") {
    const status: MsgStatus = msg.receipt.status === 1 ? "READ" : "DELIVERED";
    useMessageStore.getState().updateMessageStatus(msg.receipt.message_id, status);
    return;
  }
  if (msg.kind === "gkd") {
    void handleIncomingGkd(msg.gkd);
    return;
  }
  if (msg.kind === "gme") {
    void handleIncomingGme(msg.gme);
  }
}

async function handleIncomingGkd(gkd: import("../proto").GroupKeyDistributionData): Promise<void> {
  const { userId, x25519PrivKeyHex, accessToken } = useAuthStore.getState();
  if (!userId || !x25519PrivKeyHex || !accessToken) return;

  console.info("[chatService] GKD in", {
    group_id: gkd.group_id,
    from: gkd.sender_user_id,
    recipient: gkd.recipient_user_id,
    recipient_device: gkd.recipient_device_id || "(all)",
  });

  if (!gkdRecipientMatchesSelf(gkd)) {
    console.info("[chatService] GKD ignored (not for this session)", gkd.recipient_user_id);
    return;
  }

  const gid = gkd.group_id?.trim();
  if (gid && getGroupMembers(gid).length === 0) {
    await refreshGroupMembers(gid, accessToken);
  }

  const plain = await decryptGkdSkdm(gkd, accessToken);
  if (!plain) {
    console.warn("[chatService] GKD çözülemedi", gkd.group_id, gkd.sender_user_id);
    return;
  }

  const skdm = decodeSenderKeyDistribution(plain);
  if (!skdm) return;

  if (
    skdm.sender_user_id !== gkd.sender_user_id ||
    skdm.sender_device_id !== gkd.sender_device_id ||
    skdm.group_id !== gkd.group_id
  ) {
    console.warn("[chatService] SKDM identity mismatch — dropping", {
      envelope: [gkd.sender_user_id, gkd.sender_device_id, gkd.group_id],
      inner: [skdm.sender_user_id, skdm.sender_device_id, skdm.group_id],
    });
    return;
  }

  const isNewPeer = installPeerFromSkdm(skdm);
  console.info("[chatService] GKD → peer sender key", {
    group_id: skdm.group_id,
    sender_user_id: skdm.sender_user_id,
    sender_device_id: skdm.sender_device_id,
    key_id: skdm.key_id,
    chain_index: skdm.chain_index.toString(),
    new_peer: isNewPeer,
  });
  await flushPendingGroupPayloadsForSkdm(skdm);

  /**
   * Kontrat §10 reciprocate: peer'in bizim SKDM'imizi kaybetmiş olma
   * ihtimaline karşı (ör. Android'in dispatch_ledger'ı eski device id'ye
   * referans veriyor), yeni öğrendiğimiz peer'a kendi SKDM'imizi force ile
   * yollayalım. Loop koruması için sadece NEW peer kayıtlarında tetikleniyor.
   */
  if (isNewPeer && skdm.sender_user_id && skdm.sender_user_id !== userId) {
    try {
      const own = getOwnSenderKey(skdm.group_id) ?? getOrCreateOwnSenderKey(skdm.group_id);
      await distributeSenderKey(skdm.group_id, own, accessToken, {
        force: true,
        onlyUserId: skdm.sender_user_id,
      });
    } catch (e) {
      console.warn("[chatService] reciprocate SKDM failed:", e);
    }
  }
}

async function handleIncomingGme(gme: import("../proto").GroupMembershipEventData): Promise<void> {
  const { userId, accessToken } = useAuthStore.getState();
  if (!userId || !accessToken) return;

  const gid = gme.group_id?.trim();
  if (!gid) return;

  const JOINED = 0;
  const LEFT = 1;
  const REMOVED = 2;

  if (gme.kind === JOINED) {
    if (gme.subject_id === userId) {
      await refreshGroupMembers(gid, accessToken);
      /** Yeni web cihazı: Android’in GKD’leri inbox’ta olabilir. */
      await applyInboxDrain(accessToken);
      return;
    }
    await refreshGroupMembers(gid, accessToken);
    const own = getOwnSenderKey(gid);
    if (own) {
      await distributeSenderKey(gid, own, accessToken, {
        force: true,
        onlyUserId: gme.subject_id,
      });
    }
    return;
  }

  if (gme.kind === LEFT || gme.kind === REMOVED) {
    if (gme.subject_id === userId) {
      deleteGroupCrypto(gid);
      useMessageStore.getState().removeGroupChat(gid);
      return;
    }

    removePeerKeysForMember(gid, gme.subject_id);
    await refreshGroupMembers(gid, accessToken);

    const fresh = rotateOwnSenderKey(gid);
    await distributeSenderKey(gid, fresh, accessToken, { force: true });
  }
}

/**
 * DM akışı — API_CONTRACT’daki birebir mesajlar.
 */
async function handleDmPayload(payload: EncryptedPayloadData): Promise<void> {
  const { x25519PrivKeyHex, accessToken, userId, shadeId } = useAuthStore.getState();
  const store = useMessageStore.getState();

  payload = await enrichDmPayload(payload);

  const isOutgoingEcho = payload.sender_shade_id === shadeId;
  const ct = new Uint8Array(payload.ciphertext);
  const nc = new Uint8Array(payload.nonce);
  const msg_type = payload.type === 1 ? "IMAGE" : "TEXT";

  if (isOutgoingEcho) {
    if (store.hasMessage(payload.message_id)) return;

    const peer = getContactByUserId(payload.receiver_id);
    if (!peer) {
      console.warn("[chatService] echo from other device but receiver not in cache:", payload.receiver_id);
      return;
    }
    let content: string;
    try {
      content = decryptMessage(ct, nc, x25519PrivKeyHex!, peer.encryption_public_key);
    } catch (e) {
      console.error("[chatService] echo decrypt threw:", e);
      content = "[şifresi çözülemeyen mesaj]";
    }
    store.addMessage({
      message_id: payload.message_id,
      chat_id: peer.shade_id,
      sender_shade_id: shadeId!,
      sender_user_id: userId,
      content,
      timestamp: payload.timestamp,
      msg_type,
      status: "DELIVERED",
    });
    return;
  }

  let senderUserId: string | undefined;
  let encPubKey: string;
  try {
    const contact = await getContactInfo(payload.sender_shade_id, accessToken!);
    senderUserId = contact.user_id;
    encPubKey = contact.encryption_public_key;
  } catch (e) {
    console.error("[chatService] contact lookup failed:", e);
    store.addMessage({
      message_id: payload.message_id,
      chat_id: payload.sender_shade_id,
      sender_shade_id: payload.sender_shade_id,
      content: "[iletişim bulunamadı]",
      timestamp: payload.timestamp,
      msg_type,
      status: "DELIVERED",
    });
    return;
  }

  let content: string;
  try {
    content = decryptMessage(ct, nc, x25519PrivKeyHex!, encPubKey);
  } catch (e) {
    console.error("[chatService] decryption threw:", e);
    content = "[şifresi çözülemeyen mesaj]";
  }

  store.addMessage({
    message_id: payload.message_id,
    chat_id: payload.sender_shade_id,
    sender_shade_id: payload.sender_shade_id,
    sender_user_id: senderUserId,
    content,
    timestamp: payload.timestamp,
    msg_type,
    status: "DELIVERED",
  });

  if (senderUserId && userId && shadeId) {
    wsSend({
      message_id: payload.message_id,
      sender_id: userId,
      sender_shade_id: shadeId,
      receiver_id: senderUserId,
      status: 0,
      timestamp: Date.now(),
    });
  }
}

async function handleIncomingPayload(payload: EncryptedPayloadData): Promise<void> {
  if (payload.group_id?.trim()) {
    await handleGroupPayload(payload);
    return;
  }
  await handleDmPayload(payload);
}

async function applyInboxDrain(accessToken: string): Promise<void> {
  try {
    const { protoFrames, legacyMessages, legacyReceipts } = await drainMessageInboxAll(accessToken);

    for (const frame of protoFrames) {
      const msg = decodeWebSocketMessage(frame);
      if (!msg) {
        console.warn("[chatService] inbox frame decode failed");
        continue;
      }
      dispatchIncomingWsMessage(msg, true);
    }

    for (const row of legacyMessages) {
      void handleIncomingPayload(inboxRowToPayload(row));
    }
    for (const rec of legacyReceipts) {
      const status: MsgStatus = rec.status === "READ" ? "READ" : "DELIVERED";
      useMessageStore.getState().updateMessageStatus(rec.message_id, status);
    }

    if (protoFrames.length > 0) {
      console.info(`[chatService] inbox drained ${protoFrames.length} proto frame(s)`);
    }
  } catch (e) {
    console.warn("[chatService] inbox drain failed:", e);
  }
}

function openSocket(accessToken: string): void {
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    return;
  }
  const url = `${WS_URL}/api/v1/ws?token=${encodeURIComponent(accessToken)}`;
  const socket = new WebSocket(url);
  socket.binaryType = "arraybuffer";
  ws = socket;

  socket.onopen = () => {
    reconnectAttempts = 0;
    startHeartbeat();
    void applyInboxDrain(accessToken);
  };

  socket.onmessage = (event: MessageEvent<ArrayBuffer>) => {
    const msg = decodeWebSocketMessage(new Uint8Array(event.data));
    if (!msg) return;
    dispatchIncomingWsMessage(msg, true);
  };

  socket.onerror = () => {};

  socket.onclose = () => {
    clearHeartbeat();
    if (ws === socket) ws = null;
    if (!intentionallyClosed) scheduleReconnect();
  };
}

export function connectChat(accessToken: string): () => void {
  intentionallyClosed = false;
  activeAccessToken = accessToken;
  reconnectAttempts = 0;
  clearPendingGroupPayloads();
  openSocket(accessToken);

  return () => {
    intentionallyClosed = true;
    activeAccessToken = null;
    clearPendingGroupPayloads();
    clearHeartbeat();
    clearReconnect();
    if (ws) {
      try {
        ws.close(1000);
      } catch {
        /* noop */
      }
      ws = null;
    }
  };
}

export function sendProtoMessage(payload: EncryptedPayloadData): boolean {
  if (!ws || ws.readyState !== WebSocket.OPEN) return false;
  sendWsBinary(encodeWebSocketMessage({ kind: "payload", payload }));
  return true;
}

export function sendReadReceiptsForChat(chatId: string): void {
  const { chats, updateMessageStatus } = useMessageStore.getState();
  const { userId, shadeId } = useAuthStore.getState();
  if (!userId || !shadeId) return;

  const chat = chats[chatId];
  if (!chat) return;

  const groupId = parseGroupIdFromChatId(chatId) ?? undefined;

  const now = Date.now();
  for (const msg of chat.messages) {
    const peerUserId = msg.sender_user_id;
    if (msg.sender_shade_id === shadeId || msg.status === "READ" || !peerUserId) continue;

    wsSend({
      message_id: msg.message_id,
      sender_id: userId,
      sender_shade_id: shadeId,
      receiver_id: peerUserId,
      status: 1,
      timestamp: now,
      group_id: groupId,
    });
    updateMessageStatus(msg.message_id, "READ");
  }
}
