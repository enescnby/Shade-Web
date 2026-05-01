import { WS_URL } from "../env";
import {
  encodeWebSocketMessage,
  decodeWebSocketMessage,
  type EncryptedPayloadData,
  type DeliveryReceiptData,
} from "../proto";
import { useMessageStore, type MsgStatus } from "../store/messageStore";
import { useAuthStore } from "../store/authStore";
import { getContactInfo, getContactByUserId } from "../api/contactsApi";
import { decryptMessage } from "../crypto/messageCrypto";

let ws: WebSocket | null = null;
let heartbeatTimer: ReturnType<typeof setInterval> | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectAttempts = 0;
let intentionallyClosed = false;
let activeJwt: string | null = null;

const HEARTBEAT_MS = 25_000;
const MAX_BACKOFF_MS = 30_000;

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
      // Empty MessageAck — well-formed protobuf, no side effects on the server,
      // but enough WS traffic to keep intermediaries from idling-out the socket.
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
  if (intentionallyClosed || !activeJwt) return;
  clearReconnect();
  const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), MAX_BACKOFF_MS);
  reconnectAttempts += 1;
  console.info(`[chatService] reconnect in ${delay}ms (attempt ${reconnectAttempts})`);
  reconnectTimer = setTimeout(() => {
    if (intentionallyClosed || !activeJwt) return;
    openSocket(activeJwt);
  }, delay);
}

function wsSend(receipt: DeliveryReceiptData): void {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  const bytes = encodeWebSocketMessage({ kind: "receipt", receipt });
  ws.send(new Uint8Array(bytes).buffer as ArrayBuffer);
}

/**
 * Inbound payload handler. Three cases:
 *
 *   1. Normal incoming message: sender_shade_id !== ours.
 *        decrypt with (ourPriv, senderPub) and store under chat_id=sender_shade_id.
 *
 *   2. Outgoing echo we already sent from THIS web client (server fans-out
 *        every message to every connection of the user, including the sender).
 *        We already inserted the plaintext optimistically — so we just dedupe.
 *
 *   3. Outgoing echo originated from another device (Android) — needed for
 *        cross-device sync. We don't have the message locally, so we must
 *        decrypt and route it. The proto only carries receiver_id (a user_id);
 *        we resolve the receiver via the user_id reverse cache and route the
 *        message into chat_id=receiver.shade_id, sender_shade_id=ourShadeId.
 */
async function handleIncomingPayload(payload: EncryptedPayloadData): Promise<void> {
  const { x25519PrivKeyHex, jwt, userId, shadeId } = useAuthStore.getState();
  const store = useMessageStore.getState();

  const isOutgoingEcho = payload.sender_shade_id === shadeId;
  const ct = new Uint8Array(payload.ciphertext);
  const nc = new Uint8Array(payload.nonce);
  const msg_type = payload.type === 1 ? "IMAGE" : "TEXT";

  if (isOutgoingEcho) {
    // Case 2 — already shown locally; nothing to do.
    if (store.hasMessage(payload.message_id)) return;

    // Case 3 — echo from another device (Android); decrypt with peer pubkey.
    const peer = getContactByUserId(payload.receiver_id);
    if (!peer) {
      console.warn(
        "[chatService] echo from other device but receiver not in cache:",
        payload.receiver_id,
      );
      return;
    }
    let content: string;
    try {
      content = decryptMessage(ct, nc, x25519PrivKeyHex, peer.encryption_public_key);
    } catch (e) {
      console.error("[chatService] echo decrypt threw:", e);
      content = "[şifresi çözülemeyen mesaj]";
    }
    store.addMessage({
      message_id: payload.message_id,
      chat_id: peer.shade_id,
      sender_shade_id: shadeId,
      sender_user_id: userId,
      content,
      timestamp: payload.timestamp,
      msg_type,
      status: "DELIVERED",
    });
    return;
  }

  // Case 1 — normal incoming.
  let senderUserId: string | undefined;
  let encPubKey: string;
  try {
    const contact = await getContactInfo(payload.sender_shade_id, jwt);
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
    content = decryptMessage(ct, nc, x25519PrivKeyHex, encPubKey);
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

function openSocket(jwt: string): void {
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    return;
  }
  const url = `${WS_URL}/api/v1/ws?token=${encodeURIComponent(jwt)}`;
  const socket = new WebSocket(url);
  socket.binaryType = "arraybuffer";
  ws = socket;

  socket.onopen = () => {
    reconnectAttempts = 0;
    startHeartbeat();
  };

  socket.onmessage = (event: MessageEvent<ArrayBuffer>) => {
    const msg = decodeWebSocketMessage(new Uint8Array(event.data));
    if (!msg) return;

    if (msg.kind === "payload") {
      void handleIncomingPayload(msg.payload);
    } else if (msg.kind === "receipt") {
      const status: MsgStatus = msg.receipt.status === 1 ? "READ" : "DELIVERED";
      useMessageStore.getState().updateMessageStatus(msg.receipt.message_id, status);
    }
    // ack: server confirmed receipt — no UI action needed
  };

  socket.onerror = () => {
    // onclose will fire next; reconnect logic lives there.
  };

  socket.onclose = () => {
    clearHeartbeat();
    if (ws === socket) ws = null;
    if (!intentionallyClosed) scheduleReconnect();
  };
}

export function connectChat(jwt: string): () => void {
  intentionallyClosed = false;
  activeJwt = jwt;
  reconnectAttempts = 0;
  openSocket(jwt);

  return () => {
    intentionallyClosed = true;
    activeJwt = null;
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
  const bytes = encodeWebSocketMessage({ kind: "payload", payload });
  ws.send(new Uint8Array(bytes).buffer as ArrayBuffer);
  return true;
}

// Call when user opens a chat — sends READ receipts for all unread incoming messages
export function sendReadReceiptsForChat(chatId: string): void {
  const { chats, updateMessageStatus } = useMessageStore.getState();
  const { userId, shadeId } = useAuthStore.getState();
  if (!userId || !shadeId) return;

  const chat = chats[chatId];
  if (!chat) return;

  const now = Date.now();
  for (const msg of chat.messages) {
    if (msg.sender_shade_id !== shadeId && msg.status !== "READ" && msg.sender_user_id) {
      wsSend({
        message_id: msg.message_id,
        sender_id: userId,
        sender_shade_id: shadeId,
        receiver_id: msg.sender_user_id,
        status: 1,
        timestamp: now,
      });
      updateMessageStatus(msg.message_id, "READ");
    }
  }
}
