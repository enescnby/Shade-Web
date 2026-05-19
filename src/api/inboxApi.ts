import { API_URL } from "../env";
import type { EncryptedPayloadData } from "../proto";

/** Eski / alternatif JSON inbox satırı (yalnızca payload alanları). */
export interface InboxMessageRow {
  message_id: string;
  sender_id: string;
  sender_shade_id?: string;
  receiver_id?: string;
  group_id?: string;
  ciphertext: string;
  nonce: string;
  message_type: number;
  timestamp: number;
  sender_device_id?: string;
  sender_key_id?: number;
  chain_index?: number | string;
  signature?: string;
}

export interface InboxReceiptRow {
  message_id: string;
  sender_id: string;
  receiver_id?: string;
  group_id?: string;
  status: string;
  timestamp: number;
}

/** Android `InboxItemDto` — WS ile aynı protobuf çerçevesi (GKD / GME / payload). */
interface InboxItemDto {
  data: string;
}

interface InboxProtoResponse {
  items?: InboxItemDto[];
  count?: number;
  has_more?: boolean;
}

interface InboxLegacyResponse {
  messages?: InboxMessageRow[];
  receipts?: InboxReceiptRow[];
}

function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function parseInboxChainIndex(raw: number | string | undefined): bigint | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw === "bigint") return raw;
  if (typeof raw === "number" && Number.isFinite(raw)) return BigInt(Math.floor(raw));
  const s = String(raw).trim();
  if (!s) return undefined;
  try {
    return BigInt(s);
  } catch {
    return undefined;
  }
}

/** Eski JSON inbox satırını proto payload şekline çevirir (timestamp ms). */
export function inboxRowToPayload(row: InboxMessageRow): EncryptedPayloadData {
  const gid = row.group_id?.trim() ?? "";
  const rid = row.receiver_id?.trim() ?? "";
  const sig = row.signature?.trim();
  return {
    message_id: row.message_id,
    sender_id: row.sender_id,
    sender_shade_id: row.sender_shade_id?.trim() ?? "",
    receiver_id: rid,
    ciphertext: b64ToBytes(row.ciphertext),
    nonce: b64ToBytes(row.nonce),
    auth_tag: new Uint8Array(0),
    timestamp: row.timestamp * 1000,
    type: row.message_type,
    group_id: gid || undefined,
    sender_device_id: row.sender_device_id?.trim() || undefined,
    sender_key_id: row.sender_key_id,
    chain_index: parseInboxChainIndex(row.chain_index),
    signature: sig ? b64ToBytes(sig) : undefined,
  };
}

export interface InboxDrainResult {
  /** Base64 `WebSocketMessage` ham çerçeveleri (Android ile aynı). */
  protoFrames: Uint8Array[];
  /** Eski JSON `messages` alanı varsa. */
  legacyMessages: InboxMessageRow[];
  legacyReceipts: InboxReceiptRow[];
  hasMore: boolean;
}

/**
 * Android `FetchInboxUseCase` ile aynı: `items[].data` = Base64 WebSocketMessage.
 * Eski sunucular için `messages` / `receipts` JSON alanları da okunur.
 */
export async function drainMessageInbox(
  accessToken: string,
  limit = 100,
): Promise<InboxDrainResult> {
  const url = new URL(`${API_URL}/api/v1/messages/inbox`);
  url.searchParams.set("limit", String(Math.min(Math.max(limit, 1), 500)));
  const res = await fetch(url.toString(), {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`inbox: ${res.status}`);

  const data = (await res.json()) as InboxProtoResponse & InboxLegacyResponse;

  const protoFrames: Uint8Array[] = [];
  if (Array.isArray(data.items)) {
    for (const item of data.items) {
      const raw = item?.data?.trim();
      if (!raw) continue;
      try {
        protoFrames.push(b64ToBytes(raw));
      } catch {
        console.warn("[inbox] invalid base64 item skipped");
      }
    }
  }

  return {
    protoFrames,
    legacyMessages: Array.isArray(data.messages) ? data.messages : [],
    legacyReceipts: Array.isArray(data.receipts) ? data.receipts : [],
    hasMore: Boolean(data.has_more),
  };
}

/** `has_more` bitene kadar tüm inbox partilerini çeker. */
export async function drainMessageInboxAll(
  accessToken: string,
  limit = 100,
): Promise<{ protoFrames: Uint8Array[]; legacyMessages: InboxMessageRow[]; legacyReceipts: InboxReceiptRow[] }> {
  const protoFrames: Uint8Array[] = [];
  const legacyMessages: InboxMessageRow[] = [];
  const legacyReceipts: InboxReceiptRow[] = [];
  let hasMore = true;

  while (hasMore) {
    const batch = await drainMessageInbox(accessToken, limit);
    protoFrames.push(...batch.protoFrames);
    legacyMessages.push(...batch.legacyMessages);
    legacyReceipts.push(...batch.legacyReceipts);
    hasMore = batch.hasMore;
    if (batch.protoFrames.length === 0 && batch.legacyMessages.length === 0) break;
  }

  return { protoFrames, legacyMessages, legacyReceipts };
}
