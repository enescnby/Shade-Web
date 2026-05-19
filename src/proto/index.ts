import protobuf from "protobufjs";
import Long from "long";
import messageProto from "./message.proto?raw";
import groupProto from "./group.proto?raw";
import envelopeProto from "./envelope.proto?raw";

/**
 * core-backend/proto içeriği tek kaynak; tarayıcıda `import` çözülmediği için burada birleştirilir.
 * Sıra: message.proto → group.proto → envelope.proto (import satırları atılır).
 */
function stripProtoPreamble(src: string): string {
  return src
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      if (!t) return true;
      if (t.startsWith("//")) return true;
      if (/^syntax\s+=/.test(t)) return false;
      if (/^package\s+\w+\s*;/.test(t)) return false;
      if (/^option\s+go_package/.test(t)) return false;
      if (/^import\s+"/.test(t)) return false;
      return true;
    })
    .join("\n")
    .trim();
}

/** Go backend proto setinde yok: SKDM AEAD düz metni (encrypted_skdm içeriği). */
const WEB_ONLY_PROTO = `
message SenderKeyDistribution {
  string group_id = 1;
  string sender_user_id = 2;
  string sender_device_id = 3;
  uint32 key_id = 4;
  bytes chain_key = 5;
  bytes signing_public_key = 6;
  uint64 chain_index = 7;
}

message SyncWireMessage {
  string message_id = 1;
  string chat_id = 2;
  string sender_shade_id = 3;
  bytes ciphertext = 4;
  bytes nonce = 5;
  int64 timestamp = 6;
  string msg_type = 7;
  string status = 8;
}

message SyncWireBatch {
  repeated SyncWireMessage messages = 1;
}
`.trim();

const MERGED_PROTO = [
  `syntax = "proto3";`,
  `package pb;`,
  `option go_package = "./pb";`,
  "",
  stripProtoPreamble(messageProto),
  "",
  stripProtoPreamble(groupProto),
  "",
  stripProtoPreamble(envelopeProto),
  "",
  WEB_ONLY_PROTO,
].join("\n");

const root = protobuf.parse(MERGED_PROTO, { keepCase: true }).root;
const PB_PKG = "pb";
const WsMessageType = root.lookupType(`${PB_PKG}.WebSocketMessage`);
const SyncWireBatchType = root.lookupType(`${PB_PKG}.SyncWireBatch`);
const SenderKeyDistributionType = root.lookupType(`${PB_PKG}.SenderKeyDistribution`);

export interface EncryptedPayloadData {
  message_id: string;
  sender_id: string;
  sender_shade_id: string;
  receiver_id: string;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  auth_tag: Uint8Array;
  timestamp: number;
  type: number;
  group_id?: string;
  sender_device_id?: string;
  sender_key_id?: number;
  chain_index?: bigint;
  signature?: Uint8Array;
}

export interface DeliveryReceiptData {
  message_id: string;
  sender_id: string;
  sender_shade_id: string;
  receiver_id: string;
  status: number;
  timestamp: number;
  group_id?: string;
}

export interface MessageAckData {
  message_id: string;
}

export interface GroupKeyDistributionData {
  group_id: string;
  sender_user_id: string;
  sender_device_id: string;
  recipient_user_id: string;
  recipient_device_id: string;
  encrypted_skdm: Uint8Array;
  nonce: Uint8Array;
}

export interface GroupMembershipEventData {
  group_id: string;
  kind: number;
  actor_id: string;
  subject_id: string;
  timestamp: number;
}

export type DecodedWebSocketMessage =
  | { kind: "payload"; payload: EncryptedPayloadData }
  | { kind: "receipt"; receipt: DeliveryReceiptData }
  | { kind: "ack"; ack: MessageAckData }
  | { kind: "gkd"; gkd: GroupKeyDistributionData }
  | { kind: "gme"; gme: GroupMembershipEventData };

function longToNumber(val: unknown): number {
  if (typeof val === "number") return val;
  if (val && typeof (val as { toNumber?: () => number }).toNumber === "function") {
    return (val as { toNumber: () => number }).toNumber();
  }
  return Number(val);
}

function longToBigInt(val: unknown): bigint {
  if (typeof val === "bigint") return val;
  if (typeof val === "number") return BigInt(Math.floor(val));
  if (val && typeof (val as { toBigInt?: () => bigint }).toBigInt === "function") {
    return (val as { toBigInt: () => bigint }).toBigInt();
  }
  if (val && typeof (val as { low?: number; high?: number }).low === "number") {
    const l = val as { low: number; high: number; unsigned?: boolean };
    const low = BigInt(l.low >>> 0);
    const high = BigInt(l.high >>> 0);
    if (l.unsigned) return (high << 32n) | low;
    return BigInt(longToNumber(val));
  }
  return BigInt(String(val));
}

export interface SenderKeyDistributionDecoded {
  group_id: string;
  sender_user_id: string;
  sender_device_id: string;
  key_id: number;
  chain_key: Uint8Array;
  signing_public_key: Uint8Array;
  chain_index: bigint;
}

function uint64ForProto(v: bigint): Long {
  return Long.fromBigInt(v, true);
}

export function encodeSenderKeyDistribution(skdm: SenderKeyDistributionDecoded): Uint8Array {
  const msg = SenderKeyDistributionType.create({
    group_id: skdm.group_id,
    sender_user_id: skdm.sender_user_id,
    sender_device_id: skdm.sender_device_id,
    key_id: skdm.key_id,
    chain_key: skdm.chain_key,
    signing_public_key: skdm.signing_public_key,
    chain_index: uint64ForProto(skdm.chain_index),
  });
  return SenderKeyDistributionType.encode(msg).finish() as Uint8Array;
}

export function decodeSenderKeyDistribution(bytes: Uint8Array): SenderKeyDistributionDecoded | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const d = SenderKeyDistributionType.decode(bytes) as any;
    return {
      group_id: d.group_id ?? "",
      sender_user_id: d.sender_user_id ?? "",
      sender_device_id: d.sender_device_id ?? "",
      key_id: d.key_id ?? 0,
      chain_key: d.chain_key ?? new Uint8Array(),
      signing_public_key: d.signing_public_key ?? new Uint8Array(),
      chain_index: longToBigInt(d.chain_index),
    };
  } catch {
    return null;
  }
}

export function encodeWebSocketMessage(msg: DecodedWebSocketMessage): Uint8Array {
  let data: Record<string, unknown>;
  if (msg.kind === "payload") data = { payload: normalizePayloadForEncode(msg.payload) };
  else if (msg.kind === "receipt") data = { receipt: msg.receipt };
  else if (msg.kind === "ack") data = { ack: msg.ack };
  else if (msg.kind === "gkd") data = { gkd: msg.gkd };
  else data = { gme: msg.gme };
  return WsMessageType.encode(WsMessageType.create(data)).finish() as Uint8Array;
}

function normalizePayloadForEncode(p: EncryptedPayloadData): Record<string, unknown> {
  const idx = p.chain_index ?? 0n;
  return {
    message_id: p.message_id,
    sender_id: p.sender_id,
    sender_shade_id: p.sender_shade_id,
    receiver_id: p.receiver_id ?? "",
    ciphertext: p.ciphertext,
    nonce: p.nonce,
    auth_tag: p.auth_tag ?? new Uint8Array(),
    timestamp: p.timestamp,
    type: p.type,
    group_id: p.group_id ?? "",
    sender_device_id: p.sender_device_id ?? "",
    sender_key_id: p.sender_key_id ?? 0,
    chain_index: uint64ForProto(idx),
    signature: p.signature ?? new Uint8Array(),
  };
}

export interface DecodedSyncWireMessage {
  message_id: string;
  chat_id: string;
  sender_shade_id: string;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  timestamp: number;
  msg_type: string;
  status: string;
}

/** Decode a binary sync batch frame from Android. Returns null if bytes are not a valid SyncWireBatch. */
export function decodeSyncWireBatch(bytes: Uint8Array): DecodedSyncWireMessage[] | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const decoded = SyncWireBatchType.decode(bytes) as any;
    const messages = decoded.messages as
      | Array<{
          message_id?: string;
          chat_id?: string;
          sender_shade_id?: string;
          ciphertext?: Uint8Array;
          nonce?: Uint8Array;
          timestamp?: unknown;
          msg_type?: string;
          status?: string;
        }>
      | undefined;
    if (!Array.isArray(messages)) return null;
    return messages.map((m) => ({
      message_id: m.message_id ?? "",
      chat_id: m.chat_id ?? "",
      sender_shade_id: m.sender_shade_id ?? "",
      ciphertext: m.ciphertext ?? new Uint8Array(),
      nonce: m.nonce ?? new Uint8Array(),
      timestamp: longToNumber(m.timestamp),
      msg_type: m.msg_type ?? "TEXT",
      status: m.status ?? "SENT",
    }));
  } catch {
    return null;
  }
}

export function decodeWebSocketMessage(bytes: Uint8Array): DecodedWebSocketMessage | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const msg = WsMessageType.decode(bytes) as any;
    if (msg.payload) {
      const chainRaw = msg.payload.chain_index;
      return {
        kind: "payload",
        payload: {
          ...msg.payload,
          timestamp: longToNumber(msg.payload.timestamp),
          ciphertext: msg.payload.ciphertext ?? new Uint8Array(),
          nonce: msg.payload.nonce ?? new Uint8Array(),
          auth_tag: msg.payload.auth_tag ?? new Uint8Array(),
          group_id: msg.payload.group_id || undefined,
          sender_device_id: msg.payload.sender_device_id || undefined,
          sender_key_id: msg.payload.sender_key_id ?? undefined,
          chain_index:
            chainRaw !== undefined && chainRaw !== null ? longToBigInt(chainRaw) : undefined,
          signature: msg.payload.signature ?? undefined,
        },
      };
    }
    if (msg.receipt) {
      return {
        kind: "receipt",
        receipt: {
          ...msg.receipt,
          timestamp: longToNumber(msg.receipt.timestamp),
          group_id: msg.receipt.group_id || undefined,
        },
      };
    }
    if (msg.ack) {
      return { kind: "ack", ack: { message_id: msg.ack.message_id } };
    }
    if (msg.gkd) {
      return {
        kind: "gkd",
        gkd: {
          group_id: msg.gkd.group_id ?? "",
          sender_user_id: msg.gkd.sender_user_id ?? "",
          sender_device_id: msg.gkd.sender_device_id ?? "",
          recipient_user_id: msg.gkd.recipient_user_id ?? "",
          recipient_device_id: msg.gkd.recipient_device_id ?? "",
          encrypted_skdm: msg.gkd.encrypted_skdm ?? new Uint8Array(),
          nonce: msg.gkd.nonce ?? new Uint8Array(),
        },
      };
    }
    if (msg.gme) {
      return {
        kind: "gme",
        gme: {
          group_id: msg.gme.group_id ?? "",
          kind: typeof msg.gme.kind === "number" ? msg.gme.kind : Number(msg.gme.kind),
          actor_id: msg.gme.actor_id ?? "",
          subject_id: msg.gme.subject_id ?? "",
          timestamp: longToNumber(msg.gme.timestamp),
        },
      };
    }
    return null;
  } catch {
    return null;
  }
}
