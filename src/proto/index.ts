import protobuf from "protobufjs";

const PROTO = `
syntax = "proto3";
package com.shade.app.proto;

enum MessageType { TEXT = 0; IMAGE = 1; }
enum ReceiptStatus { DELIVERED = 0; READ = 1; }

message EncryptedPayload {
  string message_id = 1;
  string sender_id = 2;
  string sender_shade_id = 3;
  string receiver_id = 4;
  bytes ciphertext = 5;
  bytes nonce = 6;
  bytes auth_tag = 7;
  int64 timestamp = 8;
  MessageType type = 9;
}

message DeliveryReceipt {
  string message_id = 1;
  string sender_id = 2;
  string sender_shade_id = 3;
  string receiver_id = 4;
  ReceiptStatus status = 5;
  int64 timestamp = 6;
}

message MessageAck { string message_id = 1; }

message WebSocketMessage {
  oneof content {
    EncryptedPayload payload = 1;
    DeliveryReceipt receipt = 2;
    MessageAck ack = 3;
  }
}

/** Android → Web sync tunnel: one binary frame per batch (optional vs JSON batch). */
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
`;

const root = protobuf.parse(PROTO, { keepCase: true }).root;
const WsMessageType = root.lookupType("com.shade.app.proto.WebSocketMessage");
const SyncWireBatchType = root.lookupType("com.shade.app.proto.SyncWireBatch");

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
}

export interface DeliveryReceiptData {
  message_id: string;
  sender_id: string;
  sender_shade_id: string;
  receiver_id: string;
  status: number;
  timestamp: number;
}

export interface MessageAckData {
  message_id: string;
}

export type DecodedWebSocketMessage =
  | { kind: "payload"; payload: EncryptedPayloadData }
  | { kind: "receipt"; receipt: DeliveryReceiptData }
  | { kind: "ack"; ack: MessageAckData };

function longToNumber(val: unknown): number {
  if (typeof val === "number") return val;
  if (val && typeof (val as { toNumber?: () => number }).toNumber === "function") {
    return (val as { toNumber: () => number }).toNumber();
  }
  return Number(val);
}

export function encodeWebSocketMessage(msg: DecodedWebSocketMessage): Uint8Array {
  let data: Record<string, unknown>;
  if (msg.kind === "payload") data = { payload: msg.payload };
  else if (msg.kind === "receipt") data = { receipt: msg.receipt };
  else data = { ack: msg.ack };
  return WsMessageType.encode(WsMessageType.create(data)).finish() as Uint8Array;
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
      return {
        kind: "payload",
        payload: {
          ...msg.payload,
          timestamp: longToNumber(msg.payload.timestamp),
          ciphertext: msg.payload.ciphertext ?? new Uint8Array(),
          nonce: msg.payload.nonce ?? new Uint8Array(),
          auth_tag: msg.payload.auth_tag ?? new Uint8Array(),
        },
      };
    }
    if (msg.receipt) {
      return {
        kind: "receipt",
        receipt: {
          ...msg.receipt,
          timestamp: longToNumber(msg.receipt.timestamp),
        },
      };
    }
    if (msg.ack) {
      return { kind: "ack", ack: { message_id: msg.ack.message_id } };
    }
    return null;
  } catch {
    return null;
  }
}
