import { create } from "zustand";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hexToBytes, decode } from "../crypto/utils";
import { vaultGet, vaultPut, VAULT_SLOTS } from "./vaultStore";

export type MsgType = "TEXT" | "IMAGE" | "FILE";
export type MsgStatus = "SENT" | "DELIVERED" | "READ";
export type SyncStatus = "idle" | "connecting" | "syncing" | "done" | "error";

export interface RawMessage {
  message_id: string;
  chat_id: string;
  sender_shade_id: string;
  ciphertext: string;
  nonce: string;
  timestamp: number;
  msg_type: MsgType;
  status: MsgStatus;
}

export interface Message {
  message_id: string;
  chat_id: string;
  sender_shade_id: string;
  sender_user_id?: string;
  content: string;
  timestamp: number;
  msg_type: MsgType;
  status: MsgStatus;
}

export const GROUP_CHAT_PREFIX = "group:";

export function toGroupChatId(groupId: string): string {
  return `${GROUP_CHAT_PREFIX}${groupId}`;
}

export function parseGroupIdFromChatId(chatId: string): string | null {
  return chatId.startsWith(GROUP_CHAT_PREFIX)
    ? chatId.slice(GROUP_CHAT_PREFIX.length)
    : null;
}

export interface Chat {
  chat_id: string;
  messages: Message[];
  lastMessage?: Message;
  kind?: "dm" | "group";
  /** Grup adı — gösterim için */
  title?: string;
}

interface PersistedSnapshot {
  chats: Record<string, Chat>;
  syncStatus: SyncStatus;
}

interface MessageState {
  chats: Record<string, Chat>;
  syncStatus: SyncStatus;
  syncError: string;
  hydrated: boolean;
  /** True once the initial post-auth Android->Web sync has completed at least once. */
  initialSyncDone: boolean;
  addBatch: (rawMessages: RawMessage[], transferKey: Uint8Array) => void;
  addMessage: (message: Message) => void;
  hasMessage: (messageId: string) => boolean;
  updateMessageStatus: (messageId: string, status: MsgStatus) => void;
  ensureGroupChat: (groupId: string, title: string) => void;
  removeGroupChat: (groupId: string) => void;
  setSyncStatus: (status: SyncStatus, error?: string) => void;
  reset: () => void;
  hydrate: () => Promise<void>;
}

function decryptContent(
  transferKey: Uint8Array,
  ciphertextHex: string,
  nonceHex: string,
): string {
  try {
    const cipher = chacha20poly1305(transferKey, hexToBytes(nonceHex));
    return decode(cipher.decrypt(hexToBytes(ciphertextHex)));
  } catch {
    return "[şifresi çözülemeyen mesaj]";
  }
}

/** Insert message preserving timestamp order; replace if same id already present. */
function upsertMessage(chat: Chat, msg: Message): Chat {
  const existingIdx = chat.messages.findIndex((m) => m.message_id === msg.message_id);
  let next: Message[];
  if (existingIdx >= 0) {
    next = chat.messages.slice();
    // Preserve plaintext content if the new copy is undecryptable but we already have one.
    const existing = next[existingIdx];
    const merged: Message = {
      ...existing,
      ...msg,
      content:
        msg.content === "[şifresi çözülemeyen mesaj]" && existing.content
          ? existing.content
          : msg.content,
    };
    next[existingIdx] = merged;
  } else {
    next = [...chat.messages, msg];
  }
  next.sort((a, b) => a.timestamp - b.timestamp);
  const lastMessage = next[next.length - 1];
  return { ...chat, messages: next, lastMessage };
}

let persistTimer: ReturnType<typeof setTimeout> | null = null;
function schedulePersist(snapshot: PersistedSnapshot): void {
  if (persistTimer) clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    void vaultPut<PersistedSnapshot>(VAULT_SLOTS.MESSAGES, snapshot);
  }, 250);
}

export const useMessageStore = create<MessageState>((set, get) => ({
  chats: {},
  syncStatus: "idle",
  syncError: "",
  hydrated: false,
  initialSyncDone: false,

  addBatch: (rawMessages, transferKey) => {
    set((state) => {
      const chats = { ...state.chats };
      for (const raw of rawMessages) {
        const msg: Message = {
          message_id: raw.message_id,
          chat_id: raw.chat_id,
          sender_shade_id: raw.sender_shade_id,
          content: decryptContent(transferKey, raw.ciphertext, raw.nonce),
          timestamp: raw.timestamp,
          msg_type: raw.msg_type,
          status: raw.status,
        };
        const existing = chats[raw.chat_id] ?? { chat_id: raw.chat_id, messages: [] };
        chats[raw.chat_id] = upsertMessage(existing, msg);
      }
      const next = { chats };
      schedulePersist({ chats, syncStatus: state.syncStatus });
      return next;
    });
  },

  addMessage: (message) => {
    set((state) => {
      const chats = { ...state.chats };
      const existing = chats[message.chat_id] ?? { chat_id: message.chat_id, messages: [] };
      chats[message.chat_id] = upsertMessage(existing, message);
      schedulePersist({ chats, syncStatus: state.syncStatus });
      return { chats };
    });
  },

  hasMessage: (messageId) => {
    const { chats } = get();
    for (const chatId of Object.keys(chats)) {
      if (chats[chatId].messages.some((m) => m.message_id === messageId)) return true;
    }
    return false;
  },

  ensureGroupChat: (groupId, title) => {
    const chat_id = toGroupChatId(groupId);
    set((state) => {
      const chats = { ...state.chats };
      const existing = chats[chat_id];
      chats[chat_id] = {
        chat_id,
        messages: existing?.messages ?? [],
        lastMessage: existing?.lastMessage,
        kind: "group",
        title,
      };
      schedulePersist({ chats, syncStatus: state.syncStatus });
      return { chats };
    });
  },

  removeGroupChat: (groupId) => {
    const chat_id = toGroupChatId(groupId);
    set((state) => {
      const chats = { ...state.chats };
      delete chats[chat_id];
      schedulePersist({ chats, syncStatus: state.syncStatus });
      return { chats };
    });
  },

  updateMessageStatus: (messageId, status) => {
    set((state) => {
      const chats = { ...state.chats };
      let touched = false;
      for (const chatId of Object.keys(chats)) {
        const updated = chats[chatId].messages.map((m) => {
          if (m.message_id !== messageId) return m;
          touched = true;
          return { ...m, status };
        });
        if (touched) {
          chats[chatId] = {
            ...chats[chatId],
            messages: updated,
            lastMessage: updated[updated.length - 1],
          };
        }
      }
      if (touched) schedulePersist({ chats, syncStatus: state.syncStatus });
      return { chats };
    });
  },

  setSyncStatus: (syncStatus, syncError = "") =>
    set((state) => {
      const next: Partial<MessageState> = { syncStatus, syncError };
      if (syncStatus === "done") next.initialSyncDone = true;
      schedulePersist({ chats: state.chats, syncStatus });
      return next;
    }),

  reset: () =>
    set({
      chats: {},
      syncStatus: "idle",
      syncError: "",
      initialSyncDone: false,
    }),

  hydrate: async () => {
    if (get().hydrated) return;
    const snap = await vaultGet<PersistedSnapshot>(VAULT_SLOTS.MESSAGES);
    if (snap) {
      set({
        chats: snap.chats ?? {},
        // After a refresh we don't need to re-run the one-shot Android sync —
        // those messages are already decrypted and persisted.
        initialSyncDone: snap.syncStatus === "done",
        syncStatus: snap.syncStatus === "done" ? "done" : "idle",
        hydrated: true,
      });
    } else {
      set({ hydrated: true });
    }
  },
}));
