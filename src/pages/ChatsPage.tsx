import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Shield, LogOut, MessageCircle, Loader2, AlertCircle, Send, Check, CheckCheck } from "lucide-react";
import { useAuthStore } from "../store/authStore";
import { useMessageStore, type Chat, type Message } from "../store/messageStore";
import { startSync } from "../services/syncService";
import { connectChat, sendProtoMessage, sendReadReceiptsForChat } from "../services/chatService";
import { getContactInfo, clearContactCache } from "../api/contactsApi";
import { encryptMessage } from "../crypto/messageCrypto";
import { clearVault } from "../store/vaultStore";

interface LocationState {
  sessionId?: string;
  transferKeyHex?: string;
}

export default function ChatsPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const { sessionId, transferKeyHex } = (location.state ?? {}) as LocationState;
  console.info("[ChatsPage] mount, location.state:", location.state, "sessionId:", sessionId);

  const jwt = useAuthStore((s) => s.jwt);
  const shadeId = useAuthStore((s) => s.shadeId);
  const userId = useAuthStore((s) => s.userId);
  const x25519PrivKeyHex = useAuthStore((s) => s.x25519PrivKeyHex);
  const clearAuth = useAuthStore((s) => s.clearAuth);

  const chats = useMessageStore((s) => s.chats);
  const syncStatus = useMessageStore((s) => s.syncStatus);
  const syncError = useMessageStore((s) => s.syncError);
  const reset = useMessageStore((s) => s.reset);

  const [selectedChatId, setSelectedChatId] = useState<string | null>(null);
  const addMessage = useMessageStore((s) => s.addMessage);

  // Send READ receipts when active chat changes or new messages arrive in it
  const selectedChatMsgCount = useMessageStore(
    (s) => (selectedChatId ? (s.chats[selectedChatId]?.messages.length ?? 0) : 0),
  );
  useEffect(() => {
    if (selectedChatId) sendReadReceiptsForChat(selectedChatId);
  }, [selectedChatId, selectedChatMsgCount]);

  useEffect(() => {
    if (!jwt) return;
    let stopChat: (() => void) | undefined;
    const timer = setTimeout(() => {
      stopChat = connectChat(jwt);
    }, 0);
    return () => {
      clearTimeout(timer);
      stopChat?.();
    };
  }, [jwt]);

  useEffect(() => {
    // sessionId+transferKeyHex are only present in `location.state` immediately
    // after a successful QR auth navigation. On a hard refresh `location.state`
    // is null, so this effect bails — and the persisted chats from the vault
    // are already on screen via the messageStore hydrate(). No extra gate needed.
    if (!sessionId || !transferKeyHex || !jwt) return;
    let stopSync: (() => void) | undefined;
    // setTimeout(0) prevents React StrictMode's double-invoke from opening two
    // simultaneous WebSocket connections; the timer is cancelled on the first
    // (fake) unmount so only the real mount ever calls startSync.
    const timer = setTimeout(() => {
      // Fresh QR auth means a brand-new session — wipe any in-memory chats
      // left over from a different account so we don't merge histories.
      reset();
      stopSync = startSync({ sessionId, jwt, transferKeyHex });
    }, 0);
    return () => {
      clearTimeout(timer);
      stopSync?.();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, transferKeyHex, jwt]);

  async function handleSend(chatId: string, text: string) {
    if (!x25519PrivKeyHex || !shadeId || !userId) return;
    let contact: { user_id: string; shade_id: string; encryption_public_key: string };
    try {
      contact = await getContactInfo(chatId, jwt);
    } catch {
      return;
    }

    const messageId = crypto.randomUUID();
    const now = Date.now();
    const { ciphertext, nonce } = encryptMessage(text, x25519PrivKeyHex, contact.encryption_public_key);

    addMessage({
      message_id: messageId,
      chat_id: chatId,
      sender_shade_id: shadeId,
      content: text,
      timestamp: now,
      msg_type: "TEXT",
      status: "SENT",
    });

    sendProtoMessage({
      message_id: messageId,
      sender_id: userId,
      sender_shade_id: shadeId,
      receiver_id: contact.user_id,
      ciphertext,
      nonce,
      auth_tag: new Uint8Array(0),
      timestamp: now,
      type: 0,
    });
  }

  async function handleLogout() {
    clearAuth();
    reset();
    clearContactCache();
    // Hard-wipe everything stored on the device — credentials, message history,
    // and the master AES key that encrypts them. Nothing should be recoverable.
    try {
      await clearVault();
    } catch (e) {
      console.warn("[logout] clearVault failed:", e);
    }
    navigate("/", { replace: true });
  }

  const chatList = Object.values(chats).sort(
    (a, b) => (b.lastMessage?.timestamp ?? 0) - (a.lastMessage?.timestamp ?? 0),
  );

  const selectedChat = selectedChatId ? chats[selectedChatId] : null;

  return (
    <div className="flex h-screen bg-background overflow-hidden">
      {/* Sidebar */}
      <aside className="flex w-72 shrink-0 flex-col border-r border-border">
        {/* Header */}
        <div className="flex items-center gap-3 border-b border-border px-4 py-3.5">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-violet-600">
            <Shield className="h-4 w-4 text-white" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold text-foreground">Shade Web</p>
            {shadeId && (
              <p className="text-xs text-muted-foreground truncate">{shadeId}</p>
            )}
          </div>
          <button
            onClick={() => void handleLogout()}
            title="Çıkış yap"
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>

        {/* Sync banner */}
        {syncStatus !== "done" && <SyncBanner status={syncStatus} error={syncError} />}

        {/* Chat list */}
        <div className="flex-1 overflow-y-auto">
          {chatList.length === 0 && syncStatus === "done" ? (
            <div className="flex h-full flex-col items-center justify-center gap-3 px-6 text-center">
              <MessageCircle className="h-10 w-10 text-muted-foreground/30" />
              <p className="text-sm text-muted-foreground">Henüz sohbet yok</p>
            </div>
          ) : (
            chatList.map((chat) => (
              <ChatRow
                key={chat.chat_id}
                chat={chat}
                selected={chat.chat_id === selectedChatId}
                onSelect={() => setSelectedChatId(chat.chat_id)}
              />
            ))
          )}
        </div>
      </aside>

      {/* Main panel */}
      <main className="flex flex-1 flex-col overflow-hidden">
        {selectedChat ? (
          <MessagePanel
            chat={selectedChat}
            currentShadeId={shadeId}
            onSend={(text) => void handleSend(selectedChat.chat_id, text)}
          />
        ) : (
          <EmptyPanel />
        )}
      </main>
    </div>
  );
}

/* ─── Sync banner ─────────────────────────────────────────────────────────── */

function SyncBanner({ status, error }: { status: string; error: string }) {
  if (status === "error") {
    return (
      <div className="flex items-center gap-2 border-b border-red-500/20 bg-red-500/10 px-4 py-2.5">
        <AlertCircle className="h-3.5 w-3.5 shrink-0 text-red-400" />
        <span className="text-xs text-red-400">{error || "Senkronizasyon hatası"}</span>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-2 border-b border-violet-500/20 bg-violet-500/10 px-4 py-2.5">
      <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-violet-400" />
      <span className="text-xs text-violet-400">
        {status === "connecting" ? "Bağlanıyor..." : "Mesajlar senkronize ediliyor..."}
      </span>
    </div>
  );
}

/* ─── Chat row ────────────────────────────────────────────────────────────── */

function ChatRow({
  chat,
  selected,
  onSelect,
}: {
  chat: Chat;
  selected: boolean;
  onSelect: () => void;
}) {
  const last = chat.lastMessage;
  return (
    <button
      onClick={onSelect}
      className={`flex w-full items-start gap-3 px-4 py-3.5 text-left transition-colors hover:bg-muted/50 ${
        selected ? "bg-muted" : ""
      }`}
    >
      <ChatAvatar id={chat.chat_id} />
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline justify-between gap-2">
          <p className="truncate text-sm font-medium text-foreground">{chat.chat_id}</p>
          {last && (
            <span className="shrink-0 text-[10px] text-muted-foreground">
              {formatTime(last.timestamp)}
            </span>
          )}
        </div>
        {last && (
          <p className="mt-0.5 truncate text-xs text-muted-foreground">
            {last.msg_type === "TEXT" ? last.content : `[${last.msg_type.toLowerCase()}]`}
          </p>
        )}
      </div>
    </button>
  );
}

/* ─── Message panel ───────────────────────────────────────────────────────── */

function MessagePanel({
  chat,
  currentShadeId,
  onSend,
}: {
  chat: Chat;
  currentShadeId: string;
  onSend: (text: string) => void;
}) {
  const endRef = useRef<HTMLDivElement>(null);
  const sorted = [...chat.messages].sort((a, b) => a.timestamp - b.timestamp);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chat.messages.length]);

  return (
    <>
      <div className="flex shrink-0 items-center gap-3 border-b border-border px-4 py-3.5">
        <ChatAvatar id={chat.chat_id} size="sm" />
        <p className="text-sm font-semibold text-foreground">{chat.chat_id}</p>
      </div>

      <div className="flex-1 space-y-2 overflow-y-auto px-4 py-4">
        {sorted.map((msg) => (
          <MessageBubble key={msg.message_id} msg={msg} isOwn={msg.sender_shade_id === currentShadeId} />
        ))}
        <div ref={endRef} />
      </div>

      <MessageInput onSend={onSend} />
    </>
  );
}

function MessageInput({ onSend }: { onSend: (text: string) => void }) {
  const [text, setText] = useState("");

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = text.trim();
    if (!trimmed) return;
    onSend(trimmed);
    setText("");
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="flex shrink-0 items-center gap-2 border-t border-border px-4 py-3"
    >
      <input
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder="Mesaj yazın..."
        className="flex-1 rounded-xl bg-muted px-4 py-2 text-sm outline-none placeholder:text-muted-foreground focus:ring-1 focus:ring-violet-500"
      />
      <button
        type="submit"
        disabled={!text.trim()}
        className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-violet-600 text-white transition-opacity disabled:opacity-40 hover:bg-violet-500"
      >
        <Send className="h-4 w-4" />
      </button>
    </form>
  );
}

function MessageBubble({ msg, isOwn }: { msg: Message; isOwn: boolean }) {
  return (
    <div className={`flex ${isOwn ? "justify-end" : "justify-start"}`}>
      <div
        className={`max-w-[70%] rounded-2xl px-3.5 py-2 ${
          isOwn
            ? "rounded-br-sm bg-violet-600 text-white"
            : "rounded-bl-sm bg-muted text-foreground"
        }`}
      >
        {!isOwn && (
          <p className="mb-1 text-[10px] font-medium text-violet-400">
            {msg.sender_shade_id}
          </p>
        )}
        {msg.msg_type === "TEXT" ? (
          <p className="break-words text-sm leading-snug">{msg.content}</p>
        ) : (
          <p className="text-sm italic opacity-70">[{msg.msg_type.toLowerCase()}]</p>
        )}
        <div
          className={`mt-1 flex items-center justify-end gap-1 text-[10px] ${
            isOwn ? "text-white/60" : "text-muted-foreground"
          }`}
        >
          <span>{formatTime(msg.timestamp)}</span>
          {isOwn && (
            msg.status === "READ" ? (
              <CheckCheck className="h-3 w-3 text-violet-300" />
            ) : msg.status === "DELIVERED" ? (
              <CheckCheck className="h-3 w-3 text-white/60" />
            ) : (
              <Check className="h-3 w-3 text-white/40" />
            )
          )}
        </div>
      </div>
    </div>
  );
}

/* ─── Empty state ─────────────────────────────────────────────────────────── */

function EmptyPanel() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-3 px-8 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-muted">
        <MessageCircle className="h-8 w-8 text-muted-foreground/40" />
      </div>
      <p className="text-sm text-muted-foreground">Bir sohbet seçin</p>
    </div>
  );
}

/* ─── Helpers ─────────────────────────────────────────────────────────────── */

function ChatAvatar({ id, size = "md" }: { id: string; size?: "sm" | "md" }) {
  const dim = size === "sm" ? "h-8 w-8 text-xs" : "h-10 w-10 text-sm";
  return (
    <div
      className={`shrink-0 flex items-center justify-center rounded-full bg-violet-500/15 font-semibold text-violet-400 ${dim}`}
    >
      {id.slice(0, 2).toUpperCase()}
    </div>
  );
}

function formatTime(ms: number): string {
  const d = new Date(ms);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) {
    return d.toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" });
  }
  return d.toLocaleDateString("tr-TR", { day: "2-digit", month: "2-digit" });
}
