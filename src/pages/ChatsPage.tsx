import { useEffect, useRef, useState, useCallback, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useLocation, useNavigate } from "react-router-dom";
import {
  Shield,
  LogOut,
  MessageCircle,
  Loader2,
  AlertCircle,
  Send,
  Check,
  CheckCheck,
  Image as ImageIcon,
  Download,
  ChevronDown,
  X,
  Users,
} from "lucide-react";
import { useAuthStore } from "../store/authStore";
import {
  useMessageStore,
  type Chat,
  type Message,
  parseGroupIdFromChatId,
} from "../store/messageStore";
import { startSync } from "../services/syncService";
import {
  connectChat,
  sendProtoMessage,
  sendReadReceiptsForChat,
  sendGroupTextMessage,
} from "../services/chatService";
import { resetSenderKeyStore, setGroupMembers } from "../services/senderKeyStore";
import { getContactInfo, clearContactCache } from "../api/contactsApi";
import {
  buildImageMessagePlaintext,
  downloadBlobAsFile,
  downloadMediaImage,
  extractMediaImageId,
  fetchMediaBlob,
  type MediaDecryptHint,
  parseImageMessageContent,
  shadeImageDownloadFilename,
  thumbnailBase64ToDataUrl,
  uploadMediaImage,
} from "../api/mediaApi";
import { encryptImageAttachment, encryptMessage } from "../crypto/messageCrypto";
import { clearVault } from "../store/vaultStore";
import { createGroup, fetchGroups } from "../api/groupsApi";

interface LocationState {
  sessionId?: string;
  transferKeyHex?: string;
}

export default function ChatsPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const { sessionId, transferKeyHex } = (location.state ?? {}) as LocationState;
  console.info("[ChatsPage] mount, location.state:", location.state, "sessionId:", sessionId);

  const accessToken = useAuthStore((s) => s.accessToken);
  const shadeId = useAuthStore((s) => s.shadeId);
  const userId = useAuthStore((s) => s.userId);
  const x25519PrivKeyHex = useAuthStore((s) => s.x25519PrivKeyHex);
  const clearAuth = useAuthStore((s) => s.clearAuth);

  const chats = useMessageStore((s) => s.chats);
  const syncStatus = useMessageStore((s) => s.syncStatus);
  const syncError = useMessageStore((s) => s.syncError);
  const reset = useMessageStore((s) => s.reset);
  const ensureGroupChat = useMessageStore((s) => s.ensureGroupChat);

  const [selectedChatId, setSelectedChatId] = useState<string | null>(null);
  const [imageUploadBusy, setImageUploadBusy] = useState(false);
  const [groupModalOpen, setGroupModalOpen] = useState(false);
  const [newGroupName, setNewGroupName] = useState("");
  const [newGroupMembersRaw, setNewGroupMembersRaw] = useState("");
  const [groupCreateBusy, setGroupCreateBusy] = useState(false);
  const addMessage = useMessageStore((s) => s.addMessage);

  // Send READ receipts when active chat changes or new messages arrive in it
  const selectedChatMsgCount = useMessageStore(
    (s) => (selectedChatId ? (s.chats[selectedChatId]?.messages.length ?? 0) : 0),
  );
  useEffect(() => {
    if (selectedChatId) sendReadReceiptsForChat(selectedChatId);
  }, [selectedChatId, selectedChatMsgCount]);

  useEffect(() => {
    if (!accessToken) return;
    let cancelled = false;
    void (async () => {
      try {
        const groups = await fetchGroups(accessToken);
        if (cancelled) return;
        for (const g of groups) {
          setGroupMembers(
            g.group_id,
            g.members.map((m) => ({ user_id: m.user_id, shade_id: m.shade_id })),
          );
          ensureGroupChat(g.group_id, g.name);
        }
      } catch (e) {
        console.warn("[ChatsPage] Gruplar yüklenemedi:", e);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [accessToken, ensureGroupChat]);

  useEffect(() => {
    if (!accessToken) return;
    let stopChat: (() => void) | undefined;
    const timer = setTimeout(() => {
      stopChat = connectChat(accessToken);
    }, 0);
    return () => {
      clearTimeout(timer);
      stopChat?.();
    };
  }, [accessToken]);

  useEffect(() => {
    // sessionId+transferKeyHex are only present in `location.state` immediately
    // after a successful QR auth navigation. On a hard refresh `location.state`
    // is null, so this effect bails — and the persisted chats from the vault
    // are already on screen via the messageStore hydrate(). No extra gate needed.
    if (!sessionId || !transferKeyHex || !accessToken) return;
    let stopSync: (() => void) | undefined;
    // setTimeout(0) prevents React StrictMode's double-invoke from opening two
    // simultaneous WebSocket connections; the timer is cancelled on the first
    // (fake) unmount so only the real mount ever calls startSync.
    const timer = setTimeout(() => {
      // Fresh QR auth means a brand-new session — wipe any in-memory chats
      // left over from a different account so we don't merge histories.
      reset();
      resetSenderKeyStore();
      stopSync = startSync({ sessionId, accessToken, transferKeyHex });
    }, 0);
    return () => {
      clearTimeout(timer);
      stopSync?.();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, transferKeyHex, accessToken]);

  async function handleSend(chatId: string, text: string) {
    const groupId = parseGroupIdFromChatId(chatId);
    if (groupId) {
      const ok = await sendGroupTextMessage(groupId, text);
      if (!ok) console.warn("[ChatsPage] Grup mesajı gönderilemedi");
      return;
    }

    if (!x25519PrivKeyHex || !shadeId || !userId) return;
    let contact: { user_id: string; shade_id: string; encryption_public_key: string };
    try {
      contact = await getContactInfo(chatId, accessToken);
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

  async function handleSendImage(chatId: string, file: File) {
    if (parseGroupIdFromChatId(chatId)) {
      window.alert("Grup sohbetlerinde görsel gönderimi henüz desteklenmiyor.");
      return;
    }
    if (!accessToken || !x25519PrivKeyHex || !shadeId || !userId || imageUploadBusy) return;
    let contact: { user_id: string; shade_id: string; encryption_public_key: string };
    try {
      contact = await getContactInfo(chatId, accessToken);
    } catch {
      return;
    }

    /* ChaCha-Poly ile şifreli gövde ≈ plaintext + 16 bayt AEAD — 10 MB sınırını aşmasın */
    const polyOverhead = 16;
    const maxPlainBytes = 10 * 1024 * 1024 - polyOverhead;
    if (file.size > maxPlainBytes) {
      window.alert("Görsel en fazla 10 MB olabilir");
      return;
    }

    setImageUploadBusy(true);
    try {
      /* Önce görüntü baytlarını alıcıya göre ChaCha-Poly ile şifrele; sunucuya sadece şifreli gövde gider. */
      const raw = new Uint8Array(await file.arrayBuffer());
      const { ciphertext: encryptedImageBody, nonceHex } = encryptImageAttachment(
        raw,
        x25519PrivKeyHex,
        contact.encryption_public_key,
      );
      const encBlob = new Blob([encryptedImageBody], { type: "application/octet-stream" });
      const imageId = await uploadMediaImage(encBlob, accessToken, file.name || "image.bin");
      const plaintext = await buildImageMessagePlaintext(file, imageId, nonceHex);
      const messageId = crypto.randomUUID();
      const now = Date.now();
      const { ciphertext, nonce } = encryptMessage(
        plaintext,
        x25519PrivKeyHex,
        contact.encryption_public_key,
      );

      addMessage({
        message_id: messageId,
        chat_id: chatId,
        sender_shade_id: shadeId,
        content: plaintext,
        timestamp: now,
        msg_type: "IMAGE",
        status: "SENT",
      });

      if (
        !sendProtoMessage({
          message_id: messageId,
          sender_id: userId,
          sender_shade_id: shadeId,
          receiver_id: contact.user_id,
          ciphertext,
          nonce,
          auth_tag: new Uint8Array(0),
          timestamp: now,
          type: 1,
        })
      ) {
        console.error("[ChatsPage] Görsel yüklendi; WebSocket koptu, proto gönderilemedi.");
        window.alert(
          "Görsel yüklendi fakat bağlantı koptu; mesaj iletilemedi. Sayfayı yenileyip yeniden gönder.",
        );
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("[ChatsPage] görsel gönderimi:", e);
      window.alert(msg);
    } finally {
      setImageUploadBusy(false);
    }
  }

  async function handleLogout() {
    clearAuth();
    reset();
    resetSenderKeyStore();
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

  async function handleCreateGroup() {
    const name = newGroupName.trim();
    if (!accessToken || !name || groupCreateBusy) return;
    setGroupCreateBusy(true);
    try {
      const shadeIds = newGroupMembersRaw
        .split(/[\s,;]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const member_ids: string[] = [];
      for (const shade of shadeIds) {
        try {
          const c = await getContactInfo(shade, accessToken);
          member_ids.push(c.user_id);
        } catch {
          console.warn("[ChatsPage] Shade bulunamadı, atlanıyor:", shade);
        }
      }
      const g = await createGroup(accessToken, { name, member_ids });
      setGroupMembers(
        g.group_id,
        g.members.map((m) => ({ user_id: m.user_id, shade_id: m.shade_id })),
      );
      ensureGroupChat(g.group_id, g.name);
      setGroupModalOpen(false);
      setNewGroupName("");
      setNewGroupMembersRaw("");
      setSelectedChatId(`group:${g.group_id}`);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      window.alert(msg);
    } finally {
      setGroupCreateBusy(false);
    }
  }

  const chatList = Object.values(chats).sort(
    (a, b) => (b.lastMessage?.timestamp ?? 0) - (a.lastMessage?.timestamp ?? 0),
  );

  const selectedChat = selectedChatId ? chats[selectedChatId] : null;

  return (
    <div className="flex h-screen overflow-hidden bg-gradient-to-br from-background via-background to-violet-500/[0.03] dark:to-violet-950/40">
      {/* Sidebar */}
      <aside className="flex w-[min(100%,20rem)] shrink-0 flex-col border-r border-border/60 bg-background/40 backdrop-blur-xl supports-[backdrop-filter]:bg-background/35">
        {/* Header */}
        <div className="flex items-center gap-3 border-b border-border/60 px-4 py-4">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-gradient-to-br from-violet-600 to-violet-700 shadow-lg shadow-violet-600/25 ring-2 ring-violet-400/20">
            <Shield className="h-[18px] w-[18px] text-white" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-[15px] font-semibold tracking-tight text-foreground">Shade Web</p>
            {shadeId && (
              <p className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground/90">{shadeId}</p>
            )}
          </div>
          <button
            type="button"
            onClick={() => setGroupModalOpen(true)}
            title="Grup oluştur"
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl text-muted-foreground transition-colors hover:bg-muted/80 hover:text-foreground"
          >
            <Users className="h-4 w-4" />
          </button>
          <button
            onClick={() => void handleLogout()}
            title="Çıkış yap"
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl text-muted-foreground transition-colors hover:bg-muted/80 hover:text-foreground"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>

        {/* Sync banner */}
        {syncStatus !== "done" && <SyncBanner status={syncStatus} error={syncError} />}

        {/* Chat list */}
        <div className="flex-1 overflow-y-auto">
          {chatList.length === 0 && syncStatus === "done" ? (
            <div className="flex h-full flex-col items-center justify-center gap-4 px-6 py-16 text-center">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-muted/80 ring-1 ring-border/50">
                <MessageCircle className="h-7 w-7 text-muted-foreground/35" />
              </div>
              <p className="text-[15px] font-medium text-muted-foreground">Henüz sohbet yok</p>
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

        {groupModalOpen ? (
          <div className="fixed inset-0 z-[400] flex items-center justify-center bg-black/50 p-4 backdrop-blur-sm">
            <div
              role="dialog"
              aria-labelledby="group-modal-title"
              className="w-full max-w-md rounded-2xl border border-border/60 bg-background p-5 shadow-xl"
            >
              <h2 id="group-modal-title" className="text-lg font-semibold text-foreground">
                Yeni grup
              </h2>
              <p className="mt-1 text-[13px] text-muted-foreground">
                Üye Shade ID&apos;leri opsiyoneldir (virgül veya boşlukla ayırın).
              </p>
              <label className="mt-4 block text-[13px] font-medium text-foreground">
                Grup adı
                <input
                  value={newGroupName}
                  onChange={(e) => setNewGroupName(e.target.value)}
                  maxLength={128}
                  className="mt-1.5 w-full rounded-xl border border-border/50 bg-muted/40 px-3 py-2 text-[15px] outline-none ring-violet-500/25 focus:ring-2"
                  placeholder="Örn. Proje takımı"
                />
              </label>
              <label className="mt-3 block text-[13px] font-medium text-foreground">
                Üye Shade ID&apos;leri
                <textarea
                  value={newGroupMembersRaw}
                  onChange={(e) => setNewGroupMembersRaw(e.target.value)}
                  rows={3}
                  className="mt-1.5 w-full resize-none rounded-xl border border-border/50 bg-muted/40 px-3 py-2 font-mono text-[12px] outline-none ring-violet-500/25 focus:ring-2"
                  placeholder="shade_a shade_b ..."
                />
              </label>
              <div className="mt-5 flex justify-end gap-2">
                <button
                  type="button"
                  disabled={groupCreateBusy}
                  onClick={() => setGroupModalOpen(false)}
                  className="rounded-xl px-4 py-2 text-[13px] font-medium text-muted-foreground hover:bg-muted"
                >
                  İptal
                </button>
                <button
                  type="button"
                  disabled={groupCreateBusy || !newGroupName.trim()}
                  onClick={() => void handleCreateGroup()}
                  className="rounded-xl bg-violet-600 px-4 py-2 text-[13px] font-semibold text-white shadow-md shadow-violet-600/20 hover:bg-violet-700 disabled:opacity-40"
                >
                  {groupCreateBusy ? "Oluşturuluyor..." : "Oluştur"}
                </button>
              </div>
            </div>
          </div>
        ) : null}
      </aside>

      {/* Main panel */}
      <main className="flex flex-1 flex-col overflow-hidden bg-muted/15">
        {selectedChat ? (
          <MessagePanel
            chat={selectedChat}
            currentShadeId={shadeId}
            accessToken={accessToken ?? ""}
            imageUploadBusy={imageUploadBusy}
            isGroupChat={Boolean(parseGroupIdFromChatId(selectedChat.chat_id))}
            onSend={(text) => void handleSend(selectedChat.chat_id, text)}
            onSendImage={(file) => void handleSendImage(selectedChat.chat_id, file)}
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
      <div className="flex items-center gap-2.5 border-b border-red-500/15 bg-red-500/[0.07] px-4 py-3 backdrop-blur-sm">
        <AlertCircle className="h-4 w-4 shrink-0 text-red-400" />
        <span className="text-[13px] leading-snug text-red-400">{error || "Senkronizasyon hatası"}</span>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-2.5 border-b border-violet-500/15 bg-violet-500/[0.08] px-4 py-3 backdrop-blur-sm">
      <Loader2 className="h-4 w-4 shrink-0 animate-spin text-violet-500" />
      <span className="text-[13px] font-medium text-violet-600 dark:text-violet-400">
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
      className={`mx-2 mb-1 flex w-[calc(100%-1rem)] items-start gap-3 rounded-2xl px-3 py-3 text-left transition-all duration-200 hover:bg-muted/60 ${
        selected
          ? "bg-violet-500/10 shadow-sm ring-1 ring-violet-500/15 hover:bg-violet-500/[0.14]"
          : ""
      }`}
    >
      <ChatAvatar id={chat.chat_id} />
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline justify-between gap-2">
          <p className="truncate font-mono text-[13px] font-medium tracking-tight text-foreground">
            {chat.kind === "group" ? chat.title ?? chat.chat_id : chat.chat_id}
          </p>
          {last && (
            <span className="shrink-0 tabular-nums text-[11px] text-muted-foreground">
              {formatTime(last.timestamp)}
            </span>
          )}
        </div>
        {last && (
          <p className="mt-1 truncate text-[13px] text-muted-foreground/90">
            {last.msg_type === "TEXT" ? (
              last.content
            ) : last.msg_type === "IMAGE" ? (
              <span className="inline-flex items-center gap-1">
                <ImageIcon className="h-3 w-3 shrink-0 opacity-70" aria-hidden />
                Fotoğraf
              </span>
            ) : (
              `[${last.msg_type.toLowerCase()}]`
            )}
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
  accessToken,
  imageUploadBusy,
  isGroupChat,
  onSend,
  onSendImage,
}: {
  chat: Chat;
  currentShadeId: string;
  accessToken: string;
  imageUploadBusy: boolean;
  isGroupChat: boolean;
  onSend: (text: string) => void;
  onSendImage: (file: File) => void;
}) {
  const endRef = useRef<HTMLDivElement>(null);
  const sorted = [...chat.messages].sort((a, b) => a.timestamp - b.timestamp);
  const [dragOverMsgs, setDragOverMsgs] = useState(false);
  const dragDepthRef = useRef(0);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chat.messages.length]);

  return (
    <>
      <div className="flex shrink-0 items-center gap-3 border-b border-border/60 bg-background/50 px-5 py-4 backdrop-blur-md">
        <ChatAvatar id={chat.chat_id} size="sm" />
        <p className="truncate font-mono text-[15px] font-semibold tracking-tight text-foreground">
          {chat.kind === "group" ? chat.title ?? chat.chat_id : chat.chat_id}
        </p>
      </div>

      <div
        className={`flex-1 space-y-3 overflow-y-auto px-4 py-6 transition-colors sm:px-6 ${
          dragOverMsgs ? "bg-violet-500/[0.07] ring-2 ring-violet-500/25 ring-inset" : ""
        }`}
        onDragEnter={(e) => {
          if (isGroupChat || !e.dataTransfer.types.includes("Files")) return;
          e.preventDefault();
          dragDepthRef.current += 1;
          setDragOverMsgs(true);
        }}
        onDragLeave={(e) => {
          if (isGroupChat) return;
          e.preventDefault();
          dragDepthRef.current = Math.max(0, dragDepthRef.current - 1);
          if (dragDepthRef.current === 0) setDragOverMsgs(false);
        }}
        onDragOver={(e) => {
          if (!isGroupChat && e.dataTransfer.types.includes("Files")) e.preventDefault();
        }}
        onDrop={(e) => {
          e.preventDefault();
          dragDepthRef.current = 0;
          setDragOverMsgs(false);
          if (isGroupChat) return;
          const file = e.dataTransfer.files?.[0];
          if (!file?.type.startsWith("image/")) return;
          onSendImage(file);
        }}
      >
        {dragOverMsgs && (
          <p className="pointer-events-none select-none rounded-2xl border border-dashed border-violet-500/35 bg-muted/40 py-12 text-center text-[13px] font-medium text-violet-600 dark:text-violet-300">
            Görseli buraya bırak
          </p>
        )}
        {sorted.map((msg) => (
          <MessageBubble
            key={msg.message_id}
            msg={msg}
            isOwn={msg.sender_shade_id === currentShadeId}
            accessToken={accessToken}
            encryptionPeerShadeId={chat.chat_id}
          />
        ))}
        <div ref={endRef} />
      </div>

      <MessageInput
        onSend={onSend}
        onSendImage={onSendImage}
        imageUploadBusy={imageUploadBusy}
        hideImageUpload={isGroupChat}
      />
    </>
  );
}

function MessageInput({
  onSend,
  onSendImage,
  imageUploadBusy,
  hideImageUpload,
}: {
  onSend: (text: string) => void;
  onSendImage: (file: File) => void;
  imageUploadBusy: boolean;
  hideImageUpload?: boolean;
}) {
  const [text, setText] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = text.trim();
    if (!trimmed) return;
    onSend(trimmed);
    setText("");
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (file) onSendImage(file);
  }

  function handlePaste(e: React.ClipboardEvent<HTMLInputElement>) {
    if (hideImageUpload) return;
    const items = e.clipboardData.items;
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      if (item.kind !== "file" || !item.type.startsWith("image/")) continue;
      e.preventDefault();
      const f = item.getAsFile();
      if (f) onSendImage(f);
      return;
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="flex shrink-0 items-center gap-2 border-t border-border/60 bg-background/70 px-4 py-4 backdrop-blur-lg supports-[backdrop-filter]:bg-background/55 sm:px-6"
    >
      <input
        ref={fileRef}
        type="file"
        accept="image/*"
        className="hidden"
        onChange={handleFileChange}
      />
      {!hideImageUpload ? (
        <button
          type="button"
          disabled={imageUploadBusy}
          title="Görsel gönder"
          onClick={() => fileRef.current?.click()}
          className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-border/50 bg-muted/80 text-muted-foreground shadow-sm transition-all hover:border-violet-500/25 hover:bg-muted hover:text-foreground disabled:opacity-40"
        >
          {imageUploadBusy ? (
            <Loader2 className="h-[18px] w-[18px] animate-spin" />
          ) : (
            <ImageIcon className="h-[18px] w-[18px]" />
          )}
        </button>
      ) : null}
      <input
        value={text}
        onChange={(e) => setText(e.target.value)}
        onPaste={handlePaste}
        placeholder="Mesaj yazın..."
        className="min-h-11 flex-1 rounded-2xl border border-border/40 bg-muted/50 px-4 py-2.5 text-[15px] outline-none ring-violet-500/30 transition-shadow placeholder:text-muted-foreground focus:border-violet-500/35 focus:bg-background focus:ring-2"
      />
      <button
        type="submit"
        disabled={!text.trim()}
        className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-gradient-to-br from-violet-600 to-violet-700 text-white shadow-md shadow-violet-600/25 transition-all hover:shadow-lg hover:shadow-violet-600/30 disabled:pointer-events-none disabled:opacity-35"
      >
        <Send className="h-[18px] w-[18px]" />
      </button>
    </form>
  );
}

function MessageBubble({
  msg,
  isOwn,
  accessToken,
  encryptionPeerShadeId,
}: {
  msg: Message;
  isOwn: boolean;
  accessToken: string;
  /** DM’de sohbetteki karşı Shade id — ECDH görsel anahtarı bu kişiye göre türetilir */
  encryptionPeerShadeId: string;
}) {
  const isImage = msg.msg_type === "IMAGE";
  return (
    <div className={`flex ${isOwn ? "justify-end" : "justify-start"}`}>
      <div
        className={`rounded-[1.25rem] shadow-md shadow-black/[0.04] ring-1 ring-black/[0.04] dark:shadow-black/20 dark:ring-white/[0.06] ${
          isImage
            ? "max-w-[min(88vw,280px)] px-2 pb-2 pt-2 sm:max-w-[min(90vw,340px)]"
            : "max-w-[min(85%,26rem)] px-4 py-2.5"
        } ${
          isOwn
            ? "rounded-br-md bg-gradient-to-br from-violet-600 to-violet-700 text-white"
            : "rounded-bl-md bg-card text-foreground"
        }`}
      >
        {!isOwn && (
          <p className="mb-1.5 truncate font-mono text-[10px] font-medium text-violet-500 dark:text-violet-400">
            {msg.sender_shade_id}
          </p>
        )}
        {msg.msg_type === "TEXT" ? (
          <p className="break-words text-[15px] leading-relaxed">{msg.content}</p>
        ) : msg.msg_type === "IMAGE" ? (
          <MessageImageBody
            content={msg.content}
            isOwn={isOwn}
            accessToken={accessToken}
            encryptionPeerShadeId={encryptionPeerShadeId}
          />
        ) : (
          <p className="text-sm italic opacity-70">[{msg.msg_type.toLowerCase()}]</p>
        )}
        <div
          className={`mt-2 flex items-center justify-end gap-1 tabular-nums text-[11px] ${
            isOwn ? "text-white/65" : "text-muted-foreground"
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
    <div className="flex flex-1 flex-col items-center justify-center gap-4 px-8 text-center">
      <div className="flex h-20 w-20 items-center justify-center rounded-3xl bg-muted/80 shadow-inner ring-1 ring-border/50">
        <MessageCircle className="h-10 w-10 text-muted-foreground/45" />
      </div>
      <div className="space-y-1">
        <p className="text-base font-medium text-foreground">Sohbet seçin</p>
        <p className="max-w-xs text-sm text-muted-foreground">Soldaki listeden bir konuşma açarak mesajları görüntüleyebilirsin.</p>
      </div>
    </div>
  );
}

/* ─── Helpers ─────────────────────────────────────────────────────────────── */

function mimeFromImageSrcUrl(url: string): string {
  if (!url.startsWith("data:")) return "image/jpeg";
  const semi = url.indexOf(";");
  if (semi <= 5) return "image/jpeg";
  return url.slice(5, semi) || "image/jpeg";
}

/** Resolve legacy inline payloads (not Android `ImageMessageContent` JSON). */
function imageSrcFromMessageContent(content: string): string | null {
  const trimmed = content.trim();
  if (
    !trimmed ||
    trimmed.startsWith("[şifresi") ||
    trimmed === "[iletişim bulunamadı]"
  ) {
    return null;
  }
  if (trimmed.startsWith("data:image/")) return trimmed;
  if (/^https?:\/\//i.test(trimmed)) return trimmed;

  try {
    const o = JSON.parse(trimmed) as {
      mime?: string;
      type?: string;
      contentType?: string;
      data?: string;
      base64?: string;
      url?: string;
    };
    if (typeof o.url === "string" && /^https?:\/\//i.test(o.url)) return o.url;
    const mime = o.mime ?? o.type ?? o.contentType ?? "image/jpeg";
    const b64 = o.data ?? o.base64;
    if (typeof b64 === "string" && b64.length > 0) {
      return b64.startsWith("data:") ? b64 : `data:${mime};base64,${b64}`;
    }
  } catch {
    /* not JSON */
  }

  const compact = trimmed.replace(/\s/g, "");
  if (compact.length < 32 || !/^[A-Za-z0-9+/=_-]+$/.test(compact)) return null;
  return thumbnailBase64ToDataUrl(compact);
}

/** Tam çözünürlük: aynı sayfada tam ekran modal (yeni sekme yok). */
function FullImageViewerModal({ src, onClose }: { src: string; onClose: () => void }) {
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [onClose]);

  return createPortal(
    <div
      role="presentation"
      className="fixed inset-0 z-[500] flex items-center justify-center bg-black/92 p-3 backdrop-blur-md sm:p-8"
      onClick={onClose}
    >
      <button
        type="button"
        aria-label="Kapat"
        onClick={(e) => {
          e.stopPropagation();
          onClose();
        }}
        className="absolute right-3 top-3 flex h-11 w-11 items-center justify-center rounded-full bg-white/12 text-white ring-1 ring-white/25 transition-colors hover:bg-white/22 sm:right-6 sm:top-6"
      >
        <X className="h-5 w-5" />
      </button>
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions */}
      <img
        src={src}
        alt=""
        className="max-h-[min(92vh,100dvh)] max-w-[min(96vw,100%)] object-contain shadow-2xl select-none"
        onClick={(e) => e.stopPropagation()}
      />
    </div>,
    document.body,
  );
}

function ImageCornerMenu({
  isOwn,
  children,
}: {
  isOwn: boolean;
  children: (close: () => void) => ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function closeExt(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", closeExt);
    return () => document.removeEventListener("mousedown", closeExt);
  }, [open]);

  const btnRing = isOwn ? "ring-white/25 hover:bg-black/50" : "ring-white/20 hover:bg-black/55";

  return (
    <div className="absolute right-2 top-2 z-[25]" ref={ref}>
      <button
        type="button"
        aria-expanded={open}
        aria-haspopup="menu"
        onClick={(e) => {
          e.stopPropagation();
          setOpen((v) => !v);
        }}
        className={`flex h-8 w-8 items-center justify-center rounded-full bg-black/40 text-white shadow-lg backdrop-blur-md transition-colors ring-1 ${btnRing}`}
      >
        <ChevronDown
          className={`h-4 w-4 transition-transform duration-200 ${open ? "rotate-180" : ""}`}
          aria-hidden
        />
      </button>
      {open && (
        <div
          role="menu"
          className="absolute right-0 top-full z-20 mt-1 min-w-[12rem] overflow-hidden rounded-xl border border-border/70 bg-popover py-1 text-popover-foreground shadow-2xl ring-1 ring-black/5 dark:bg-zinc-950/98 dark:ring-white/10"
          onClick={(e) => e.stopPropagation()}
        >
          {children(() => setOpen(false))}
        </div>
      )}
    </div>
  );
}

function ImageMenuItem({
  icon,
  label,
  disabled,
  busy,
  onClick,
}: {
  icon: ReactNode;
  label: string;
  disabled?: boolean;
  busy?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      role="menuitem"
      disabled={disabled || busy}
      className="flex w-full items-center gap-2.5 px-3 py-2.5 text-left text-[13px] font-medium transition-colors hover:bg-muted disabled:pointer-events-none disabled:opacity-45"
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
    >
      {busy ? <Loader2 className="h-4 w-4 shrink-0 animate-spin opacity-70" aria-hidden /> : icon}
      {label}
    </button>
  );
}

function triggerDownloadFromUrl(url: string, filename: string): void {
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function MessageImageBody({
  content,
  isOwn,
  accessToken,
  encryptionPeerShadeId,
}: {
  content: string;
  isOwn: boolean;
  accessToken: string;
  encryptionPeerShadeId: string;
}) {
  const parsed = parseImageMessageContent(content);
  const legacyImageId = !parsed ? extractMediaImageId(content) : null;
  const legacyInlineSrc = !parsed && !legacyImageId ? imageSrcFromMessageContent(content) : null;

  const thumbSrc = parsed ? thumbnailBase64ToDataUrl(parsed.thumbnailBase64) : null;

  const [brokenThumb, setBrokenThumb] = useState(false);
  const [downloadBusy, setDownloadBusy] = useState(false);

  const resolvedUrlRef = useRef<string | null>(null);
  const fullBlobCacheRef = useRef<Blob | null>(null);

  const [resolvedUrl, setResolvedUrl] = useState<string | null>(null);
  const [viewerSrc, setViewerSrc] = useState<string | null>(null);
  const [fullLoadBusy, setFullLoadBusy] = useState(false);
  const [fullLoadError, setFullLoadError] = useState(false);

  const imageIdForDownload = parsed?.imageId ?? legacyImageId;

  const needsServerFetch =
    Boolean(imageIdForDownload && accessToken && !legacyInlineSrc && !!(parsed || legacyImageId));

  const resolveMediaDecryptHint = useCallback(async (): Promise<MediaDecryptHint | undefined> => {
    const p = parseImageMessageContent(content);
    const nonce = p?.imageNonceHex?.trim();
    const priv = useAuthStore.getState().x25519PrivKeyHex;
    if (!nonce || !accessToken || !encryptionPeerShadeId || !priv) return undefined;
    try {
      const contact = await getContactInfo(encryptionPeerShadeId, accessToken);
      return {
        imageNonceHex: nonce,
        x25519PrivKeyHex: priv,
        peerEncryptionPubKeyHex: contact.encryption_public_key,
      };
    } catch {
      return undefined;
    }
  }, [content, accessToken, encryptionPeerShadeId]);

  useEffect(() => {
    fullBlobCacheRef.current = null;
    if (resolvedUrlRef.current) {
      URL.revokeObjectURL(resolvedUrlRef.current);
      resolvedUrlRef.current = null;
    }
    setResolvedUrl(null);
    setFullLoadError(false);
    setViewerSrc(null);
    setBrokenThumb(false);
  }, [content, legacyInlineSrc]);

  useEffect(
    () => () => {
      if (resolvedUrlRef.current) {
        URL.revokeObjectURL(resolvedUrlRef.current);
        resolvedUrlRef.current = null;
      }
      fullBlobCacheRef.current = null;
    },
    [],
  );

  useEffect(() => {
    if (!needsServerFetch || !imageIdForDownload) return;
    const imageId = imageIdForDownload;
    let cancelled = false;

    async function load() {
      setFullLoadBusy(true);
      setFullLoadError(false);
      try {
        const hint = await resolveMediaDecryptHint();
        const blob = await fetchMediaBlob(imageId, accessToken, hint);
        if (cancelled) return;
        fullBlobCacheRef.current = blob;
        const nextUrl = URL.createObjectURL(blob);
        if (resolvedUrlRef.current) URL.revokeObjectURL(resolvedUrlRef.current);
        resolvedUrlRef.current = nextUrl;
        setResolvedUrl(nextUrl);
      } catch {
        if (!cancelled) setFullLoadError(true);
      } finally {
        if (!cancelled) setFullLoadBusy(false);
      }
    }

    void load();

    return () => {
      cancelled = true;
    };
  }, [needsServerFetch, imageIdForDownload, accessToken, resolveMediaDecryptHint]);

  async function handleDownloadServer(close: () => void) {
    if (!imageIdForDownload || !accessToken) return;
    setDownloadBusy(true);
    try {
      if (fullBlobCacheRef.current) {
        downloadBlobAsFile(fullBlobCacheRef.current);
      } else {
        const decryptHint = await resolveMediaDecryptHint();
        await downloadMediaImage(imageIdForDownload, accessToken, decryptHint);
      }
      close();
    } catch (e) {
      console.error("[MessageImageBody] download failed:", e);
    } finally {
      setDownloadBusy(false);
    }
  }

  const aspectRatio =
    parsed && parsed.width > 0 && parsed.height > 0 ? parsed.width / parsed.height : undefined;

  const imgThumbClass =
    "max-h-52 min-h-14 w-full max-w-full rounded-xl object-cover transition-opacity duration-200 sm:max-h-60";
  const imgFullClass =
    "max-h-52 min-h-14 w-full max-w-full cursor-zoom-in rounded-xl object-contain bg-black/[0.04] sm:max-h-60 dark:bg-black/35";

  const imgBubbleFrame =
    "relative rounded-xl bg-muted/40 shadow-inner ring-1 ring-black/[0.06] dark:bg-black/25 dark:ring-white/[0.08]";
  const imgBubbleClip = "relative isolate overflow-hidden rounded-xl";

  const showThumbOnly = Boolean(thumbSrc && !brokenThumb && !resolvedUrl);

  const serverBubble = Boolean(!legacyInlineSrc && (parsed || legacyImageId));

  return (
    <>
      {viewerSrc ? (
        <FullImageViewerModal src={viewerSrc} onClose={() => setViewerSrc(null)} />
      ) : null}

      {legacyInlineSrc ? (
        <div className={`relative -mx-0.5 ${imgBubbleFrame}`}>
          <ImageCornerMenu isOwn={isOwn}>
            {(close) => (
              <ImageMenuItem
                icon={<Download className="h-4 w-4 shrink-0 opacity-80" aria-hidden />}
                label="Bilgisayara indir"
                onClick={() => {
                  triggerDownloadFromUrl(
                    legacyInlineSrc,
                    shadeImageDownloadFilename(mimeFromImageSrcUrl(legacyInlineSrc)),
                  );
                  close();
                }}
              />
            )}
          </ImageCornerMenu>
          <div className={imgBubbleClip}>
            {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions */}
            <img
              src={legacyInlineSrc}
              alt=""
              loading="lazy"
              decoding="async"
              tabIndex={0}
              title="Büyütmek için tıkla"
              onClick={() => setViewerSrc(legacyInlineSrc)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  setViewerSrc(legacyInlineSrc);
                }
              }}
              className={`${imgFullClass} outline-none ring-violet-500/0 focus-visible:ring-2`}
            />
          </div>
        </div>
      ) : null}

      {serverBubble ? (
        <div className={`relative ${imgBubbleFrame}`}>
          <ImageCornerMenu isOwn={isOwn}>
            {(close) => (
              <ImageMenuItem
                icon={<Download className="h-4 w-4 shrink-0 opacity-80" aria-hidden />}
                label="Bilgisayara indir"
                disabled={!accessToken}
                busy={downloadBusy}
                onClick={() => void handleDownloadServer(close)}
              />
            )}
          </ImageCornerMenu>
          <div
            className={imgBubbleClip}
            style={
              thumbSrc && !resolvedUrl && aspectRatio && !fullLoadError
                ? { aspectRatio }
                : undefined
            }
          >
            {resolvedUrl ? (
              <>
                {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions */}
                <img
                  src={resolvedUrl}
                  alt=""
                  loading="lazy"
                  decoding="async"
                  tabIndex={0}
                  title="Büyütmek için tıkla"
                  onClick={() => setViewerSrc(resolvedUrl)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      setViewerSrc(resolvedUrl);
                    }
                  }}
                  className={`${imgFullClass} outline-none ring-violet-500/0 focus-visible:ring-2`}
                />
              </>
            ) : showThumbOnly ? (
              <img
                src={thumbSrc!}
                alt=""
                loading="lazy"
                decoding="async"
                onError={() => setBrokenThumb(true)}
                className={`${imgThumbClass} ${fullLoadBusy ? "opacity-65" : ""}`}
              />
            ) : (
              <div
                className={`pointer-events-none flex min-h-[112px] flex-col items-center justify-center gap-2 px-4 py-10 text-center ${
                  isOwn ? "bg-white/12 text-white/90" : "bg-muted/60 text-muted-foreground"
                }`}
              >
                <ImageIcon className="h-10 w-10 opacity-55" aria-hidden />
                <span className="max-w-[15rem] text-[13px] leading-snug">
                  {fullLoadError ? "Görsel yüklenemedi. Köşeden indirmeyi dene." : "Yükleniyor..."}
                </span>
              </div>
            )}

            {fullLoadBusy && !resolvedUrl ? (
              <div className="pointer-events-none absolute right-3 top-14 flex justify-end">
                <span className="flex h-9 w-9 items-center justify-center rounded-full bg-black/45 text-white shadow-lg backdrop-blur-md">
                  <Loader2 className="h-[18px] w-[18px] animate-spin" aria-hidden />
                </span>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}

      {!legacyInlineSrc && !parsed && !legacyImageId ? (
        <p className={`text-sm italic opacity-70 ${isOwn ? "text-white/85" : ""}`}>
          Görsel gösterilemiyor
        </p>
      ) : null}
    </>
  );
}

function ChatAvatar({ id, size = "md" }: { id: string; size?: "sm" | "md" }) {
  const dim = size === "sm" ? "h-9 w-9 text-[11px]" : "h-11 w-11 text-sm";
  return (
    <div
      className={`shrink-0 flex items-center justify-center rounded-full bg-gradient-to-br from-violet-500/20 to-violet-600/10 font-semibold tracking-wide text-violet-600 shadow-sm ring-2 ring-background dark:text-violet-400 ${dim}`}
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
