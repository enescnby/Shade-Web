import { WS_URL } from "../env";
import { hexToBytes } from "../crypto/utils";
import { useMessageStore, type RawMessage } from "../store/messageStore";
import { useAuthStore } from "../store/authStore";
import { prefetchContacts } from "../api/contactsApi";

interface SyncOptions {
  sessionId: string;
  jwt: string;
  transferKeyHex: string;
}

export function startSync({
  sessionId,
  jwt,
  transferKeyHex,
}: SyncOptions): () => void {
  const { addBatch, setSyncStatus } = useMessageStore.getState();
  const transferKey = hexToBytes(transferKeyHex);
  const seenChatPartners = new Set<string>();

  setSyncStatus("connecting");

  const url = `${WS_URL}/api/v1/ws/sync/${sessionId}?token=${encodeURIComponent(jwt)}&role=web`;
  console.info("[sync] connecting", url);
  const ws = new WebSocket(url);

  ws.onopen = () => {
    console.info("[sync] open");
    setSyncStatus("syncing");
  };

  ws.onmessage = (event: MessageEvent<string>) => {
    try {
      const msg = JSON.parse(event.data) as {
        type: string;
        messages?: RawMessage[];
        code?: string;
        message?: string;
      };
      if (msg.type === "batch" && Array.isArray(msg.messages)) {
        addBatch(msg.messages, transferKey);
        // Track every chat partner so we can prefetch their contact info —
        // this populates the user_id reverse cache, which the realtime echo
        // handler needs to decrypt outgoing messages from another device.
        const ownShadeId = useAuthStore.getState().shadeId;
        for (const m of msg.messages) {
          if (m.chat_id && m.chat_id !== ownShadeId) seenChatPartners.add(m.chat_id);
        }
      } else if (msg.type === "sync_complete") {
        setSyncStatus("done");
        if (seenChatPartners.size > 0) {
          void prefetchContacts(Array.from(seenChatPartners), jwt);
        }
        ws.close(1000);
      } else if (msg.type === "error") {
        setSyncStatus("error", msg.message ?? msg.code ?? "Bilinmeyen hata");
      }
    } catch {
      // malformed frame — ignore
    }
  };

  ws.onerror = (e) => {
    console.error("[sync] error", e);
    setSyncStatus("error", "Bağlantı hatası");
  };

  ws.onclose = (event) => {
    console.info("[sync] close", event.code, event.reason);
    if (event.code === 1000) return; // normal close after sync_complete
    if (event.code === 4401)
      setSyncStatus("error", "Oturum geçersiz veya süresi doldu");
    else if (event.code === 4404)
      setSyncStatus("error", "Sync oturumu bulunamadı");
    else if (event.code === 4410) setSyncStatus("error", "Sync süresi doldu");
    else if (event.code === 4429)
      setSyncStatus("error", "Bağlantı limiti aşıldı");
    else if (useMessageStore.getState().syncStatus !== "done") {
      setSyncStatus("error", "Bağlantı beklenmedik şekilde kapandı");
    }
  };

  return () => {
    if (
      ws.readyState === WebSocket.OPEN ||
      ws.readyState === WebSocket.CONNECTING
    ) {
      ws.close();
    }
  };
}
