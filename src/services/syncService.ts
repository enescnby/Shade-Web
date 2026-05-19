import { WS_URL } from "../env";
import { hexToBytes } from "../crypto/utils";
import { useMessageStore, type RawMessage, parseGroupIdFromChatId } from "../store/messageStore";
import { useAuthStore } from "../store/authStore";
import { prefetchContacts } from "../api/contactsApi";
import { applySyncedGroupsFromWire } from "./syncWireContract";

interface SyncOptions {
  sessionId: string;
  accessToken: string;
  transferKeyHex: string;
}

export function startSync({
  sessionId,
  accessToken,
  transferKeyHex,
}: SyncOptions): () => void {
  const { addBatch, setSyncStatus } = useMessageStore.getState();
  const transferKey = hexToBytes(transferKeyHex);
  /** DM karşı Shade ID’leri */
  const seenDmPeers = new Set<string>();
  /** Grup üyelerinin Shade ID’leri (contacts prefetch) */
  const seenGroupMemberShades = new Set<string>();

  setSyncStatus("connecting");

  const url = `${WS_URL}/api/v1/ws/sync/${sessionId}?token=${encodeURIComponent(accessToken)}&role=web`;
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
        groups?: unknown;
        code?: string;
        message?: string;
      };

      if (msg.type === "groups_snapshot" && msg.groups !== undefined) {
        applySyncedGroupsFromWire(msg.groups).forEach((id) => seenGroupMemberShades.add(id));
      }

      if (msg.type === "batch") {
        if (msg.groups !== undefined) {
          applySyncedGroupsFromWire(msg.groups).forEach((id) => seenGroupMemberShades.add(id));
        }
        if (Array.isArray(msg.messages)) {
          addBatch(msg.messages, transferKey);
          const ownShadeId = useAuthStore.getState().shadeId;
          for (const m of msg.messages) {
            if (!m.chat_id || m.chat_id === ownShadeId) continue;
            if (parseGroupIdFromChatId(m.chat_id)) continue;
            seenDmPeers.add(m.chat_id);
          }
        }
      } else if (msg.type === "sync_complete") {
        setSyncStatus("done");
        const shades = [...seenDmPeers, ...seenGroupMemberShades];
        if (shades.length > 0) {
          void prefetchContacts(shades, accessToken);
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
    if (event.code === 1000) return;
    if (event.code === 4401)
      setSyncStatus("error", "Oturum geçersiz veya süresi doldu");
    else if (event.code === 4404)
      setSyncStatus("error", "Sync oturumu bulunamadı");
    else if (event.code === 4410) setSyncStatus("error", "Sync süresi doldu");
    else if (event.code === 4408)
      setSyncStatus(
        "error",
        "Web bağlantısı zaman aşımına uğradı; tarayıcıda oturumu açık tutun",
      );
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
