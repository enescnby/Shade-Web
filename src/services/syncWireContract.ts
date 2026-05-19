/**
 * @fileoverview Android → Web QR sync (`WS /api/v1/ws/sync/:session?role=web`) için grup bilgisinin JSON ile iletilmesi.
 *
 * ## Çerçeve türleri (UTF-8 JSON metin)
 *
 * Mevcut tipler korunur: `batch`, `sync_complete`, `error`.
 *
 * ### `groups_snapshot` (önerilir — mesaj batch’lerinden önce)
 *
 * ```json
 * {
 *   "type": "groups_snapshot",
 *   "groups": [ { ... REST GroupResponse ile aynı ... } ]
 * }
 * ```
 *
 * ### `batch` içinde opsiyonel `groups`
 *
 * ```json
 * {
 *   "type": "batch",
 *   "groups": [ ... ],
 *   "messages": [ ... ]
 * }
 * ```
 *
 * Web tarafı **önce** `groups`, **sonra** `messages` uygular.
 *
 * ## `groups[]` öğesi — `GET /api/v1/groups` ile birebir
 *
 * | Alan | Tip |
 * |------|-----|
 * | `group_id` | UUID string |
 * | `name` | string |
 * | `owner_id` | UUID string |
 * | `avatar_url` | string (boş olabilir) |
 * | `members` | `{ user_id, shade_id, role: "owner" \| "member" }[]` |
 * | `created_at` | ISO-8601 string |
 *
 * ## Grup mesajları — `RawMessage.chat_id`
 *
 * - **DM**: karşı tarafın Shade ID’si (mevcut davranış).
 * - **Grup**: `"group:" + group_id` — örn. `"group:550e8400-e29b-41d4-a716-446655440000"`.
 *
 * ## Önerilen Android sırası
 *
 * 1. Bir veya daha fazla `groups_snapshot` veya her batch’te güncel `groups`.
 * 2. `batch.messages` (grup satırlarında `chat_id` önekli).
 * 3. `sync_complete`.
 */

import type { GroupResponseDto } from "../api/groupsApi";
import { useMessageStore } from "../store/messageStore";
import { setGroupMembers } from "./senderKeyStore";

export type { GroupResponseDto as SyncWireGroupRow };

/**
 * REST ile uyumlu grup listesini uygular; üye Shade ID’lerini prefetch için döner.
 */
export function applySyncedGroupsFromWire(groups: unknown): Set<string> {
  const shadeIds = new Set<string>();
  if (!Array.isArray(groups)) return shadeIds;

  const ensure = useMessageStore.getState().ensureGroupChat;
  for (const raw of groups) {
    const g = raw as Partial<GroupResponseDto>;
    if (!g.group_id || typeof g.name !== "string") continue;

    const members = Array.isArray(g.members)
      ? g.members.map((m) => ({
          user_id: String(m.user_id ?? ""),
          shade_id: String(m.shade_id ?? ""),
          role: (m.role === "owner" ? "owner" : "member") as "owner" | "member",
        }))
      : [];

    for (const m of members) {
      if (m.shade_id) shadeIds.add(m.shade_id);
    }

    setGroupMembers(g.group_id, members);
    ensure(g.group_id, g.name);
  }
  return shadeIds;
}
