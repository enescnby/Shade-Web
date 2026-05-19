import { API_URL } from "../env";
import { fetchUserKeys } from "./keysApi";

export interface ContactInfo {
  user_id: string;
  shade_id: string;
  encryption_public_key: string;
}

const byShadeId = new Map<string, ContactInfo>();
const byUserId = new Map<string, ContactInfo>();

function cacheContact(info: ContactInfo): void {
  byShadeId.set(info.shade_id, info);
  byUserId.set(info.user_id, info);
}

export async function getContactInfo(
  shadeId: string,
  accessToken: string,
): Promise<ContactInfo> {
  const cached = byShadeId.get(shadeId);
  if (cached) return cached;

  const res = await fetch(`${API_URL}/api/v1/user/lookup/${encodeURIComponent(shadeId)}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`Contact lookup failed: ${res.status}`);

  const data = (await res.json()) as ContactInfo;
  cacheContact(data);
  return data;
}

/**
 * Synchronous reverse lookup. Useful when an outgoing-echo arrives over the
 * websocket and we only know the receiver's user_id (the proto carries no
 * receiver_shade_id). Returns null if we've never resolved this contact yet.
 */
export function getContactByUserId(userId: string): ContactInfo | null {
  return byUserId.get(userId) ?? null;
}

/** Android `getOrFetchContactByUserId` — önce `GET /keys/:user_id`, sonra önbellek. */
export async function fetchContactByUserId(
  userId: string,
  accessToken: string,
  options?: { bypassCache?: boolean },
): Promise<ContactInfo | null> {
  if (!options?.bypassCache) {
    const cached = getContactByUserId(userId);
    if (cached?.encryption_public_key) return cached;
  }

  try {
    const keys = await fetchUserKeys(userId, accessToken);
    const info: ContactInfo = {
      user_id: userId,
      shade_id: keys.core_guard_id?.trim() || userId,
      encryption_public_key: keys.public_key,
    };
    cacheContact(info);
    return info;
  } catch {
    const cached = getContactByUserId(userId);
    return cached?.encryption_public_key ? cached : null;
  }
}

/** Pre-populate both caches — used by the sync flow once it knows chat partners. */
export async function prefetchContacts(
  shadeIds: string[],
  accessToken: string,
): Promise<void> {
  const fresh = shadeIds.filter((id) => !byShadeId.has(id));
  await Promise.allSettled(fresh.map((id) => getContactInfo(id, accessToken)));
}

export function clearContactCache(): void {
  byShadeId.clear();
  byUserId.clear();
}
