import { API_URL } from "../env";

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

export async function getContactInfo(shadeId: string, jwt: string): Promise<ContactInfo> {
  const cached = byShadeId.get(shadeId);
  if (cached) return cached;

  const res = await fetch(`${API_URL}/api/v1/user/lookup/${encodeURIComponent(shadeId)}`, {
    headers: { Authorization: `Bearer ${jwt}` },
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

/** Pre-populate both caches — used by the sync flow once it knows chat partners. */
export async function prefetchContacts(shadeIds: string[], jwt: string): Promise<void> {
  const fresh = shadeIds.filter((id) => !byShadeId.has(id));
  await Promise.allSettled(fresh.map((id) => getContactInfo(id, jwt)));
}

export function clearContactCache(): void {
  byShadeId.clear();
  byUserId.clear();
}
