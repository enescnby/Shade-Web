import { API_URL } from "../env";

export async function fetchUserKeys(
  userId: string,
  accessToken: string,
): Promise<{ core_guard_id: string; public_key: string }> {
  const res = await fetch(`${API_URL}/api/v1/keys/${encodeURIComponent(userId)}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`keys ${userId}: ${res.status}`);
  const data = (await res.json()) as { core_guard_id?: string; public_key?: string };
  const public_key = data.public_key ?? "";
  const core_guard_id = data.core_guard_id ?? "";
  if (!public_key) throw new Error("keys: missing public_key");
  return { core_guard_id, public_key };
}
