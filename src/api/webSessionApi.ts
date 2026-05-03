import { API_URL } from "../env";

export interface CreateSessionResponse {
  session_id: string;
}

export interface AuthorizedSessionResponse {
  ciphertext: string;
  nonce: string;
  android_x25519_pub: string;
  /** Web session access token (Bearer / WS query). Backend may use camelCase or PascalCase. */
  access_token?: string;
  AccessToken?: string;
  device_id?: string;
  DeviceID?: string;
}

/** Normalize poll JSON field names from the server. */
export function sessionPollTokens(data: AuthorizedSessionResponse): {
  accessToken: string;
  deviceId: string;
} {
  const accessToken = data.access_token ?? data.AccessToken ?? "";
  const deviceId = data.device_id ?? data.DeviceID ?? "";
  return { accessToken, deviceId };
}

const MOCK = import.meta.env.VITE_MOCK_AUTH === "true";

export async function createWebSession(): Promise<CreateSessionResponse> {
  if (MOCK) {
    return { session_id: crypto.randomUUID() };
  }
  const res = await fetch(`${API_URL}/api/v1/auth/web/session`, { method: "POST" });
  if (!res.ok) throw new Error(`Session oluşturulamadı: ${res.status}`);
  return res.json();
}

export async function pollWebSession(
  sessionId: string,
  signal: AbortSignal,
): Promise<AuthorizedSessionResponse | null> {
  if (MOCK) {
    // Mock modda sonsuza kadar bekle (Android taraması simüle edilmez)
    void sessionId;
    void signal;
    return null;
  }
  const res = await fetch(`${API_URL}/api/v1/auth/web/session/${sessionId}`, {
    signal,
  });
  if (res.status === 202) return null;
  if (!res.ok) throw new Error(`Session poll hatası: ${res.status}`);
  return res.json();
}
