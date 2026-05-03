import { create } from "zustand";
import { vaultPut, vaultGet, VAULT_SLOTS } from "./vaultStore";

interface AuthCredentials {
  /** OAuth-style access token for this web client only (Bearer / WS). */
  accessToken: string;
  /** Device/session id from the poll response (optional UX / future revoke). */
  deviceId: string;
  shadeId: string;
  userId: string;
  x25519PrivKeyHex: string;
  ed25519PrivKeyHex: string;
}

/** Legacy vault payloads used `jwt` for the same bearer value. */
type VaultAuthPayload = AuthCredentials & { jwt?: string };

interface AuthState extends AuthCredentials {
  isAuthenticated: boolean;
  /** True once we've attempted to load from the encrypted vault on boot. */
  hydrated: boolean;
  setAuth: (data: AuthCredentials) => void;
  clearAuth: () => void;
  hydrate: () => Promise<void>;
}

const EMPTY: AuthCredentials = {
  accessToken: "",
  deviceId: "",
  shadeId: "",
  userId: "",
  x25519PrivKeyHex: "",
  ed25519PrivKeyHex: "",
};

export const useAuthStore = create<AuthState>((set, get) => ({
  ...EMPTY,
  isAuthenticated: false,
  hydrated: false,

  setAuth: (data) => {
    set({ ...data, isAuthenticated: true });
    // Fire-and-forget — the in-memory state is the source of truth at runtime;
    // the vault is just so a refresh restores the same session.
    void vaultPut<AuthCredentials>(VAULT_SLOTS.AUTH, data);
  },

  clearAuth: () => {
    set({ ...EMPTY, isAuthenticated: false });
  },

  hydrate: async () => {
    if (get().hydrated) return;
    const stored = await vaultGet<VaultAuthPayload>(VAULT_SLOTS.AUTH);
    if (!stored) {
      set({ hydrated: true });
      return;
    }
    const accessToken = stored.accessToken || stored.jwt || "";
    if (!accessToken) {
      set({ hydrated: true });
      return;
    }
    const normalized: AuthCredentials = {
      accessToken,
      deviceId: stored.deviceId ?? "",
      shadeId: stored.shadeId,
      userId: stored.userId,
      x25519PrivKeyHex: stored.x25519PrivKeyHex,
      ed25519PrivKeyHex: stored.ed25519PrivKeyHex,
    };
    set({ ...normalized, isAuthenticated: true, hydrated: true });
    if (stored.jwt && !stored.accessToken) {
      void vaultPut<AuthCredentials>(VAULT_SLOTS.AUTH, normalized);
    }
  },
}));
