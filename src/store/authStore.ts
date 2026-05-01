import { create } from "zustand";
import { vaultPut, vaultGet, VAULT_SLOTS } from "./vaultStore";

interface AuthCredentials {
  jwt: string;
  shadeId: string;
  userId: string;
  x25519PrivKeyHex: string;
  ed25519PrivKeyHex: string;
}

interface AuthState extends AuthCredentials {
  isAuthenticated: boolean;
  /** True once we've attempted to load from the encrypted vault on boot. */
  hydrated: boolean;
  setAuth: (data: AuthCredentials) => void;
  clearAuth: () => void;
  hydrate: () => Promise<void>;
}

const EMPTY: AuthCredentials = {
  jwt: "",
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
    const stored = await vaultGet<AuthCredentials>(VAULT_SLOTS.AUTH);
    if (stored && stored.jwt) {
      set({ ...stored, isAuthenticated: true, hydrated: true });
    } else {
      set({ hydrated: true });
    }
  },
}));
