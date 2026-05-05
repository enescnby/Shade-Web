import { useSyncExternalStore } from "react";
import { translations, type TranslationKey } from "./translations";

// ── Language store (no React state — works outside components too) ──────────
type Listener = () => void;
const listeners = new Set<Listener>();

function getStoredLang(): string {
  try {
    const stored = localStorage.getItem("shade_lang");
    if (stored && stored in translations) return stored;
  } catch {
    // localStorage may be unavailable
  }
  // Auto-detect: if browser language starts with "tr" default to Turkish
  const browser = navigator.language ?? "";
  return browser.startsWith("tr") ? "tr" : "en";
}

let currentLang = getStoredLang();

export function setLanguage(lang: "en" | "tr") {
  currentLang = lang;
  try {
    localStorage.setItem("shade_lang", lang);
  } catch {
    // ignore
  }
  listeners.forEach((l) => l());
}

export function getLanguage(): string {
  return currentLang;
}

// ── Hook ─────────────────────────────────────────────────────────────────────
export function useTranslation() {
  const lang = useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => currentLang,
  );

  function t(key: TranslationKey, vars?: Record<string, string>): string {
    const dict = translations[lang] ?? translations["en"];
    let value = dict[key] ?? key;
    if (vars) {
      for (const [k, v] of Object.entries(vars)) {
        value = value.replaceAll(`{{${k}}}`, v);
      }
    }
    return value;
  }

  return { t, lang, setLanguage };
}
