export type TranslationKey =
  | "app_tagline"
  | "qr_expired"
  | "qr_expires_in"
  | "qr_new"
  | "step1"
  | "step2"
  | "step3"
  | "footer_privacy"
  | "unknown_error"
  | "decrypt_error"
  | "poll_error"
  | "chats_empty"
  | "select_chat"
  | "type_message"
  | "logout_title"
  | "sync_connecting"
  | "sync_syncing"
  | "sync_error";

type Translations = Record<TranslationKey, string>;

const en: Translations = {
  app_tagline: "End-to-end encrypted messaging",
  qr_expired: "QR code\nexpired",
  qr_expires_in: "QR code expires in {{time}}",
  qr_new: "Generate New QR",
  step1: "Open the Shade app on your Android device",
  step2: 'Go to Settings → tap "Connect to Web"',
  step3: "Point the camera at the QR code",
  footer_privacy: "All data is end-to-end encrypted. The server cannot access message content.",
  unknown_error: "Unknown error",
  decrypt_error: "Decryption error",
  poll_error: "Poll error",
  chats_empty: "No chats yet",
  select_chat: "Select a conversation",
  type_message: "Type a message…",
  logout_title: "Log out",
  sync_connecting: "Connecting...",
  sync_syncing: "Syncing messages...",
  sync_error: "Sync error",
};

const tr: Translations = {
  app_tagline: "Uçtan uca şifreli mesajlaşma",
  qr_expired: "QR kodun süresi\ndoldu",
  qr_expires_in: "QR kod {{time}} sonra geçersiz olacak",
  qr_new: "Yeni QR Oluştur",
  step1: "Android'de Shade uygulamasını aç",
  step2: 'Ayarlar → "Web\'e Bağlan" seçeneğine dokun',
  step3: "Kamerayı QR kodun üzerine tut",
  footer_privacy: "Tüm veriler uçtan uca şifrelenir. Sunucu mesaj içeriklerine erişemez.",
  unknown_error: "Bilinmeyen hata",
  decrypt_error: "Şifre çözme hatası",
  poll_error: "Poll hatası",
  chats_empty: "Henüz sohbet yok",
  select_chat: "Bir sohbet seçin",
  type_message: "Mesaj yazın...",
  logout_title: "Çıkış yap",
  sync_connecting: "Bağlanıyor...",
  sync_syncing: "Mesajlar senkronize ediliyor...",
  sync_error: "Senkronizasyon hatası",
};

export const translations: Record<string, Translations> = { en, tr };
