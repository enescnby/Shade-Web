import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { QRCodeSVG } from "qrcode.react";
import { Shield, RefreshCw } from "lucide-react";
import {
  deriveTransferKey,
  decryptCredentials,
  generateEphemeralKeyPair,
} from "../crypto/authCrypto";
import { bytesToHex } from "../crypto/utils";
import {
  createWebSession,
  pollWebSession,
  sessionPollTokens,
} from "../api/webSessionApi";
import { useAuthStore } from "../store/authStore";

const QR_TTL_SECONDS = 120;
const POLL_INTERVAL_MS = 2000;

type Status = "loading" | "waiting" | "success" | "error" | "expired";

function ScanCorners() {
  return (
    <>
      <span className="absolute -top-px -left-px h-7 w-7 rounded-tl-xl border-t-2 border-l-2 border-violet-500" />
      <span className="absolute -top-px -right-px h-7 w-7 rounded-tr-xl border-t-2 border-r-2 border-violet-500" />
      <span className="absolute -bottom-px -left-px h-7 w-7 rounded-bl-xl border-b-2 border-l-2 border-violet-500" />
      <span className="absolute -bottom-px -right-px h-7 w-7 rounded-br-xl border-b-2 border-r-2 border-violet-500" />
    </>
  );
}

function Step({ n, text }: { n: number; text: string }) {
  return (
    <div className="flex items-start gap-3">
      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-violet-500/15 text-[11px] font-semibold text-violet-500 mt-0.5">
        {n}
      </span>
      <p className="text-sm text-muted-foreground leading-snug">{text}</p>
    </div>
  );
}

export default function QrAuthPage() {
  const navigate = useNavigate();
  const setAuth = useAuthStore((s) => s.setAuth);

  const wasAuthenticatedAtMount = useRef(
    useAuthStore.getState().isAuthenticated,
  );

  useEffect(() => {
    if (wasAuthenticatedAtMount.current) {
      navigate("/chats", { replace: true });
    }
  }, [navigate]);

  const [status, setStatus] = useState<Status>("loading");
  const [qrValue, setQrValue] = useState("");
  const [secondsLeft, setSecondsLeft] = useState(QR_TTL_SECONDS);
  const [errorMsg, setErrorMsg] = useState("");

  const sessionIdRef = useRef("");
  const privKeyRef = useRef<Uint8Array | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const initSession = useRef(async () => {
    setSecondsLeft(QR_TTL_SECONDS);
    try {
      const keypair = generateEphemeralKeyPair();
      privKeyRef.current = keypair.privKey;
      const { session_id } = await createWebSession();
      sessionIdRef.current = session_id;
      setQrValue(`shade://web-auth?s=${session_id}&k=${keypair.pubKeyHex}`);
      setStatus("waiting");
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : "Bilinmeyen hata");
      setStatus("error");
    }
  }).current;

  // Countdown
  useEffect(() => {
    if (status !== "waiting") return;
    const id = setInterval(() => {
      setSecondsLeft((s) => {
        if (s <= 1) {
          clearInterval(id);
          setStatus("expired");
          return 0;
        }
        return s - 1;
      });
    }, 1000);
    return () => clearInterval(id);
  }, [status]);

  // Polling
  useEffect(() => {
    if (status !== "waiting") return;
    const controller = new AbortController();
    abortRef.current = controller;
    let active = true;

    async function poll() {
      while (active && !controller.signal.aborted) {
        try {
          const data = await pollWebSession(
            sessionIdRef.current,
            controller.signal,
          );
          if (data && privKeyRef.current) {
            active = false;
            const { accessToken, deviceId } = sessionPollTokens(data);
            console.log("[QrAuth] Raw data from server:", {
              android_x25519_pub: data.android_x25519_pub,
              nonce: data.nonce,
              ciphertext: data.ciphertext,
              hasAccessToken: Boolean(accessToken),
            });
            if (!accessToken) {
              setErrorMsg("Oturum jetonu alınamadı (AccessToken eksik)");
              setStatus("error");
              return;
            }
            let transferKey: Uint8Array;
            let creds: ReturnType<typeof decryptCredentials>;
            try {
              transferKey = deriveTransferKey(
                privKeyRef.current,
                data.android_x25519_pub,
              );
              creds = decryptCredentials(
                transferKey,
                data.ciphertext,
                data.nonce,
              );
            } catch (decryptErr) {
              console.error("[QrAuth] Decryption failed:", decryptErr);
              setErrorMsg(
                decryptErr instanceof Error
                  ? decryptErr.message
                  : "Şifre çözme hatası",
              );
              setStatus("error");
              return;
            }
            console.log("[QrAuth] Decrypted credentials:", creds);
            // setAuth persists the full credential set to the encrypted vault.
            setAuth({
              accessToken,
              deviceId,
              shadeId: creds.shade_id,
              userId: creds.user_id,
              x25519PrivKeyHex: creds.x25519_priv,
              ed25519PrivKeyHex: creds.ed25519_priv,
            });
            setStatus("success");
            navigate("/chats", {
              state: {
                sessionId: sessionIdRef.current,
                transferKeyHex: bytesToHex(transferKey),
              },
            });
            return;
          }
        } catch (e) {
          if (controller.signal.aborted) return;
          setErrorMsg(e instanceof Error ? e.message : "Poll hatası");
          setStatus("error");
          return;
        }
        await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
      }
    }

    poll();
    return () => {
      active = false;
      controller.abort();
    };
  }, [status, navigate, setAuth]);

  useEffect(() => {
    void initSession();
  }, []);

  const minutes = Math.floor(secondsLeft / 60);
  const secs = secondsLeft % 60;
  const timerStr = `${minutes}:${secs.toString().padStart(2, "0")}`;
  const progress = (secondsLeft / QR_TTL_SECONDS) * 100;

  function handleRetry() {
    setStatus("loading");
    setErrorMsg("");
    setTimeout(() => void initSession(), 0);
  }

  return (
    <div className="flex flex-1 flex-col items-center justify-center bg-background px-4 py-12">
      {/* Brand */}
      <div className="mb-8 flex flex-col items-center gap-4">
        <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-violet-600 shadow-lg shadow-violet-500/25">
          <Shield className="h-7 w-7 text-white" />
        </div>
        <div className="text-center">
          <h1 className="text-[26px] font-semibold tracking-tight text-foreground">
            Shade Web
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Uçtan uca şifreli mesajlaşma
          </p>
        </div>
      </div>

      {/* QR Card */}
      <div className="w-full max-w-[320px] rounded-3xl border border-border bg-card shadow-2xl shadow-black/5 overflow-hidden">
        {/* QR area */}
        <div className="flex items-center justify-center p-8 pb-6">
          <div className="relative">
            {status === "waiting" && qrValue && <ScanCorners />}

            {status === "loading" && (
              <div className="flex h-52 w-52 items-center justify-center">
                <div className="h-8 w-8 animate-spin rounded-full border-[3px] border-border border-t-violet-500" />
              </div>
            )}

            {status === "waiting" && qrValue && (
              <div className="rounded-xl overflow-hidden p-2 bg-white">
                <QRCodeSVG
                  value={qrValue}
                  size={192}
                  level="M"
                  includeMargin={false}
                />
              </div>
            )}

            {status === "expired" && (
              <div className="flex h-52 w-52 flex-col items-center justify-center gap-4">
                <div className="flex h-14 w-14 items-center justify-center rounded-full bg-muted">
                  <RefreshCw className="h-6 w-6 text-muted-foreground" />
                </div>
                <p className="text-sm text-center text-muted-foreground leading-snug">
                  QR kodun süresi
                  <br />
                  doldu
                </p>
              </div>
            )}

            {status === "error" && (
              <div className="flex h-52 w-52 flex-col items-center justify-center gap-3 px-4 text-center">
                <div className="flex h-14 w-14 items-center justify-center rounded-full bg-red-500/10">
                  <span className="text-2xl">⚠️</span>
                </div>
                <p className="text-xs text-muted-foreground leading-snug">
                  {errorMsg}
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Timer bar */}
        {status === "waiting" && (
          <div className="px-8 pb-5">
            <div className="flex items-center gap-2.5">
              <div className="h-1 flex-1 overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-violet-500 transition-all duration-1000"
                  style={{ width: `${progress}%` }}
                />
              </div>
              <span className="text-xs tabular-nums text-muted-foreground w-7 text-right">
                {timerStr}
              </span>
            </div>
            <p className="mt-2 text-center text-[11px] text-muted-foreground/70">
              QR kod {timerStr} sonra geçersiz olacak
            </p>
          </div>
        )}

        {/* Retry button */}
        {(status === "expired" || status === "error") && (
          <div className="px-8 pb-7 flex justify-center">
            <button
              onClick={handleRetry}
              className="flex items-center gap-2 rounded-xl bg-violet-600 px-5 py-2.5 text-sm font-medium text-white hover:bg-violet-700 active:scale-95 transition-all"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Yeni QR Oluştur
            </button>
          </div>
        )}

        {/* Divider */}
        <div className="border-t border-border" />

        {/* Steps */}
        <div className="px-7 py-5 space-y-3.5">
          <Step n={1} text="Android'de Shade uygulamasını aç" />
          <Step n={2} text={'Ayarlar → "Web\'e Bağlan" seçeneğine dokun'} />
          <Step n={3} text="Kamerayı QR kodun üzerine tut" />
        </div>
      </div>

      <p className="mt-6 text-xs text-muted-foreground/60 text-center max-w-xs">
        Tüm veriler uçtan uca şifrelenir. Sunucu mesaj içeriklerine erişemez.
      </p>
    </div>
  );
}
