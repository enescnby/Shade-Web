import { API_URL } from "../env";
import { decryptImageAttachment } from "../crypto/messageCrypto";

const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Matches Android `ImageMessageContent` JSON inside decrypted IMAGE messages. */
export interface ImageMessageContent {
  imageId: string;
  thumbnailBase64: string;
  imageNonceHex: string;
  width: number;
  height: number;
  sizeBytes: number;
}

/**
 * Konuyla (DM’deki karşı tarafın) X25519 public + bizim priv ile tam boy foto şifresi çözülür.
 */
export interface MediaDecryptHint {
  imageNonceHex: string;
  x25519PrivKeyHex: string;
  peerEncryptionPubKeyHex: string;
}

function sniffImageMimeFromBase64Prefix(b64: string): string {
  const slice = b64.slice(0, 48);
  const pad = slice.length % 4 === 0 ? "" : "=".repeat(4 - (slice.length % 4));
  let binary: string;
  try {
    binary = atob(slice.replace(/-/g, "+").replace(/_/g, "/") + pad);
  } catch {
    return "image/jpeg";
  }
  const u = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) u[i] = binary.charCodeAt(i);
  if (u[0] === 0x89 && u[1] === 0x50 && u[2] === 0x4e && u[3] === 0x47) return "image/png";
  if (u[0] === 0xff && u[1] === 0xd8 && u[2] === 0xff) return "image/jpeg";
  if (u[0] === 0x47 && u[1] === 0x49 && u[2] === 0x46) return "image/gif";
  if (u[0] === 0x52 && u[1] === 0x49 && u[2] === 0x46 && u[3] === 0x46) return "image/webp";
  return "image/jpeg";
}

export function thumbnailBase64ToDataUrl(thumbnailBase64: string): string {
  const normalized = thumbnailBase64.replace(/\s/g, "").replace(/-/g, "+").replace(/_/g, "/");
  const mime = sniffImageMimeFromBase64Prefix(normalized);
  return `data:${mime};base64,${normalized}`;
}

export function parseImageMessageContent(content: string): ImageMessageContent | null {
  try {
    const o = JSON.parse(content.trim()) as Record<string, unknown>;
    const imageId = o.imageId;
    const thumbnailBase64 = o.thumbnailBase64;
    if (typeof imageId !== "string" || !UUID_RE.test(imageId.trim())) return null;
    if (typeof thumbnailBase64 !== "string" || thumbnailBase64.length < 24) return null;
    return {
      imageId: imageId.trim(),
      thumbnailBase64,
      imageNonceHex: typeof o.imageNonceHex === "string" ? o.imageNonceHex : "",
      width:
        typeof o.width === "number" && Number.isFinite(o.width)
          ? Math.max(0, Math.floor(o.width))
          : 0,
      height:
        typeof o.height === "number" && Number.isFinite(o.height)
          ? Math.max(0, Math.floor(o.height))
          : 0,
      sizeBytes:
        typeof o.sizeBytes === "number" && Number.isFinite(o.sizeBytes)
          ? Math.max(0, Math.floor(o.sizeBytes))
          : 0,
    };
  } catch {
    return null;
  }
}

/** Legacy: plaintext was only the UUID, or `{ "imageId": "<uuid>" }` without thumbnails. */
export function extractMediaImageId(content: string): string | null {
  const trimmed = content.trim();
  if (UUID_RE.test(trimmed)) return trimmed;
  try {
    const o = JSON.parse(trimmed) as { imageId?: string };
    if (typeof o.imageId === "string") {
      const id = o.imageId.trim();
      return UUID_RE.test(id) ? id : null;
    }
  } catch {
    /* not JSON */
  }
  return null;
}

/** Plaintext JSON for `encryptMessage`, aligned with Android `ImageMessageContent`. */
export async function buildImageMessagePlaintext(
  file: File,
  imageId: string,
  imageNonceHex: string,
): Promise<string> {
  const bitmap = await createImageBitmap(file);
  const width = bitmap.width;
  const height = bitmap.height;
  const maxEdge = 320;
  const scale = Math.min(1, maxEdge / Math.max(width, height));
  const tw = Math.round(width * scale);
  const th = Math.round(height * scale);
  const canvas = document.createElement("canvas");
  canvas.width = tw;
  canvas.height = th;
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    bitmap.close();
    throw new Error("canvas");
  }
  ctx.drawImage(bitmap, 0, 0, tw, th);
  bitmap.close();
  const dataUrl = canvas.toDataURL("image/jpeg", 0.72);
  const thumbnailBase64 = dataUrl.slice(dataUrl.indexOf(",") + 1);
  const payload: ImageMessageContent = {
    imageId,
    thumbnailBase64,
    imageNonceHex,
    width,
    height,
    sizeBytes: file.size,
  };
  return JSON.stringify(payload);
}

/** Tek bir `ArrayBuffer` üzerinde Uint8 — `Blob` / strict TS uyumu */
type BinBytes = Uint8Array<ArrayBuffer>;

function cloneBytes(slice: Uint8Array): BinBytes {
  const out = new Uint8Array(slice.byteLength);
  out.set(slice);
  return out;
}

/** BOM/boşluk sıyırma sonrası yeni buffer (subarray ile paylaşım + ArrayBufferLike hatasını önler) */
function normalizeLeadingBytes(bytes: Uint8Array): BinBytes {
  let i = 0;
  const len = bytes.length;
  if (len >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) i = 3;
  while (
    i < len &&
    (bytes[i] === 0x09 || bytes[i] === 0x0a || bytes[i] === 0x0d || bytes[i] === 0x20)
  ) {
    i++;
  }
  return cloneBytes(bytes.subarray(i));
}

function sniffImageMimeFromBuffer(bytes: Uint8Array): string | null {
  if (bytes.length < 12) return null;
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return "image/png";
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "image/jpeg";
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) return "image/gif";
  /* RIFF....WEBP */
  if (
    bytes[0] === 0x52 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x46 &&
    bytes[8] === 0x57 &&
    bytes[9] === 0x45 &&
    bytes[10] === 0x42 &&
    bytes[11] === 0x50
  ) {
    return "image/webp";
  }
  /* ISO BMFF — offset 4 = "ftyp" (AVIF / HEIC vb.) */
  if (bytes[4] === 0x66 && bytes[5] === 0x74 && bytes[6] === 0x79 && bytes[7] === 0x70) {
    const brand = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11]);
    if (brand === "avif" || brand === "avis") return "image/avif";
    if (
      brand === "heic" ||
      brand === "heix" ||
      brand === "hevc" ||
      brand === "hevx" ||
      brand === "mif1" ||
      brand === "msf1"
    ) {
      return "image/heic";
    }
  }
  return null;
}

function decodeBase64Payload(b64: string): Uint8Array | null {
  try {
    let clean = b64.replace(/\s/g, "").replace(/-/g, "+").replace(/_/g, "/");
    const pad = clean.length % 4 === 0 ? "" : "=".repeat(4 - (clean.length % 4));
    clean += pad;
    const bin = atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function decodeMaybeNestedBase64(s: string): Uint8Array | null {
  const t = s.trim();
  const compact = t.replace(/\s/g, "");
  const dm = /^data:image\/[^;]+;base64,(.+)$/i.exec(compact);
  if (dm) return decodeBase64Payload(dm[1]);
  return decodeBase64Payload(compact);
}

/**
 * Sunucu bazen ham binary yerine JSON / düz base64 / data-URL döndürür;
 * octet-stream ile gelince <img> kırılıyor — burada gerçek pikselleri çıkarırız.
 */
function tryDecodeWrappedImage(ab: ArrayBuffer): { bytes: BinBytes; via: string } {
  let raw = normalizeLeadingBytes(new Uint8Array(ab));
  if (sniffImageMimeFromBuffer(raw)) return { bytes: raw, via: "binary" };

  const fullStr = new TextDecoder("utf-8", { fatal: false }).decode(raw).trim();

  const dataUrl = /^data:image\/[^;]+;base64,(.+)$/is.exec(fullStr.replace(/\s/g, ""));
  if (dataUrl) {
    const dec = decodeBase64Payload(dataUrl[1]);
    if (dec) {
      const n = normalizeLeadingBytes(dec);
      if (sniffImageMimeFromBuffer(n)) return { bytes: n, via: "data-url-body" };
    }
  }

  if (fullStr.startsWith("{")) {
    try {
      const j = JSON.parse(fullStr) as Record<string, unknown>;
      for (const k of ["data", "base64", "bytes", "image", "content", "payload", "body"]) {
        const v = j[k];
        if (typeof v !== "string" || v.length < 40) continue;
        const dec = decodeMaybeNestedBase64(v);
        if (dec) {
          const n = normalizeLeadingBytes(dec);
          if (sniffImageMimeFromBuffer(n)) return { bytes: n, via: `json.${k}` };
        }
      }
    } catch {
      /* ignore */
    }
  }

  const compact = fullStr.replace(/\s/g, "");
  if (/^[A-Za-z0-9+/]+=*$/.test(compact) && compact.length >= 80 && compact.length % 4 === 0) {
    const dec = decodeBase64Payload(compact);
    if (dec) {
      const n = normalizeLeadingBytes(dec);
      if (sniffImageMimeFromBuffer(n)) return { bytes: n, via: "plain-base64-body" };
    }
  }

  /* Bazı sunucular JPEG/PNG/WebP öncesine birkaç bayt ekler; ilk 8 KB içinde imza ara */
  const scanMax = Math.min(raw.length - 12, 8192);
  for (let i = 1; i <= scanMax; i++) {
    const slice = raw.subarray(i);
    if (sniffImageMimeFromBuffer(slice))
      return { bytes: cloneBytes(slice), via: `binary-skip-prefix-${i}` };
  }

  return { bytes: raw, via: "binary-no-signature" };
}

function extensionForMime(mime: string): string {
  if (mime.includes("png")) return "png";
  if (mime.includes("webp")) return "webp";
  if (mime.includes("gif")) return "gif";
  if (mime.includes("avif")) return "avif";
  if (mime.includes("heic") || mime.includes("heif")) return "heic";
  return "jpg";
}

/** Dosya adı gövdesi: Shade-Image-YYYY-MM-DD-HH-mm-ss */
export function buildShadeImageDownloadBasename(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `Shade-Image-${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}-${p(d.getHours())}-${p(d.getMinutes())}-${p(d.getSeconds())}`;
}

export function shadeImageDownloadFilename(mime: string): string {
  return `${buildShadeImageDownloadBasename()}.${extensionForMime(mime)}`;
}

/** Önbelleğe alınmış blob ile tekrar indir çağrısı yapmadan dosya kaydet. */
export function downloadBlobAsFile(blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = shadeImageDownloadFilename(blob.type);
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.setTimeout(() => URL.revokeObjectURL(url), 180_000);
}

export async function downloadMediaImage(
  imageId: string,
  accessToken: string,
  decryptHint?: MediaDecryptHint | null,
): Promise<void> {
  const blob = await fetchMediaBlob(imageId, accessToken, decryptHint);
  downloadBlobAsFile(blob);
}

const MEDIA_LOG = "[shade-media]";

/** Sunucu `imageId`, `image_id`, `data` içi vb. döndürebilir. */
function extractImageIdFromUploadResponse(body: unknown): string | null {
  if (typeof body === "string") {
    const t = body.trim();
    return UUID_RE.test(t) ? t : null;
  }
  if (!body || typeof body !== "object") return null;

  function pick(o: Record<string, unknown>): string | null {
    for (const k of ["imageId", "image_id", "ImageId", "uuid", "id"]) {
      const v = o[k];
      if (typeof v === "string" && UUID_RE.test(v.trim())) return v.trim();
    }
    return null;
  }

  const o = body as Record<string, unknown>;
  const direct = pick(o);
  if (direct) return direct;

  for (const wrap of ["data", "result", "payload"]) {
    const inner = o[wrap];
    if (inner && typeof inner === "object") {
      const id = pick(inner as Record<string, unknown>);
      if (id) return id;
    }
  }
  return null;
}

/** Ham veya şifrelenmiş gövdeyi yükler (`image` alanı). */
export async function uploadMediaImage(blob: Blob, accessToken: string, filename: string): Promise<string> {
  if (blob.size > MAX_UPLOAD_BYTES) {
    throw new Error("Görsel en fazla 10 MB olabilir");
  }
  if (!accessToken?.trim()) {
    throw new Error("Kimlik doğrulama eksik — yeniden oturum aç.");
  }

  const form = new FormData();
  /* Üçüncü argüman: bazı sunucular boş dosya adını reddeder */
  form.append("image", blob, filename || "image.bin");

  const url = `${API_URL}/api/v1/media/upload`;
  console.info(`${MEDIA_LOG} upload`, {
    url,
    bytes: blob.size,
    type: blob.type || "(unknown)",
    filename: filename || "image.bin",
    hasAuth: Boolean(accessToken.length),
  });

  const res = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}` },
    body: form,
  });

  if (!res.ok) {
    let detail = "";
    try {
      detail = (await res.clone().text()).trim().slice(0, 600);
    } catch {
      detail = "";
    }
    console.warn(`${MEDIA_LOG} upload HTTP ${res.status}`, detail || "(gövde yok)");
    throw new Error(
      detail
        ? `Yükleme başarısız (${res.status}): ${detail}`
        : `Yükleme başarısız: HTTP ${res.status}`,
    );
  }

  const rawText = (await res.text()).trim();
  let parsed: unknown = rawText;
  if (rawText) {
    try {
      parsed = JSON.parse(rawText) as unknown;
    } catch {
      parsed = rawText;
    }
  }

  const imageId = extractImageIdFromUploadResponse(parsed);
  if (!imageId) {
    console.warn(`${MEDIA_LOG} upload yanıtında UUID yok`, parsed);
    throw new Error("Sunucu yanıtında imageId bulunamadı (beklenen: uuid)");
  }

  console.info(`${MEDIA_LOG} upload ok`, { imageId });
  return imageId;
}

function hexPreview(bytes: Uint8Array, max = 24): string {
  const n = Math.min(max, bytes.length);
  let s = "";
  for (let i = 0; i < n; i++) s += bytes[i].toString(16).padStart(2, "0") + " ";
  return s.trim();
}

export async function fetchMediaBlob(
  imageId: string,
  accessToken: string,
  decryptHint?: MediaDecryptHint | null,
): Promise<Blob> {
  const path = `/api/v1/media/${encodeURIComponent(imageId)}`;
  const url = `${API_URL}${path}`;
  console.info(`${MEDIA_LOG} request`, {
    method: "GET",
    url,
    imageId,
    hasAuthToken: Boolean(accessToken?.length),
  });

  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  const contentType = res.headers.get("Content-Type");
  const contentLength = res.headers.get("Content-Length");

  console.info(`${MEDIA_LOG} response meta`, {
    status: res.status,
    statusText: res.statusText,
    ok: res.ok,
    contentType,
    contentLength,
    contentDisposition: res.headers.get("Content-Disposition"),
  });

  if (!res.ok) {
    const ct = contentType ?? "";
    let errorPreview = "";
    try {
      const clone = res.clone();
      if (ct.includes("json") || ct.includes("text")) {
        errorPreview = (await clone.text()).slice(0, 800);
      } else {
        const b = await clone.arrayBuffer();
        errorPreview = `binary ${b.byteLength} bytes, head: ${hexPreview(new Uint8Array(b), 32)}`;
      }
    } catch {
      errorPreview = "(okunamadı)";
    }
    console.warn(`${MEDIA_LOG} error body preview`, errorPreview);
    throw new Error(`Medya alınamadı: ${res.status}`);
  }

  const buf = await res.arrayBuffer();

  const decryptNonce = decryptHint?.imageNonceHex?.trim();
  if (decryptNonce && decryptHint?.x25519PrivKeyHex && decryptHint.peerEncryptionPubKeyHex) {
    const rawCt = new Uint8Array(buf);
    const decrypted = decryptImageAttachment(
      rawCt,
      decryptHint.imageNonceHex,
      decryptHint.x25519PrivKeyHex,
      decryptHint.peerEncryptionPubKeyHex,
    );
    const decMime = decrypted ? sniffImageMimeFromBuffer(decrypted) : null;
    if (decrypted && decMime) {
      console.info(`${MEDIA_LOG} chaCha çözümü başarılı (ham gövdeden)`, {
        sniffedMime: decMime,
        byteLength: buf.byteLength,
        plainLength: decrypted.byteLength,
      });
      return new Blob([decrypted], { type: decMime });
    }
  }

  const unpacked = tryDecodeWrappedImage(buf);
  const sniffed = sniffImageMimeFromBuffer(unpacked.bytes);

  const hasDecryptHint = Boolean(
    decryptNonce &&
      decryptHint?.x25519PrivKeyHex &&
      decryptHint?.peerEncryptionPubKeyHex,
  );

  /** Ham gövdede çıkmadıysa unwrap sonrasında tekrar dene */
  let bodyForBlob: BinBytes = unpacked.bytes;
  let mime: string | null = sniffed;
  if (!mime && !hasDecryptHint) {
    const h = contentType?.split(";")[0]?.trim();
    if (h && h.startsWith("image/")) mime = h;
  }

  if (!sniffed && hasDecryptHint) {
    const decrypted = decryptImageAttachment(
      unpacked.bytes,
      decryptHint!.imageNonceHex,
      decryptHint!.x25519PrivKeyHex,
      decryptHint!.peerEncryptionPubKeyHex,
    );
    const decMime = decrypted ? sniffImageMimeFromBuffer(decrypted) : null;
    if (decrypted && decMime) {
      bodyForBlob = decrypted;
      mime = decMime;
      console.info(`${MEDIA_LOG} chaCha çözümü başarılı (unwrap sonrası)`, {
        unpackVia: unpacked.via,
        sniffedMime: decMime,
        plainLength: decrypted.byteLength,
      });
    }
  }

  if (!mime) {
    const h = contentType?.split(";")[0]?.trim();
    if (h && h.startsWith("image/")) mime = h;
  }

  if (!mime) {
    console.warn(`${MEDIA_LOG} tanınmayan görsel formatı (tarayıcıda açılamayabilir)`, {
      hasDecryptHint,
      decryptTriedPoly1305: Boolean(decryptNonce),
      unpackVia: unpacked.via,
      headHex: hexPreview(unpacked.bytes, 24),
      asciiHead: new TextDecoder("utf-8", { fatal: false }).decode(unpacked.bytes.slice(0, 80)),
    });
    mime = "application/octet-stream";
  }

  console.info(`${MEDIA_LOG} response body`, {
    byteLength: buf.byteLength,
    unpackedByteLength: unpacked.bytes.byteLength,
    unpackVia: unpacked.via,
    sniffedMime: mime,
    declaredContentType: contentType,
    headHex: hexPreview(bodyForBlob, 16),
  });

  return new Blob([bodyForBlob], { type: mime });
}
