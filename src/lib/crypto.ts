// Client-side cryptography. All secrets are generated and used ONLY in the
// browser. The server receives hashes (identity) and ciphertext (content).

const ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // no 0/O/1/I/L — unambiguous
const enc = new TextEncoder();
const dec = new TextDecoder();

/** Generate a high-entropy access key / invite code, e.g. "K7M4Q-X2P9R-..." */
export function generateCode(groups = 8, groupLen = 5): string {
  const rand = new Uint32Array(groups * groupLen);
  crypto.getRandomValues(rand);
  const chars = Array.from(rand, (n) => ALPHABET[n % ALPHABET.length]);
  const out: string[] = [];
  for (let g = 0; g < groups; g++) out.push(chars.slice(g * groupLen, (g + 1) * groupLen).join(""));
  return out.join("-");
}

/** Normalize user-entered codes: uppercase, strip separators/spaces. */
export function normalizeCode(code: string): string {
  return code.toUpperCase().replace(/[^A-Z0-9]/g, "");
}

/** SHA-256 hex digest — the only form in which keys ever leave the client. */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(input));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

function b64encode(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function b64decode(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

/**
 * Derive the AES-256-GCM channel key from an invite code via HKDF-SHA-256.
 * Anyone who knows the invite code can derive the key; the server cannot,
 * because it only ever stores the code's hash.
 */
export async function deriveChannelKey(inviteCode: string): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey("raw", enc.encode(normalizeCode(inviteCode)), "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode("blackvault-channel-v1"), info: enc.encode("aes-256-gcm") },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptText(key: CryptoKey, plaintext: string): Promise<{ ciphertext: string; nonce: string }> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, enc.encode(plaintext));
  return { ciphertext: b64encode(ct), nonce: b64encode(nonce.buffer as ArrayBuffer) };
}

export async function decryptText(key: CryptoKey, ciphertext: string, nonce: string): Promise<string> {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64decode(nonce) as BufferSource },
    key,
    b64decode(ciphertext) as BufferSource,
  );
  return dec.decode(pt);
}
