// Per PROTOCOL.md §4: X25519 + ML-KEM-768 hybrid KEX.
// Uses @noble/curves for X25519 and Ed25519, @noble/post-quantum for ML-KEM-768.
// All secrets are zeroed after use (see zeroize()).

import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import {
  HKDF_INFO_KEX_MASTER,
  HKDF_SALT_KEX,
  TRANSCRIPT_PREFIX,
  OFFER_SIGN_PREFIX,
  ANSWER_SIGN_PREFIX,
  type IdentityKeyPair,
  type IdentityKeyPublic,
  type EphemeralKeyPair,
  type EphemeralPublic,
} from "./types";
import type { ByteSeq } from "./types";

// Re-export so other modules in api/voice/ don't have to import from types.ts.
export type { ByteSeq };

const enc = new TextEncoder();

/** Zeroize a Uint8Array. Best-effort; the JS engine may have copied it. */
export function zeroize(buf: ByteSeq | undefined | null): void {
  if (!buf) return;
  buf.fill(0);
}

/** Constant-time byte equality. */
export function ctEqual(a: ByteSeq, b: ByteSeq): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Random bytes from a CSPRNG. */
export function randomBytes(n: number): ByteSeq {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

/** Hex encode (lowercase, no prefix). */
export function toHex(buf: ByteSeq): string {
  let s = "";
  for (let i = 0; i < buf.length; i++) s += buf[i].toString(16).padStart(2, "0");
  return s;
}

/** Hex decode. Throws on invalid input. */
export function fromHex(s: string): ByteSeq {
  if (s.length % 2 !== 0) throw new Error("hex: odd length");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Base64 (standard, with padding) of a byte sequence. */
export function toB64(buf: ByteSeq): string {
  let s = "";
  for (let i = 0; i < buf.length; i++) s += String.fromCharCode(buf[i]);
  return btoa(s);
}

/** Base64 decode. Throws on invalid input. */
export function fromB64(s: string): ByteSeq {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Concatenate multiple byte sequences. */
export function concat(...parts: ByteSeq[]): ByteSeq {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

/** SHA-256 of bytes. */
export function sha256Bytes(...parts: ByteSeq[]): ByteSeq {
  return sha256(concat(...parts));
}

/** HKDF-SHA-256, output a single block of `outLen` bytes. */
export function hkdfSha256(ikm: ByteSeq, salt: ByteSeq, info: ByteSeq, outLen: number): ByteSeq {
  return hkdf(sha256, ikm, salt, info, outLen);
}

/** Generate a fresh identity keypair. */
export function generateIdentity(): IdentityKeyPair {
  const ed = ed25519.keygen();
  const x = x25519.keygen();
  const m = ml_kem768.keygen();
  return {
    ed25519: { publicKey: ed.publicKey, secretKey: ed.secretKey },
    x25519:  { publicKey: x.publicKey, secretKey: x.secretKey },
    mlkem:   { publicKey: m.publicKey, secretKey: m.secretKey },
  };
}

/** Generate a fresh per-call ephemeral keypair. */
export function generateEphemeral(): EphemeralKeyPair {
  const x = x25519.keygen();
  const m = ml_kem768.keygen();
  return {
    x25519: { publicKey: x.publicKey, secretKey: x.secretKey },
    mlkem:  { publicKey: m.publicKey, secretKey: m.secretKey },
  };
}

/** Encode an identity public bundle in the canonical order used everywhere. */
export function encodeIdentityPublic(id: IdentityKeyPublic): ByteSeq {
  return concat(id.ed25519, id.x25519, id.mlkem);
}

/** Compute the transcript hash (per §4.2). */
export function computeTranscriptHash(input: {
  callId: ByteSeq;
  callerIdentity: IdentityKeyPublic;
  calleeIdentity: IdentityKeyPublic;
  callerEphemeral: EphemeralPublic;
  calleeEphemeralPublic: ByteSeq;        // callee's X25519 ephemeral public
  mlkemCiphertext: ByteSeq;              // callee's ML-KEM encapsulation to caller's pub
}): ByteSeq {
  const bytes = concat(
    enc.encode(TRANSCRIPT_PREFIX),
    input.callId,
    input.callerIdentity.x25519,
    input.callerIdentity.mlkem,
    input.calleeIdentity.x25519,
    input.calleeIdentity.mlkem,
    input.callerEphemeral.x25519,
    input.callerEphemeral.mlkem,
    input.calleeEphemeralPublic,
    input.mlkemCiphertext,
  );
  return sha256Bytes(bytes);
}

/**
 * ML-KEM encapsulation by the callee against the caller's ephemeral public key.
 * Returns the 1088-byte ciphertext and a 32-byte shared secret.
 */
export function kemEncapsulate(mlkemPub: ByteSeq): { ciphertext: ByteSeq; sharedSecret: ByteSeq } {
  const r = ml_kem768.encapsulate(mlkemPub);
  return { ciphertext: r.cipherText, sharedSecret: r.sharedSecret };
}

/**
 * ML-KEM decapsulation by the caller using its own ML-KEM private key.
 * Returns the 32-byte shared secret.
 */
export function kemDecapsulate(mlkemPriv: ByteSeq, ciphertext: ByteSeq): ByteSeq {
  return ml_kem768.decapsulate(ciphertext, mlkemPriv);
}

/**
 * X25519 ECDH. Each side uses its own ephemeral private with the
 * other side's ephemeral public.
 */
export function x25519Shared(myPriv: ByteSeq, theirPub: ByteSeq): ByteSeq {
  return x25519.getSharedSecret(myPriv, theirPub);
}

/**
 * Combine X25519 + ML-KEM shared secrets via HKDF-SHA-256. Per §4.2.
 * Both sides must produce the same `kexSecret` (and `transcriptHash`).
 *
 * The `kexSecret` is returned alongside the transcript hash so the
 * caller can derive the safety number and key schedule.
 */
export function deriveKexSecret(input: {
  x25519Shared: ByteSeq;
  mlkemShared: ByteSeq;
  transcriptHash: ByteSeq;
}): ByteSeq {
  const ikm = concat(input.x25519Shared, input.mlkemShared);
  const salt = sha256Bytes(enc.encode(HKDF_SALT_KEX));
  const info = concat(enc.encode(HKDF_INFO_KEX_MASTER), input.transcriptHash);
  return hkdfSha256(ikm, salt, info, 32);
}

/** Ed25519 sign/verify for the SDP binding. */
export function ed25519Sign(edPriv: ByteSeq, msg: ByteSeq): ByteSeq {
  return ed25519.sign(msg, edPriv);
}

export function ed25519Verify(edPub: ByteSeq, msg: ByteSeq, sig: ByteSeq): boolean {
  return ed25519.verify(sig, msg, edPub);
}

/**
 * Compute the offer signature input bytes (per §6.3).
 * Both sides use the same construction so the signature is verifiable.
 */
export function offerSignatureInput(input: {
  callId: ByteSeq;
  identity: IdentityKeyPublic;
  ephemeral: EphemeralPublic;
  sdpCompressed: ByteSeq;
}): ByteSeq {
  return concat(
    enc.encode(OFFER_SIGN_PREFIX),
    input.callId,
    input.identity.x25519,
    input.identity.mlkem,
    input.ephemeral.x25519,
    input.ephemeral.mlkem,
    input.sdpCompressed,
  );
}

/** Answer signature input (per §6.3, answer side). */
export function answerSignatureInput(input: {
  callId: ByteSeq;
  identity: IdentityKeyPublic;
  ephemeralX25519: ByteSeq;     // callee's x25519 ephemeral pub
  mlkemCiphertext: ByteSeq;     // encapsulated to caller's pub
  sdpCompressed: ByteSeq;
}): ByteSeq {
  return concat(
    enc.encode(ANSWER_SIGN_PREFIX),
    input.callId,
    input.identity.x25519,
    input.identity.mlkem,
    input.ephemeralX25519,
    input.mlkemCiphertext,
    input.sdpCompressed,
  );
}
