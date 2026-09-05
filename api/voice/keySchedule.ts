// Per PROTOCOL.md §5: derive the SRTP keys, ratchet root, and safety
// number seed from the KEX shared secret and transcript hash. All
// derivations are HKDF-SHA-256 with distinct info labels so the keys
// occupy separate key spaces.

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concat, type ByteSeq } from "./kex";
import {
  HKDF_INFO_CHAINING,
  HKDF_INFO_ROOT,
  HKDF_INFO_SRTP_KEY_CM,
  HKDF_INFO_SRTP_SALT,
  HKDF_INFO_SRTP_KEY_GCM,
  HKDF_INFO_SRTP_SALT_GCM,
  HKDF_INFO_RATCHET_ROOT,
  HKDF_INFO_SAFETY_SEED,
  HKDF_INFO_SAFETY_FINAL,
} from "./types";

const enc = new TextEncoder();
const ZERO_SALT = new Uint8Array(32);

function derive(outLen: number, ikm: ByteSeq, salt: ByteSeq, info: string | ByteSeq): ByteSeq {
  const infoBytes = typeof info === "string" ? enc.encode(info) : info;
  return hkdf(sha256, ikm, salt, infoBytes, outLen);
}

export interface KeySchedule {
  kexChainingKey: ByteSeq;   // 32
  rootKey: ByteSeq;          // 32
  srtpMasterKey: ByteSeq;     // 16 (AES-CM-128) — for the default voice SRTP session
  srtpMasterSalt: ByteSeq;    // 14 (RFC 3711 default for AES-CM-128)
  srtpGcmKey: ByteSeq;        // 32 (AES-256-GCM) — for the optional cipher
  srtpGcmSalt: ByteSeq;       // 12
  ratchetRoot: ByteSeq;       // 32 (reserved; not used in v1)
  safetyNumberSeed: ByteSeq;  // 32
}

/**
 * Derive the full key schedule from the KEX shared secret and the
 * transcript hash. Both sides must produce the same output.
 */
export function deriveKeySchedule(kexSecret: ByteSeq, transcriptHash: ByteSeq): KeySchedule {
  const kexChainingKey = derive(32, kexSecret, transcriptHash, HKDF_INFO_CHAINING);
  const rootKey = derive(32, kexChainingKey, ZERO_SALT, HKDF_INFO_ROOT);

  const srtpMasterKey = derive(16, rootKey, ZERO_SALT, HKDF_INFO_SRTP_KEY_CM);
  const srtpMasterSaltRaw = derive(32, rootKey, ZERO_SALT, HKDF_INFO_SRTP_SALT);
  // RFC 3711 §4.1.1: the master salt is 14 bytes for AES-CM-128.
  const srtpMasterSalt = srtpMasterSaltRaw.slice(0, 14);

  const srtpGcmKey = derive(32, rootKey, ZERO_SALT, HKDF_INFO_SRTP_KEY_GCM);
  const srtpGcmSaltRaw = derive(32, rootKey, ZERO_SALT, HKDF_INFO_SRTP_SALT_GCM);
  // RFC 7714 §5: the GCM salt is 12 bytes.
  const srtpGcmSalt = srtpGcmSaltRaw.slice(0, 12);

  const ratchetRoot = derive(32, rootKey, ZERO_SALT, HKDF_INFO_RATCHET_ROOT);

  const safetyNumberSeed = derive(32, rootKey, transcriptHash, HKDF_INFO_SAFETY_SEED);

  return {
    kexChainingKey,
    rootKey,
    srtpMasterKey,
    srtpMasterSalt,
    srtpGcmKey,
    srtpGcmSalt,
    ratchetRoot,
    safetyNumberSeed,
  };
}

/**
 * Compute the final 32-byte safety number digest. Per §8.
 *
 * Inputs:
 *  - callerIdentity: caller's long-term public triple
 *  - calleeIdentity: callee's long-term public triple
 *  - safetyNumberSeed: from the key schedule
 */
export function computeSafetyNumberDigest(input: {
  callerIdentity: { x25519: ByteSeq; mlkem: ByteSeq };
  calleeIdentity: { x25519: ByteSeq; mlkem: ByteSeq };
  safetyNumberSeed: ByteSeq;
}): ByteSeq {
  const bytes = concat(
    enc.encode(HKDF_INFO_SAFETY_FINAL),
    input.callerIdentity.x25519,
    input.callerIdentity.mlkem,
    input.calleeIdentity.x25519,
    input.calleeIdentity.mlkem,
    input.safetyNumberSeed,
  );
  return sha256(bytes);
}
