// Shared types for the voice subsystem. Per PROTOCOL.md §1-§5.
// All byte sequences are Uint8Array. Strings (transcript labels,
// info labels) are UTF-8 encoded at the point of use.

export type ByteSeq = Uint8Array;

/** Long-term identity (per user). */
export interface IdentityKeyPair {
  ed25519: { publicKey: ByteSeq; secretKey: ByteSeq };
  x25519:  { publicKey: ByteSeq; secretKey: ByteSeq };
  mlkem:   { publicKey: ByteSeq; secretKey: ByteSeq };
}

export interface IdentityKeyPublic {
  ed25519: ByteSeq;
  x25519:  ByteSeq;
  mlkem:   ByteSeq;
}

/** Per-call ephemeral keys. */
export interface EphemeralKeyPair {
  x25519: { publicKey: ByteSeq; secretKey: ByteSeq };
  mlkem:  { publicKey: ByteSeq; secretKey: ByteSeq };
}

export interface EphemeralPublic {
  x25519: ByteSeq;
  mlkem:  ByteSeq;
}

/** Signaling message shapes. */
export interface CallOffer {
  v: 1;
  callId: string;            // 32 hex chars = 16 random bytes
  callerIdentity: IdentityKeyPublic;
  callerEphemeral: EphemeralPublic;
  signature: string;          // hex
  sdpOffer: string;           // base64 of gzipped SDP
}

export interface CallAnswer {
  v: 1;
  callId: string;
  calleeIdentity: IdentityKeyPublic;
  calleeEphemeral: EphemeralPublic;       // x25519 + mlkem (caller uses x25519, callee uses mlkem decapsulation)
  mlkemCiphertext: string;                // base64; callee's ML-KEM encapsulation to caller's ML-KEM pub
  signature: string;
  sdpAnswer: string;
}

export type CallHangupReason = "user" | "timeout" | "error" | "key-mismatch";

export interface CallHangup {
  v: 1;
  callId: string;
  reason: CallHangupReason;
}

/** SDP attribute required by the protocol. */
export const SDP_REQUIRED_ATTRIBUTES = {
  opusRtpMap: "opus/48000/2",
  opusFmtp: (bitrate: number) => `stereo=0; maxaveragebitrate=${bitrate}; usedtx=0; useinbandfec=1; cbr=1`,
  fingerprintHash: "sha-256",
} as const;

export const DEFAULT_OPUS_BITRATE_KBPS = 32;
export const DEFAULT_OPUS_FRAME_MS = 20;

/** Salt used in HKDF for the KEX master secret derivation. */
export const HKDF_SALT_KEX = "bv-voice-v1-kex-salt";
export const HKDF_INFO_KEX_MASTER = "bv-voice-v1-kex-master";
export const HKDF_INFO_CHAINING = "bv-voice-v1-chaining";
export const HKDF_INFO_ROOT = "bv-voice-v1-root";
export const HKDF_INFO_SRTP_KEY_CM = "bv-voice-v1-srtp-key-aes-cm-128";
export const HKDF_INFO_SRTP_SALT = "bv-voice-v1-srtp-salt";
export const HKDF_INFO_SRTP_KEY_GCM = "bv-voice-v1-srtp-key-aes-gcm-256";
export const HKDF_INFO_SRTP_SALT_GCM = "bv-voice-v1-srtp-salt-aes-gcm";
export const HKDF_INFO_RATCHET_ROOT = "bv-voice-v1-ratchet-root";
export const HKDF_INFO_SAFETY_SEED = "bv-voice-v1-safety-number";
export const HKDF_INFO_SAFETY_FINAL = "bv-voice-v1-safety-final";

/** Transcript context labels (per RFC 8789-style domain separation). */
export const TRANSCRIPT_PREFIX = "bv-voice-v1-transcript";
export const OFFER_SIGN_PREFIX = "bv-voice-v1-offer";
export const ANSWER_SIGN_PREFIX = "bv-voice-v1-answer";
export const COMPRESSED_SDP_TAG = "bv-voice-v1-sdp";
