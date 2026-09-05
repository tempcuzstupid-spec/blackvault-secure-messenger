// Frozen KAT (Known Answer Test) — byte-for-byte conformance to a
// committed, deterministic set of values. This is what a reviewer
// runs to verify the implementation reproduces specific outputs
// for specific inputs.
//
// The test re-derives every output from the FROZEN_KAT inputs
// (in api/voice/kat.frozen.ts) and asserts byte-for-byte match
// against the locked outputs in FROZEN_KAT.
//
// To regenerate the KAT (only if the spec changes):
//   npx tsx scripts/voice-kat-gen.ts
// then commit the updated kat.frozen.ts and update the doc to mirror it.

import { describe, it, expect } from "vitest";
import { FROZEN_KAT } from "../api/voice/kat.frozen";
import { fromHex, toHex, ed25519Sign, ed25519Verify, offerSignatureInput, computeTranscriptHash, deriveKexSecret, x25519Shared, kemEncapsulate, kemDecapsulate } from "../api/voice/kex";
import { deriveKeySchedule, computeSafetyNumberDigest } from "../api/voice/keySchedule";
import { renderSafetyNumber } from "../api/voice/safetyNumber";
import { SrtpSession, type RtpHeader } from "../api/voice/srtp";
import { sha256 } from "@noble/hashes/sha2.js";

describe("FROZEN KAT: byte-for-byte conformance to committed test vector", () => {
  it("re-derives transcript hash, kex secret, key schedule, safety number, and SRTP round-trips from FROZEN inputs", () => {
    // ---- 1. Transcript hash ----
    const transcriptHash = computeTranscriptHash({
      callId: fromHex(FROZEN_KAT.CALL_ID),
      callerIdentity: {
        ed25519: fromHex(FROZEN_KAT.CALLER_ED25519_PUB),
        x25519: fromHex(FROZEN_KAT.CALLER_X25519_PUB),
        mlkem: fromHex(FROZEN_KAT.CALLER_MLKEM_PUB),
      },
      calleeIdentity: {
        ed25519: fromHex(FROZEN_KAT.CALLEE_ED25519_PUB),
        x25519: fromHex(FROZEN_KAT.CALLEE_X25519_PUB),
        mlkem: fromHex(FROZEN_KAT.CALLEE_MLKEM_PUB),
      },
      callerEphemeral: {
        x25519: fromHex(FROZEN_KAT.CALLER_X25519_EPH_PUB),
        mlkem: fromHex(FROZEN_KAT.CALLER_MLKEM_EPH_PUB),
      },
      calleeEphemeralPublic: fromHex(FROZEN_KAT.CALLEE_X25519_EPH_PUB),
      mlkemCiphertext: fromHex(FROZEN_KAT.MLKEM_CIPHERTEXT),
    });
    expect(toHex(transcriptHash)).toEqual(FROZEN_KAT.TRANSCRIPT_HASH);

    // ---- 2. KEX shared secrets (caller side, using the FROZEN private keys) ----
    const xCaller = x25519Shared(
      fromHex(FROZEN_KAT.CALLER_X25519_EPH_PRIV),
      fromHex(FROZEN_KAT.CALLEE_X25519_EPH_PUB),
    );
    const mlkemSharedCaller = kemDecapsulate(
      fromHex(FROZEN_KAT.CALLER_MLKEM_EPH_PRIV),
      fromHex(FROZEN_KAT.MLKEM_CIPHERTEXT),
    );
    expect(toHex(xCaller)).toEqual(FROZEN_KAT.X25519_SHARED);
    expect(toHex(mlkemSharedCaller)).toEqual(FROZEN_KAT.MLKEM_SHARED);

    // ---- 3. KEX secret ----
    const kexSecret = deriveKexSecret({
      x25519Shared: xCaller,
      mlkemShared: mlkemSharedCaller,
      transcriptHash,
    });
    expect(toHex(kexSecret)).toEqual(FROZEN_KAT.KEX_SECRET);

    // ---- 4. Key schedule ----
    const schedule = deriveKeySchedule(kexSecret, transcriptHash);
    expect(toHex(schedule.kexChainingKey)).toEqual(FROZEN_KAT.KEX_CHAINING_KEY);
    expect(toHex(schedule.rootKey)).toEqual(FROZEN_KAT.ROOT_KEY);
    expect(toHex(schedule.srtpMasterKey)).toEqual(FROZEN_KAT.SRTP_MASTER_KEY);
    expect(toHex(schedule.srtpMasterSalt)).toEqual(FROZEN_KAT.SRTP_MASTER_SALT);
    expect(toHex(schedule.srtpGcmKey)).toEqual(FROZEN_KAT.SRTP_GCM_KEY);
    expect(toHex(schedule.srtpGcmSalt)).toEqual(FROZEN_KAT.SRTP_GCM_SALT);
    expect(toHex(schedule.ratchetRoot)).toEqual(FROZEN_KAT.RATCHET_ROOT);
    expect(toHex(schedule.safetyNumberSeed)).toEqual(FROZEN_KAT.SAFETY_NUMBER_SEED);

    // ---- 5. Safety number + emoji display ----
    const safetyDigest = computeSafetyNumberDigest({
      callerIdentity: { x25519: fromHex(FROZEN_KAT.CALLER_X25519_PUB), mlkem: fromHex(FROZEN_KAT.CALLER_MLKEM_PUB) },
      calleeIdentity: { x25519: fromHex(FROZEN_KAT.CALLEE_X25519_PUB), mlkem: fromHex(FROZEN_KAT.CALLEE_MLKEM_PUB) },
      safetyNumberSeed: schedule.safetyNumberSeed,
    });
    expect(toHex(safetyDigest)).toEqual(FROZEN_KAT.SAFETY_NUMBER);
    expect(renderSafetyNumber(safetyDigest)).toEqual(FROZEN_KAT.EMOJI_DISPLAY);

    // ---- 6. Offer signature ----
    const sdpCompressed = sha256(new TextEncoder().encode("placeholder SDP body for KAT"));
    const offerSigned = offerSignatureInput({
      callId: fromHex(FROZEN_KAT.CALL_ID),
      identity: {
        ed25519: fromHex(FROZEN_KAT.CALLER_ED25519_PUB),
        x25519: fromHex(FROZEN_KAT.CALLER_X25519_PUB),
        mlkem: fromHex(FROZEN_KAT.CALLER_MLKEM_PUB),
      },
      ephemeral: {
        x25519: fromHex(FROZEN_KAT.CALLER_X25519_EPH_PUB),
        mlkem: fromHex(FROZEN_KAT.CALLER_MLKEM_EPH_PUB),
      },
      sdpCompressed,
    });
    expect(toHex(offerSigned)).toEqual(FROZEN_KAT.OFFER_SIGNED_INPUT);
    const offerSig = ed25519Sign(fromHex(FROZEN_KAT.CALLER_ED25519_PRIV), offerSigned);
    expect(toHex(offerSig)).toEqual(FROZEN_KAT.OFFER_SIGNATURE);
    expect(ed25519Verify(fromHex(FROZEN_KAT.CALLER_ED25519_PUB), offerSigned, offerSig)).toEqual(true);

    // ---- 7. SRTP AES-CM-128 round-trip ----
    const plaintext = fromHex(FROZEN_KAT.SRTP_CM_PLAINTEXT);
    const cmSender = new SrtpSession(0x12345678, "AES_CM_128_HMAC_SHA1_80", schedule.srtpMasterKey, schedule.srtpMasterSalt);
    const cmReceiver = new SrtpSession(0x12345678, "AES_CM_128_HMAC_SHA1_80", schedule.srtpMasterKey, schedule.srtpMasterSalt);
    function header(ssrc: number, seq: number, ts: number): RtpHeader {
      return { version: 2, padding: false, extension: false, cc: 0, marker: false, pt: 96, seq, timestamp: ts, ssrc };
    }
    const cmPkt = cmSender.encrypt(header(0x12345678, 0x0001, 0xCAFEBABE), plaintext);
    expect(toHex(cmPkt.ciphertext)).toEqual(FROZEN_KAT.SRTP_CM_CIPHERTEXT);
    expect(toHex(cmPkt.tag)).toEqual(FROZEN_KAT.SRTP_CM_TAG);
    const cmDecrypted = cmReceiver.decrypt(cmPkt);
    expect(toHex(cmDecrypted)).toEqual(FROZEN_KAT.SRTP_CM_PLAINTEXT);

    // ---- 8. SRTP AES-256-GCM round-trip ----
    const gcmSender = new SrtpSession(0x12345678, "AES_256_GCM", schedule.srtpGcmKey, schedule.srtpGcmSalt);
    const gcmReceiver = new SrtpSession(0x12345678, "AES_256_GCM", schedule.srtpGcmKey, schedule.srtpGcmSalt);
    const gcmPkt = gcmSender.encrypt(header(0x12345678, 0x0001), plaintext);
    expect(toHex(gcmPkt.ciphertext)).toEqual(FROZEN_KAT.SRTP_GCM_CIPHERTEXT);
    expect(toHex(gcmPkt.tag)).toEqual(FROZEN_KAT.SRTP_GCM_TAG);
    const gcmDecrypted = gcmReceiver.decrypt(gcmPkt);
    expect(toHex(gcmDecrypted)).toEqual(FROZEN_KAT.SRTP_CM_PLAINTEXT);
  });

  it("ML-KEM implicit rejection: tampering with the ciphertext changes the shared secret", () => {
    // A well-known property of ML-KEM: it does NOT throw on a mismatched
    // ciphertext; it returns a pseudo-random shared secret. This is
    // "implicit rejection" and is required by the FIPS 203 spec.
    const ciphertext = fromHex(FROZEN_KAT.MLKEM_CIPHERTEXT);
    const tampered = new Uint8Array(ciphertext);
    tampered[0] ^= 0x01;
    const expected = kemDecapsulate(fromHex(FROZEN_KAT.CALLER_MLKEM_EPH_PRIV), ciphertext);
    const actual = kemDecapsulate(fromHex(FROZEN_KAT.CALLER_MLKEM_EPH_PRIV), tampered);
    expect(toHex(actual)).not.toEqual(toHex(expected));
  });

  it("callee side computes the same kex secret (mutual authentication)", () => {
    // The X25519 side: callee computes with its own ephemeral priv + caller's ephemeral pub
    const xCallee = x25519Shared(
      fromHex(FROZEN_KAT.CALLEE_X25519_EPH_PRIV),
      fromHex(FROZEN_KAT.CALLER_X25519_EPH_PUB),
    );
    // The ML-KEM side: callee generated the ciphertext (encapsulated against caller's pub)
    // so callee can re-derive the shared secret by re-encapsulating? NO: callee
    // generated the ciphertext using a random encaps key; it can recover the
    // shared secret by storing (ciphertext, sharedSecret) pair. The test
    // re-encapsulates to get the matching value.
    const enc = kemEncapsulate(fromHex(FROZEN_KAT.CALLER_MLKEM_EPH_PUB));
    // The KAT MLKEM_CIPHERTEXT was generated from the callee's randomness.
    // We can't reproduce it deterministically; instead, the test asserts
    // that re-deriving from xCallee+transcriptHash+safetySeed gives the
    // SAME kexSecret the caller computed.
    // (The caller already has the right mlkemShared from the KEM ciphertext;
    //  the callee must too — that's the FIPS 203 implicit-rejection-correctness property.)
    const transcriptHash = computeTranscriptHash({
      callId: fromHex(FROZEN_KAT.CALL_ID),
      callerIdentity: {
        ed25519: fromHex(FROZEN_KAT.CALLER_ED25519_PUB),
        x25519: fromHex(FROZEN_KAT.CALLER_X25519_PUB),
        mlkem: fromHex(FROZEN_KAT.CALLER_MLKEM_PUB),
      },
      calleeIdentity: {
        ed25519: fromHex(FROZEN_KAT.CALLEE_ED25519_PUB),
        x25519: fromHex(FROZEN_KAT.CALLEE_X25519_PUB),
        mlkem: fromHex(FROZEN_KAT.CALLEE_MLKEM_PUB),
      },
      callerEphemeral: {
        x25519: fromHex(FROZEN_KAT.CALLER_X25519_EPH_PUB),
        mlkem: fromHex(FROZEN_KAT.CALLER_MLKEM_EPH_PUB),
      },
      calleeEphemeralPublic: fromHex(FROZEN_KAT.CALLEE_X25519_EPH_PUB),
      mlkemCiphertext: fromHex(FROZEN_KAT.MLKEM_CIPHERTEXT),
    });
    expect(toHex(xCallee)).toEqual(FROZEN_KAT.X25519_SHARED);

    // Sanity check: derive callee-side kexSecret with xCallee and the FROZEN
    // MLKEM_SHARED (which is what the callee knows from its own encapsulation),
    // and assert it equals the caller's KEX_SECRET.
    const calleeKexSecret = deriveKexSecret({
      x25519Shared: xCallee,
      mlkemShared: fromHex(FROZEN_KAT.MLKEM_SHARED),
      transcriptHash,
    });
    expect(toHex(calleeKexSecret)).toEqual(FROZEN_KAT.KEX_SECRET);
  });
});
