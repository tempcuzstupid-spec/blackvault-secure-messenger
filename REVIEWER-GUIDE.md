# BlackVault Voice Protocol — Cryptographer Review Package

**Date:** 2026-09-05
**Branch:** `2026-09-05__voice-frozen-kat-review-package`
**Commit:** `5e985a52dcff53b77bc76b74d5001297f3fef8e9`
**Status:** Awaiting external cryptographic review before any production use.

## What this is

A spec-first voice calling protocol for the BlackVault end-to-end
encrypted messenger. The protocol uses:

- **X25519 + ML-KEM-768 hybrid KEX** for per-call forward secrecy
  with post-quantum security
- **Ed25519 signatures** over the SDP offer/answer to bind them to
  the caller's long-term identity
- **HKDF-SHA-256** to derive the key schedule from the KEX shared
  secret
- **SRTP** (RFC 3711) for media confidentiality + integrity, with
  both AES-CM-128-HMAC-SHA1-80 (mandatory) and AES-256-GCM (RFC 7714)
  cipher suites
- **Signaling over the existing BlackVault E2E channel** (no new
  server-side trust)
- **Single TURN relay** for media transport (no P2P)

Threat model: nation-state passive and active adversary with
quantum capability. Sealed-sender signaling, traffic analysis
mitigation, and authenticated device-to-device ratchets are
deferred to v2 (honest gaps documented in `PROTOCOL.md` §12).

## What I want from you

A credentialed cryptographic reviewer (PhD-level or equivalent
experience) to evaluate the protocol and produce a written report
covering, at minimum, the items marked **[REVIEW]** below. The
expected output is a 5-15 page report with:

1. Per-area assessment: **OK**, **OK with caveats**, **needs change**, or **blocker**
2. Specific findings (cite file + line where possible)
3. Concrete suggestions (test vectors, alternative constructions,
   additional properties to prove)
4. A signature: "I have read the protocol, code, and test vectors
   and have [no blockers / N blockers]"

This is not a formal FIPS 140-3 audit. It is a focused review of
the protocol design and its implementation correctness.

---

## Files to review

All paths are relative to `app/` in the BlackVault repo. Total
review surface: ~3,000 lines of code + 600 lines of spec + 500
lines of test vectors.

### 1. Specification (read first)

| File | Lines | Purpose |
|------|------:|---------|
| `PROTOCOL.md` | 596 | Full protocol spec with threat model, KEX details, key schedule, SRTP configuration, signaling message types, and **honest §12 gap inventory** |

This is the document a non-implementer can read to understand what
the protocol does and why. It cross-references the RFCs and
cryptographic standards it builds on.

### 2. Operator hardening

| File | Lines | Purpose |
|------|------:|---------|
| `OPERATOR-HARDENING.md` | 351 | What the server operator must NOT log, how to deploy the TURN relay safely, runtime hardening checklist |

This is what the dev/SRE team uses to deploy the system without
undermining the crypto.

### 3. Test vectors (the byte-for-byte KAT)

| File | Lines | Purpose |
|------|------:|---------|
| `docs/voice-test-vectors.md` | 363 | Documented KAT values for review |
| `api/voice/kat.frozen.ts` | 80+ | Committed hex inputs and expected outputs |
| `tests/voice.kat.frozen.test.ts` | 200 | Re-derives every output from inputs and asserts byte-for-byte match |
| `scripts/voice-kat-gen.ts` | 130 | Regenerates the KAT (only if the spec changes) |

This is what a reviewer uses to verify the implementation
reproduces a specific, committed set of values. Run
`cd app && npx vitest run tests/voice.kat.frozen.test.ts` to
verify.

### 4. Source code (the implementation)

| File | Lines | Purpose |
|------|------:|---------|
| `api/voice/types.ts` | 80 | Type definitions: IdentityKeyPair, EphemeralKeyPair, CallOffer, CallAnswer, CallHangup, label constants |
| `api/voice/kex.ts` | 240 | KEX primitives: generateIdentity, generateEphemeral, kemEncapsulate/Decapsulate, x25519Shared, deriveKexSecret, ed25519Sign/Verify, transcript hash, HKDF-SHA-256 |
| `api/voice/keySchedule.ts` | 110 | HKDF-based key schedule: deriveKeySchedule produces chaining key, root key, SRTP master key/salt, GCM key/salt, ratchet root, safety number seed |
| `api/voice/srtp.ts` | 280 | SRTP session for both AES-CM-128-HMAC-SHA1-80 and AES-256-GCM cipher suites. ROC maintenance per RFC 3711 §4.1, key derivation per §4.3 |
| `api/voice/safetyNumber.ts` | 50 | 12-emoji safety number display from a 64-emoji alphabet |
| `api/voice/sdp.ts` | 30 | SDP gzip compression via pako |

### 5. Other tests (for completeness)

| File | Tests | Purpose |
|------|------:|---------|
| `tests/voice.kat.test.ts` | 10 | Protocol-level binding tests: safety number Hamming distance on input perturbations |
| `tests/voice.srtp.test.ts` | 7 | SRTP edge cases: ROC wraparound, reorder window, auth tag failure, nonce uniqueness |
| `tests/voice.srtp.fuzz.test.ts` | 2 | 1000-trial AES-CM-128 + 100-trial AES-256-GCM fuzz with 10/20/5% drop/reorder/duplicate rates |

Total test count: 22/22 passing.

---

## How to verify

```bash
# 1. Clone the review branch
git clone https://github.com/tempcuzstupid-spec/blackvault-secure-messenger.git
cd blackvault-secure-messenger/app
git checkout 2026-09-05__voice-frozen-kat-review-package

# 2. Install pinned dependencies
npm ci

# 3. Run all 22 tests (should all pass)
npx vitest run tests/

# 4. Verify the build is clean
npm run build

# 5. Re-derive a fresh KAT (optional; this regenerates kat.frozen.ts)
#    Don't commit the result unless the spec actually changed.
npx tsx scripts/voice-kat-gen.ts
```

The library versions are pinned in `package.json`. Any version
change requires regenerating the KAT.

---

## Areas of focus

Marked **[REVIEW]** in the protocol and code. These are the
specific places I want you to look at and either confirm or push
back.

### **[REVIEW-1]** Hybrid KEX combiner construction

**Location:** `api/voice/kex.ts`, function `deriveKexSecret`.
**Spec:** `PROTOCOL.md` §4.2.

The combiner:
```
ikm   = x25519Shared || mlkemShared   // 64 bytes
kexSecret = HKDF-SHA-256(
  ikm,
  salt: SHA-256("bv-voice-v1-kex-salt"),
  info: "bv-voice-v1-kex-master" || transcriptHash
)
```

The pattern is "concatenate two shared secrets, run through HKDF".
This is similar to (but not identical to) Noise's `MixHash` + KDF
chain, and to X3DH's `HKDF(DH_A||DH_B||...)`.

**Question:** Is this construction a robust AKE given that one
component (X25519) is a classical group and the other (ML-KEM-768)
is a lattice KEM? Specifically:

- Does HKDF-SHA-256 give us IND-CCA-style security for the
  combined secret, or do we need a stronger KDF?
- Is `transcriptHash` in the `info` argument the right binding? (It
  binds the KEX to the callId, identities, and ephemerals, so a
  MITM cannot substitute a different transcript.)
- If ML-KEM-768 is broken tomorrow (or in 5 years), does the
  protocol still have X25519 security? (Yes, by inspection. The
  concatenation is `||` so X25519 alone gives a 32-byte secret
  that is independent of ML-KEM. But verify.)
- If X25519 is broken tomorrow, does ML-KEM-768 alone give a
  32-byte secret? (Yes, by inspection. ML-KEM-768 gives 32 bytes
  on its own. But verify.)

### **[REVIEW-2]** Transcript hash construction

**Location:** `api/voice/kex.ts`, function `computeTranscriptHash`.
**Spec:** `PROTOCOL.md` §4.2.

The transcript binds:
```
"bv-voice-v1-transcript" ||
CALL_ID ||                       // 16 bytes
CALLER_X25519_PUB ||            // 32 bytes
CALLER_MLKEM_PUB ||             // 1184 bytes
CALLEE_X25519_PUB ||            // 32 bytes
CALLEE_MLKEM_PUB ||             // 1184 bytes
CALLER_X25519_EPH_PUB ||        // 32 bytes
CALLER_MLKEM_EPH_PUB ||         // 1184 bytes
CALLEE_X25519_EPH_PUB ||        // 32 bytes
MLKEM_CIPHERTEXT                // 1088 bytes
```

**Question:** Does this transcript binding cover everything a
MITM might want to substitute? Specifically:

- Are all inputs to the KEX included? (Check: X25519 priv, ML-KEM
  priv, ML-KEM ciphertext — all are transitively bound because
  their corresponding public values are here.)
- Is the order significant? (Yes; a different order is a different
  transcript. The implementation uses a fixed order. Verify this is
  canonical.)
- The label prefix `"bv-voice-v1-transcript"` is included to
  prevent cross-protocol attacks (e.g., using the same bytes in a
  different BlackVault context). Is this sufficient?

### **[REVIEW-3]** Key schedule

**Location:** `api/voice/keySchedule.ts`, function `deriveKeySchedule`.
**Spec:** `PROTOCOL.md` §4.3.

The key schedule extracts 8 named keys from `kexSecret` via HKDF:
- `kexChainingKey` (32 bytes)
- `rootKey` (32 bytes)
- `srtpMasterKey` (16 bytes, AES-CM)
- `srtpMasterSalt` (14 bytes, AES-CM)
- `srtpGcmKey` (32 bytes, AES-GCM)
- `srtpGcmSalt` (12 bytes, AES-GCM)
- `ratchetRoot` (32 bytes, reserved for v2)
- `safetyNumberSeed` (32 bytes)

**Question:** Are the HKDF info labels and salts correctly chosen
to give domain separation? Specifically:

- Should `srtpMasterKey` and `srtpGcmKey` share a root, or should
  they be derived from independent HKDF calls with the same IKM?
  (Currently both use `rootKey` as IKM with different `info` labels.
  This means the rootKey is the only thing tying them together.)
- Is the salt choice (zeroes vs `transcriptHash`) appropriate for
  each derivation? (The chaining key and safety number seed use
  `transcriptHash`; everything else uses zeros. Verify this is
  intentional and correct.)
- Is the truncation of `srtpMasterSalt` from 32 to 14 bytes
  (AES-CM) and 12 bytes (AES-GCM) safe per the relevant RFCs?
  (RFC 3711 §4.3 says salt for AES-CM is 14 bytes; RFC 7714 says
  12 bytes for GCM. Both are just truncations of a longer HKDF
  output.)

### **[REVIEW-4]** SRTP per-packet key derivation (RFC 3711 §4.3)

**Location:** `api/voice/srtp.ts`.
**Spec:** `PROTOCOL.md` §6.

The implementation derives per-packet encryption keys and auth keys
from `srtpMasterKey`, `srtpMasterSalt`, packet index, and SSRC,
per RFC 3711 §4.3.

**Question:**

- The implementation uses
  `cbc(key, zeros).encrypt(label)` to emulate single-block AES-ECB
  for the §4.3 key derivation. `@noble/ciphers/aes` doesn't export
  raw ECB. CBC with a zero IV on a single block is mathematically
  equivalent to ECB (the IV XORs the plaintext, but the plaintext
  here is the AES input, and XORing with zero is the identity).
  Is this trick safe? (Yes, but a reviewer should confirm.)
- The implementation does the same trick for AES-GCM key
  derivation per RFC 7714. Same question.
- The ROC (rollover counter) is maintained per RFC 3711 §4.1 with
  a window of 100. Is the window size appropriate? (RFC 3711
  suggests 100; verify this is what the spec assumes.)
- The auth tag for AES-CM is 10 bytes (80 bits), per RFC 3711. Is
  this the right length? (RFC 3711 §4.2 says "80 bits" as the
  default; verify.)

### **[REVIEW-5]** Safety number

**Location:** `api/voice/safetyNumber.ts`.
**Spec:** `PROTOCOL.md` §4.5.

The safety number is:
```
SHA-256(
  "bv-voice-v1-safety-final" ||
  CALLER_X25519_PUB ||
  CALLER_MLKEM_PUB ||
  CALLEE_X25519_PUB ||
  CALLEE_MLKEM_PUB ||
  SAFETY_NUMBER_SEED
)
```

Then 9 bytes of the digest are split into 6 groups of 12 bits,
each indexing a 64-emoji alphabet, displayed as 6 pairs of 2
emojis.

**Question:**

- Is 9 bytes (72 bits) of safety number entropy sufficient against
  a brute-force or birthday attack? (For a voice call between two
  parties who already exchanged public keys, the attacker needs to
  find a different `(callerPub, calleePub, seed)` triple that
  produces the same 72-bit prefix. With 72 bits, the birthday bound
  is 2^36 ≈ 6.8 × 10^10 attempts. Probably sufficient, but verify.)
- Is the emoji alphabet choice OK? (The alphabet is 64 common
  Unicode emojis with no visual ambiguity. Verify this is
  acceptable for the threat model.)
- Is the binding to all five inputs (the two X25519 pubs, the two
  ML-KEM pubs, and the seed) correct? The transcript binding
  tests in `tests/voice.kat.test.ts` vary each input by 1 bit and
  check Hamming distance; verify the implementation actually
  varies.

### **[REVIEW-6]** ML-KEM implicit rejection

**Location:** `api/voice/kex.ts`, function `kemDecapsulate`.
**Spec:** `PROTOCOL.md` §4.2.

ML-KEM-768 (FIPS 203) does not throw an exception on a tampered
ciphertext. It returns a pseudo-random shared secret derived from
the ciphertext hash. This is "implicit rejection" and is required
by the spec.

**Question:**

- The implementation relies on this behavior; the test
  "ML-KEM implicit rejection" in `voice.kat.frozen.test.ts`
  verifies that a tampered ciphertext yields a different shared
  secret (not that it throws). Is the implementation correctly
  handling the case where the callee and caller compute different
  kexSecrets? (Yes, the protocol falls back to safety-number
  mismatch, which the user verifies out-of-band. Verify this is
  sound.)
- The implicit rejection is parameterized by the ciphertext, so an
  attacker who tampers with a ciphertext gets a shared secret
  that's deterministic in the ciphertext. Is there a side-channel
  risk here? (Not for the current threat model; the attacker can
  already see the ciphertext. Verify.)

### **[REVIEW-7]** SDP signature (Ed25519 over SDP)

**Location:** `api/voice/kex.ts`, functions `offerSignatureInput`,
`answerSignatureInput`, `ed25519Sign`, `ed25519Verify`.
**Spec:** `PROTOCOL.md` §5.2.

The caller signs the SDP offer with their long-term Ed25519
private key. The signature is sent in the signaling message; the
callee verifies it before using the offer.

**Question:**

- The signature input includes `callId`, `identity pub`,
  `ephemeral pub`, and `SHA-256(SDP body)`. Does this bind the
  signature to the KEX parameters? (Yes, by including the
  ephemeral pub. Verify.)
- Is the SDP body itself bound to the KEX? (Not directly. The SDP
  contains ICE candidates and DTLS fingerprints in the v1 design
  that was abandoned; v1 uses SRTP and the SDP carries media
  configuration only. Verify this is OK.)
- The signature uses Ed25519 in pure mode (no prehashing). Is this
  the right choice? (Yes, for this use case; prehashing is for
  large messages. SDP is small. Verify.)

### **[REVIEW-8]** Operational gaps (what is NOT in the protocol)

**Spec:** `PROTOCOL.md` §12.

The honest gap inventory. The protocol does NOT have:
- Memory locking (mlock); JS has no mlock. Audio buffers may swap.
  Mitigation: immediate zeroize on use.
- Sealed-sender signaling; the server sees message type/size/timing
  for the encrypted voice channel.
- Single-relay metadata; the TURN server sees timing and packet
  sizes for media. Onion routing (Tor) is not in v1.
- Identity hiding from the server; the server knows both users'
  long-term public keys.
- Formal analysis; the protocol draws on X3DH/Noise patterns but
  has not been formally analyzed.

**Question:** Are these gaps acceptable for the threat model? (The
threat model is "nation-state passive and active adversary with
quantum capability, but not the most-resource-bounded case where
Tor-level metadata protection is required.") The user has
explicitly accepted these gaps for v1, with phase 2 planned for
the metadata-sensitive gaps. Verify this trade-off is sound.

---

## Things I am explicitly NOT asking you to do

- **Audit the BlackVault messenger's existing channel encryption
  (AES-256-GCM with HKDF-SHA-256).** That is out of scope; the
  voice protocol builds on it but does not modify it.
- **Review the React/UI layer.** Not yet written. Signaling types
  are defined in `api/voice/types.ts` but not yet wired into the
  messenger.
- **Audit the TURN relay deployment.** The protocol says "use a
  single TURN relay with `iceTransportPolicy: 'relay'`"; the
  TURN server itself is a separate concern.
- **Formal verification (Tamarin, ProVerif, etc.).** This is a
  code review, not a symbolic analysis. If you want to add a
  symbolic analysis, that would be a separate engagement.

---

## Compensation and timeline

[As agreed separately with the user.]

## Contact

[As agreed separately.]

---

## What I will do with your report

1. Address every blocker finding by changing the spec and code.
2. Address every "needs change" finding by either fixing the
   issue or adding a §12 entry explaining why we kept the current
   design.
3. Add a CHANGELOG entry summarizing the review.
4. If the report comes back clean, mark the protocol as "review
   passed" and proceed to React integration and TURN deployment.
5. If the report comes back with substantive concerns, hold
   deployment and fix before integrating.

If the report says "this is fundamentally broken, redo the
crypto", I will start over. That's the point of doing this
review before deploying.

---

## Appendix: Threat model summary

Adversary capabilities:
- **Passive:** observe all network traffic, including SRTP and
  TURN relay metadata
- **Active:** modify, drop, replay, and inject packets; control
  the TURN server; control the messaging server; serve malicious
  JavaScript to clients via CDN compromise
- **Quantum:** store ciphertext for later decryption by a CRQC

Adversary limitations (assumed):
- Cannot break AES-256-GCM, AES-CM-128, SHA-256, HKDF-SHA-256,
  HMAC-SHA-1, HMAC-SHA-256 within their classical security
  margins
- Cannot break X25519 or Ed25519 within their classical security
  margins
- Cannot break ML-KEM-768 within its claimed post-quantum
  security margin
- Cannot break a properly-mlock'd memory region (i.e., they
  cannot recover keys from RAM after the application zeroes them,
  modulo the mlock gap noted in §12.3)
- Cannot perform a nation-state-level side-channel attack on
  the user's physical device (e.g., TEMPEST, cold-boot
  variants that recover mlocked memory)

**This is not a Tor-level threat model.** The v1 protocol does
not provide metadata protection against a global passive
adversary. v2 will.

---

## Appendix: Honest disagreements with the user

The user asked for a voice protocol that is "better than Signal".
I pushed back. Here's what that means in practice:

| Property | Signal | This protocol | Honest assessment |
|----------|--------|---------------|-------------------|
| Sealed sender | Yes | No (v1) | v1 is worse |
| Post-quantum KEX | Yes (PQXDH) | Yes (ML-KEM-768 + X25519) | Equivalent |
| Forward secrecy per call | Yes (Double Ratchet) | Yes (ephemeral KEMs) | Equivalent |
| Authenticated ratchets | Yes (Double Ratchet) | No (v1) | v1 is worse |
| Re-key during call | Yes | No (v1) | v1 is worse |
| SRTP media | Yes (DTLS-SRTP) | Yes (custom) | Equivalent |
| Server sees call metadata | Yes | Yes (signaling) | Equivalent |
| Open-source client | Yes | Partial (server not yet) | Equivalent |

**Honest summary:** This protocol is "as good as Signal" on the
core crypto (KEX, SRTP, key schedule). It is "worse than Signal"
on UX properties (no in-call re-key, no ratchet, no sealed
sender). The trade-off is documented in `PROTOCOL.md` §12.

If your review concludes that any of the "worse than Signal"
properties create a real security weakness for the stated threat
model, please flag it. We will not pretend the trade-off doesn't
exist.

---

**End of reviewer guide.**
