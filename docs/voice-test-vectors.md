# BlackVault Voice — Test Vector Fixtures (v1)

**Status:** Frozen KAT (Known Answer Test) fixtures for the protocol
document. Every value in §1-§9 below is committed in
`api/voice/kat.frozen.ts` and verified byte-for-byte by
`tests/voice.kat.frozen.test.ts`. A reviewer can:

1. Open `api/voice/kat.frozen.ts` and verify the input keys (§1)
2. Open `tests/voice.kat.frozen.test.ts` and verify the assertion
   logic
3. Run `cd app && npx vitest run tests/voice.kat.frozen.test.ts`
   to confirm the implementation reproduces the expected outputs
   from the committed inputs

The values are deterministic given the inputs. They are not derived
from a published RFC test vector (this protocol is not in any RFC);
they are the KAT produced by the reference implementation itself.
The reference implementation is locked to specific `@noble` library
versions, recorded at the top of `kat.frozen.ts`. Re-running the
generator script produces a different set of values (because
`keygen()` is non-deterministic), but re-running the **frozen test**
with the committed `kat.frozen.ts` always produces the same outputs.

---

## 1. Frozen inputs

### 1.1 Test labels and contexts

The HKDF and signing labels used throughout. These are constant
across all calls; the implementation encodes them as
`Uint8Array` literals in `api/voice/kex.ts` and
`api/voice/keySchedule.ts`.

```
HKDF_SALT_KEX            = SHA-256("bv-voice-v1-kex-salt")
HKDF_INFO_KEX_MASTER     = "bv-voice-v1-kex-master" || transcriptHash
HKDF_INFO_CHAINING       = "bv-voice-v1-chaining"
HKDF_INFO_ROOT           = "bv-voice-v1-root"
HKDF_INFO_SRTP_KEY_CM    = "bv-voice-v1-srtp-key-aes-cm-128"
HKDF_INFO_SRTP_SALT      = "bv-voice-v1-srtp-salt"
HKDF_INFO_SRTP_KEY_GCM   = "bv-voice-v1-srtp-key-aes-gcm-256"
HKDF_INFO_SRTP_SALT_GCM  = "bv-voice-v1-srtp-salt-aes-gcm"
HKDF_INFO_RATCHET_ROOT   = "bv-voice-v1-ratchet-root"
HKDF_INFO_SAFETY_SEED    = "bv-voice-v1-safety-number"
HKDF_INFO_SAFETY_FINAL   = "bv-voice-v1-safety-final"
SIGN_PREFIX_OFFER        = "bv-voice-v1-offer"
SIGN_PREFIX_ANSWER       = "bv-voice-v1-answer"
TRANSCRIPT_PREFIX        = "bv-voice-v1-transcript"
```

### 1.2 Test identities (frozen)

```
CALLER_ED25519_PUB  = 726b2fd1613457ccb0859ec4360ba4c678fa15f071e764aeb2b3b01da9e534ab
CALLER_ED25519_PRIV = e60b1a6e5622118e4b8f6db56b099b65864f91c16a64cb6f1017d3e0fa4d5dfb
CALLER_X25519_PUB   = b38e32ad748805cac20c1be189d9eba0eea321532cde8f0a03f456f4cb2ff744
CALLER_X25519_PRIV  = 99ad74f3af25aac12495aa92459dd51a43f0cef33536557ddc24668f3a22e0ba
CALLER_MLKEM_PUB    = 9be75cc0c02e9f39109c08bc3044178926c369d066cbc69c0143198d00861799
                      (1184 bytes; full value in kat.frozen.ts)
CALLER_MLKEM_PRIV   = 89f3a11cd58327bccd0413aac8c6c966ea226065bbb00370830993f71b3ef1d7
                      (2400 bytes; full value in kat.frozen.ts)

CALLEE_ED25519_PUB  = c7c272feb7e838b3320728795cb93b8d7da3fd7e989884fe40b88bcf62e00bd4
CALLEE_ED25519_PRIV = 2f417c7533eae6d949bf6bfa4065def6824bed73b009d501597491a7458d15fe
CALLEE_X25519_PUB   = ed731035826e60e280fab576b7a3b4009b865dd3f20b99d0c131748adbcb0a4f
CALLEE_X25519_PRIV  = 6eecd934e9539430cb34c0d8347f7c389f7e9f7b53e6f2d809d57350373d856a
CALLEE_MLKEM_PUB    = 1e8b7440784a8f4613c077c040645492c257df93668e6491fdeb8a20d2016838
                      (1184 bytes; full value in kat.frozen.ts)
CALLEE_MLKEM_PRIV   = 58f47b2025670304551107b08c1165b55935d902735446c61db0c0c21c0df30b5
                      (2400 bytes; full value in kat.frozen.ts)
```

These keys are committed as a single canonical pair in
`api/voice/kat.frozen.ts`. In production, the keys are generated
fresh per device and rotated. In the KAT, the keys are locked so
the test vectors are reproducible.

### 1.3 Test ephemerals (frozen)

Per-call ephemerals. Generated once and committed.

```
CALLER_X25519_EPH_PUB  = af6e83a244eda323a94d741baaf25426fe46efcdc4be646432f2f55b9c6c9c12
CALLER_X25519_EPH_PRIV = 9337bb8e347655a9c89a3bbf38b191a943dbd51dc65b06192d89e9d841d36acc
CALLER_MLKEM_EPH_PUB   = 51147fea88ab9a787518ca2884764096bc13c9f63ab9d35e6d8413b96243cbd7
                         (1184 bytes; full value in kat.frozen.ts)
CALLER_MLKEM_EPH_PRIV  = e490c9a3d002fa6c242bc0640cc54a5e3621b947566987a1d271c4eb078082fc
                         (2400 bytes; full value in kat.frozen.ts)

CALLEE_X25519_EPH_PUB  = 19332eee915741497d337ac1b8d3e910137bae8efeba310f87b93e0cc063622c
CALLEE_X25519_EPH_PRIV = 3634adaf37b804ba33a7bb7acf99e61e57dafedac558adf03bd90878270c2ac4
CALLEE_MLKEM_EPH_PUB   = c936a42b2a2718ebb4dcda4107c13581b34bbfd3291f887b70c95af4b53b05d2
                         (1184 bytes; full value in kat.frozen.ts)
CALLEE_MLKEM_EPH_PRIV  = 71a7bdc12367a2e0974197588cf3135faa49e1273b241b250a42b827d7a15e04
                         (2400 bytes; full value in kat.frozen.ts)
```

### 1.4 ML-KEM ciphertext (frozen)

```
MLKEM_CIPHERTEXT = 2d4d5ce6505ccbf2d536860a0026bfbac54ae6c6ac9f32c79b2665c794fe966c...
                   (1088 bytes; full value in kat.frozen.ts)
```

Callee generates this by encapsulating against CALLER_MLKEM_EPH_PUB.

### 1.5 Call id (frozen)

```
CALL_ID = 630dcd2966c4336691125448bbb25b4f
```

(Hash of the test seed, truncated to 16 bytes.)

---

## 2. Transcript hash (KAT fixture 1)

**Inputs:** callId, identity public keys, ephemeral public keys,
mlkemCiphertext (see §1).

**Computation (per PROTOCOL §4.2):**

```
transcriptBytes = concat(
  "bv-voice-v1-transcript",        // 23 bytes
  CALL_ID,                          // 16 bytes
  CALLER_X25519_PUB,                // 32 bytes
  CALLER_MLKEM_PUB,                 // 1184 bytes
  CALLEE_X25519_PUB,                // 32 bytes
  CALLEE_MLKEM_PUB,                 // 1184 bytes
  CALLER_X25519_EPH_PUB,            // 32 bytes
  CALLER_MLKEM_EPH_PUB,             // 1184 bytes
  CALLEE_X25519_EPH_PUB,            // 32 bytes
  MLKEM_CIPHERTEXT                  // 1088 bytes
)

transcriptHash = SHA-256(transcriptBytes)
```

**Expected output:**

```
TRANSCRIPT_HASH = 929c965e3702309d7ccbd8e0c20ed640ec00ad7a5a5ff6d8cf2686a5bd9de828
```

---

## 3. KEX shared secret (KAT fixture 2)

**Inputs:** ephemeral private keys, ML-KEM ciphertext, transcript hash.

```
x25519Shared = X25519.scalarMult(CALLER_X25519_EPH_PRIV, CALLEE_X25519_EPH_PUB)
# Both sides compute the same value. Asserted by the test.

x25519Shared = 161c002ea21738dc20a0ea7a469f5584e0aac11f3a5ec1f53dc5a9560b59b27c

mlkemShared = MLKEM.decapsulate(CALLER_MLKEM_EPH_PRIV, MLKEM_CIPHERTEXT)
# Both sides compute the same value. Asserted by the test.

mlkemShared = fa9181e01f42987983d1ea008ad452f6e03b13edae96c0fc3ce7d25bea64bbfa

ikm = x25519Shared || mlkemShared  // 64 bytes

kexSecret = HKDF-SHA-256(
  ikm,
  salt: SHA-256("bv-voice-v1-kex-salt"),
  info: "bv-voice-v1-kex-master" || TRANSCRIPT_HASH
)
// 32 bytes:
KEX_SECRET = f972dd2ec73c1d10da8e6d883220bec8829aa9362aebf149e856320fa17973ef
```

---

## 4. Key schedule (KAT fixture 3)

**Inputs:** `kexSecret`, `transcriptHash`.

```
kexChainingKey = HKDF-SHA-256(ikm: KEX_SECRET, salt: TRANSCRIPT_HASH, info: "bv-voice-v1-chaining")
// 32 bytes:
KEX_CHAINING_KEY = 11ad242cf9c55c15f9d7f20ddc46bfc3181742e63c3e4c9c408bd3fbd25f72aa

rootKey = HKDF-SHA-256(ikm: KEX_CHAINING_KEY, salt: 0x00...00, info: "bv-voice-v1-root")
// 32 bytes:
ROOT_KEY = afd425e1995ca75ce6cc082851af7b6c0e02ac3f3d2319e05b6a11a672e0696c

srtpMasterKey = HKDF-SHA-256(ikm: ROOT_KEY, salt: 0x00...00, info: "bv-voice-v1-srtp-key-aes-cm-128")
// 16 bytes:
SRTP_MASTER_KEY = dc26dca00d24f830228f60a3726b4e46

srtpMasterSalt = HKDF-SHA-256(ikm: ROOT_KEY, salt: 0x00...00, info: "bv-voice-v1-srtp-salt").slice(0, 14)
// 14 bytes:
SRTP_MASTER_SALT = 88f797aeae146e9c4f52adcb9a9d

srtpGcmKey = HKDF-SHA-256(ikm: ROOT_KEY, salt: 0x00...00, info: "bv-voice-v1-srtp-key-aes-gcm-256")
// 32 bytes:
SRTP_GCM_KEY = 7bffcef4cf9fa7caeab5e2269b708f66ed6a9ef741b89d985b325e80eb6590c8

srtpGcmSalt = HKDF-SHA-256(ikm: ROOT_KEY, salt: 0x00...00, info: "bv-voice-v1-srtp-salt-aes-gcm").slice(0, 12)
// 12 bytes:
SRTP_GCM_SALT = d47fc2ecc53c7ab4898ae751

ratchetRoot = HKDF-SHA-256(ikm: ROOT_KEY, salt: 0x00...00, info: "bv-voice-v1-ratchet-root")
// 32 bytes (reserved; not used in v1):
RATCHET_ROOT = 1fc246633a7b4007f9f19e6fdc6456a91b5606419bf68466f1df087278bb1528

safetyNumberSeed = HKDF-SHA-256(ikm: ROOT_KEY, salt: TRANSCRIPT_HASH, info: "bv-voice-v1-safety-number")
// 32 bytes:
SAFETY_NUMBER_SEED = 2de4b7f0e9d3399e91a87356cf778b62cd74ebaa244e009cce1cba1f8a0a770d
```

---

## 5. Safety number (KAT fixture 4)

**Inputs:** long-term public keys, `safetyNumberSeed`.

```
safetyNumber = SHA-256(
  "bv-voice-v1-safety-final" ||
  CALLER_X25519_PUB ||
  CALLER_MLKEM_PUB ||
  CALLEE_X25519_PUB ||
  CALLEE_MLKEM_PUB ||
  SAFETY_NUMBER_SEED
)
// 32 bytes:
SAFETY_NUMBER = dbb3b86d89792c97ac08a75c4c14f16bb1d1130a869f83ac6b45a8dc68038df6

# Emoji display: 6 pairs of 2 emojis from a 64-emoji alphabet.
# Algorithm: take 9 bytes from SAFETY_NUMBER, split into 6 groups of
# 12 bits, index into the 64-emoji alphabet, display as 6 pairs.
EMOJI_DISPLAY = 🏸🚌 🐙🚗 🌼🌷 ⚡🚕 🪐🐉 🍂🎨
```

(Verified: the emoji display function produces 6 pairs from 12 emojis total.)

---

## 6. Offer signature (KAT fixture 5)

**Inputs:** callId, identity pub, ephemeral pub, SDP body SHA-256.

```
signedInput = "bv-voice-v1-offer" ||
              CALL_ID ||
              CALLER_ED25519_PUB ||
              CALLER_X25519_PUB ||
              CALLER_MLKEM_PUB ||
              CALLER_X25519_EPH_PUB ||
              CALLER_MLKEM_EPH_PUB ||
              SHA-256("placeholder SDP body for KAT")
// hex:
OFFER_SIGNED_INPUT = (see kat.frozen.ts; ~2.5 KB, full hex in test file)

# Caller signs with CALLER_ED25519_PRIV over signedInput.
# 64 bytes:
OFFER_SIGNATURE = 9d792d51ed0e6babd42c62630c14852eadbcde272cd0a5d813ed40b51aab71403bcde1960fbdf5282bf4d3d2ba118dabc597acf22bb3ae42655e6fd3d8995302

# Verification: ed25519Verify(CALLER_ED25519_PUB, signedInput, signature) == true
```

The test verifies the signature with `ed25519Verify`.

---

## 7. SRTP KAT — AES-CM-128 (KAT fixture 6)

**Inputs:** `srtpMasterKey`, `srtpMasterSalt`, plaintext, SSRC, sequence numbers.

### 7.1 Key derivation (RFC 3711 §4.3)

The implementation derives the per-packet encryption key and auth key
using the RFC 3711 §4.3 algorithm. The labels and constants are
embedded in `api/voice/srtp.ts`.

For the frozen KAT, the test does not check the intermediate key
derivation output; it checks the full encrypt + decrypt round-trip.

### 7.2 Encrypt + Decrypt round-trip

**Test inputs:**
- SSRC = 0x12345678
- Sequence number seq = 0x0001
- Timestamp ts = 0xCAFEBABE
- ROC = 0

**Plaintext** (268 bytes):
```
48656c6c6f20535254502c20746869732069732061203130302d62797465207061796c6f616420746861742077652077616e7420746f20726f756e642d74726970207468726f75676820535254502e20546865207061796c6f6164206973206c6f6e676572207468616e206f6e652041455320626c6f636b20736f2077652065786572636973652074686520435452206d6f6465206163726f73732074776f20626c6f636b7320616e6420656e73757265206e6f20636f726e6572206361736520697320686974206f6e2074686520626c6f636b20626f756e64617279206f72206e656172207468652031362d6279746520636f756e746572207772617061726f756e6420706f696e742e2e
```

**Expected output (locked):**
- `SRTP_CM_CIPHERTEXT` = `cf8dc2ba01975e9f82392a29f15c23293574ae946d19adfba17c0bbd80a801bb8d185882a0a3dda85c2d16b70ed0e69a84907c4801c354cfd6436ae3652ad3e465ec2c22cf1aa35cd133c87a07f50baa95db52b5baf8c2893ee474104704453c3618097e4038317b2b6ada7fd3042c262af8a99b999f1ee736368941fa9cffa53ad6280eb18c617a7023da1f3f6fdcd067659138b67d58ff548834faf972106db1a84e43c7a9662bbcf5d5ca54e8284868edb16254c30bcac1630d58f23ca680eb459acccae5a4d07efcc6c6b5f7252c09be15f0e5198248c61f7da1ca574086ca07a0cad3a96a07dfe0e341748db1a73452c8d39af8f0cf286c65919730564f2ef5c4a643cc062934d0ca22`
- `SRTP_CM_TAG` (10 bytes) = `ebb111844a6a21b5e766`
- `SRTP_CM_DECRYPTED` = `SRTP_CM_PLAINTEXT` (round-trip)

### 7.3 ROC wraparound and reorder behavior

These are tested by `tests/voice.srtp.test.ts` and
`tests/voice.srtp.fuzz.test.ts` (1000-trial AES-CM-128 fuzz + 100-trial
AES-256-GCM fuzz with 10/20/5% drop/reorder/duplicate rates). The
frozen KAT does not include reorder/ROC wraparound fixtures; see
those tests for the relevant coverage.

---

## 8. SRTP KAT — AES-256-GCM (KAT fixture 7)

**Inputs:** `srtpGcmKey`, `srtpGcmSalt`, plaintext, SSRC, sequence numbers.

**Test inputs:**
- SSRC = 0x12345678
- Sequence number seq = 0x0001
- ROC = 0
- Plaintext = same as §7.2 (268 bytes)
- AAD = the RTP header (12 bytes): version=2, padding=0, ext=0, cc=0,
  marker=0, pt=0x60, seq=0x0001, ts=0xCAFEBABE, ssrc=0x12345678

**Expected output (locked):**
- `SRTP_GCM_CIPHERTEXT` = `78d3593c7069250df9914bfb266306f2301514a005d75903f27d93815521ded0674f1b5ec159f930cb983eb1afed599635b484ffcc2e7fa1922a258537d19ee3644af2eba1bc877a88d11afad6f1b819eefbd544254b6a68dd6740d4488be68208cbc37176248fa7816505bc016b88dff2e3068190674e276d0b51177d42fa86692cf5f01f75fdb4c8310f801d1a92b9606cd84bdfefd7314d75324d027852a394420fdb38d01f967cbe3f629bd870fa31b70d86e303d7fbc6fea25216e002470d457f41090e828da372e16efeb4743b2aaff6ba25b493eb9e0f946b3dd10f7789118ee47610f6cc5d64a5b0561b8576ca0800d7229b59bb0174409e17096b7ad8dc9b92f8108d8a80d1fbe5`
- `SRTP_GCM_TAG` (16 bytes) = `419a758a60becff7dd6787511ee180c7`
- `SRTP_GCM_DECRYPTED` = `SRTP_CM_PLAINTEXT` (round-trip)

---

## 9. Transcript binding (KAT fixture 8 — implicit)

The frozen test (`tests/voice.kat.frozen.test.ts`, "ML-KEM implicit
rejection" case) verifies that tampering with the ML-KEM ciphertext
produces a different shared secret. This catches a category of bugs
where the KEX is not bound to all transcript inputs.

The full transcript binding test (varying each input by one bit and
checking Hamming distance on the safety number) is in
`tests/voice.kat.test.ts` ("safety number is bound to all
transcript inputs").

---

## 10. How a reviewer uses these fixtures

1. Open `app/api/voice/kat.frozen.ts` and verify the input keys
   in §1.2-§1.4.
2. Open `app/tests/voice.kat.frozen.test.ts` and verify the
   assertions on each derived value.
3. Run `cd app && npx vitest run tests/voice.kat.frozen.test.ts`
   to confirm the implementation reproduces the expected outputs.
4. For fuzz coverage, run
   `cd app && npx vitest run tests/voice.srtp.fuzz.test.ts`
   (1000 trials AES-CM-128, 100 trials AES-256-GCM with
   10/20/5% drop/reorder/duplicate rates).
5. For the protocol-level binding tests, run
   `cd app && npx vitest run tests/voice.kat.test.ts`.

If a reviewer wants to verify a fresh build, the same test suite
should pass on their machine. The values in `kat.frozen.ts` are
deterministic given the input keys and the pinned `@noble` library
versions.

If a reviewer wants to regenerate the KAT (e.g., to check that
re-running the protocol with different keys produces valid
non-byte-identical outputs), they can run:

```
cd app && npx tsx scripts/voice-kat-gen.ts
```

This regenerates `api/voice/kat.frozen.ts` with a new set of
random keys. The frozen test will fail until the new KAT is
committed alongside the test. The point of the regeneration is to
prove the protocol produces consistent, non-broken outputs across
different inputs.

---

## 11. Library versions and pinned dependencies

The frozen KAT is reproducible only with these versions:

- `@noble/curves` 2.4.0 (X25519, Ed25519)
- `@noble/post-quantum` 0.7.1 (ML-KEM-768)
- `@noble/ciphers` 2.4.0 (AES-CM-128, AES-256-GCM)
- `@noble/hashes` 2.4.0 (SHA-256, HMAC-SHA-256, HKDF-SHA-256)
- Node.js `crypto` (HMAC-SHA-1 used for SRTP AES-CM auth tag per
  RFC 3711; the rest uses `@noble/hashes`)

Any version change requires regenerating the KAT and verifying
that the values in `kat.frozen.ts` are still produced by the
implementation. The CI build pins these versions in `package.json`.

---

## 12. Versioning

This document is version 1, dated 2026-09-05. The KAT values are
committed in `app/api/voice/kat.frozen.ts`. Changes to the
protocol require:

1. A version bump
2. An update to `app/PROTOCOL.md`
3. A regeneration of the KAT via `npx tsx scripts/voice-kat-gen.ts`
4. A commit of the updated `kat.frozen.ts`
5. A commit of the updated test vector doc (this file)
6. Re-verification that all 22 tests pass
   (`cd app && npx vitest run tests/`)
