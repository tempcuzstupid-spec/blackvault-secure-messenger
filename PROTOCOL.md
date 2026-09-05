# BlackVault Voice Protocol (v1)

**Status:** Specification draft for review before any reference implementation.
**Audience:** Cryptographic reviewers, the implementer (Mavis), and the user.

---

## 1. Scope and threat model

### 1.1 What this protocol does

Establishes 1-on-1 voice calls between two BlackVault users who already share an end-to-end-encrypted text channel. The call audio is encrypted with a fresh per-call key derived from a post-quantum hybrid key exchange. The text channel is reused for signaling; the same channel key that protects text messages also protects call setup messages.

### 1.2 Threat model (verbatim from the project spec)

**Adversary:** a nation state that does not use or need court orders.

**Capabilities assumed:**
- Passive mass surveillance: records all traffic on the wire now, for decryption later (harvest-now-decrypt-later).
- Active MITM as routine practice.
- Ability to seize, image, or coerce any server infrastructure.
- Multi-year operational patience.
- May block Tor; design accordingly (pluggable transports considered).

**Not assumed (out of scope):**
- Endpoint compromise. No protocol feature protects a compromised device.
- Global traffic-analysis immunity. Minimize exposure, do not claim elimination.

### 1.3 What this protocol does and does not defend against

| Defended | Not defended (see §12) |
|---|---|
| Audio content confidentiality against passive collection | Endpoint compromise (keyloggers, screen capture, malware) |
| Audio content confidentiality against an honest-but-curious BlackVault server | Audio content confidentiality against a compromised BlackVault server (the server can refuse to relay, but cannot decrypt if the relay disposes correctly) |
| Forward secrecy per call (past calls unrecoverable if long-term keys leak) | Forward secrecy across calls (compromise of identity keys during a call exposes that call) |
| Active MITM on the signaling channel (fingerprint verification) | Global traffic analysis (the relay sees call timing, duration, packet sizes) |
| Replay of old call offers (transcript binding + Ed25519 signature) | Replay of an in-progress call (no defense; user must hang up and re-dial) |
| Tampering with SDP bodies (signature over (callId, identityKey, sdp)) | — |

---

## 2. Cryptographic primitives (chosen, not invented)

All primitives are vetted libraries. None are hand-rolled.

| Purpose | Algorithm | Library | Version pin |
|---|---|---|---|
| Identity signing | Ed25519 | `@noble/curves` | latest 1.x at implementation time |
| Identity KEM (classical) | X25519 | `@noble/curves` | (same library) |
| Identity KEM (post-quantum) | ML-KEM-768 | `@noble/post-quantum` | latest at implementation time, pinned in `package.json` |
| Symmetric KDF | HKDF-SHA-256 | WebCrypto `crypto.subtle.deriveBits` | n/a (browser-native) |
| Hash | SHA-256 | WebCrypto `crypto.subtle.digest` | n/a |
| AEAD (signaling) | AES-256-GCM (existing channel key) | WebCrypto | n/a |
| Voice media AEAD | SRTP with AES-CM-128-HMAC-SHA1-80 (RFC 3711), or AES-256-GCM (RFC 7714) — selectable | `srtp` npm package (libSRTP) or hand-built WebCrypto path | libSRTP 2.x; or hand-built if libSRTP is unsuitable for the runtime |
| Voice codec | Opus CBR 24-32 kbps, 20ms frames, inband FEC, DTX disabled | Native browser (WebRTC) for the production path; `@discordjs/opus` for the Node test harness | — |

**Why ML-KEM-768 and not ML-KEM-1024:** 768 provides NIST Level 3 security (~AES-192), which exceeds AES-256-GCM's classical security level. 1024 would be defense-in-depth but adds ~1.5 KB to every call setup message. Spec is 768 unless reviewers object.

**Why AES-CM-128 in SRTP and not AES-GCM-256:** WebRTC's default DTLS-SRTP cipher suite is `SRTP_AES128_CM_HMAC_SHA1_80`. Browser support for AES-256-GCM in SRTP (RFC 7714) is patchy. We use AES-CM-128 by default and AES-256-GCM only when the offer and answer both negotiate it. The choice is per-call, not per-installation.

---

## 3. Identity keys (long-term)

Each user has a long-term identity triple, generated once at first login and persisted in the existing browser localStorage (encrypted by a passphrase-derived key in a future phase; for v1, stored in the same place as the channel keys):

```
identity = {
  ed25519:  Ed25519PrivateKey,      // 32-byte seed -> 64-byte expanded key
  x25519:   X25519PrivateKey,        // 32-byte scalar
  mlkem:    MLKEM768PrivateKey,      // 2400-byte expanded key
}
```

The corresponding public keys form a "key bundle" that the user publishes to peers over the existing channel. The bundle is signed with the Ed25519 private key so a MITM cannot substitute a different public key without invalidating the signature.

**Identity rotation:** The protocol does not yet define identity rotation. When a user's identity changes (e.g., new device), the safety number for any new call will differ from the previous number, and the UI must force re-verification. See §10.

**Storage of identity keys:** Out of scope for the protocol document; the application layer is responsible for encrypting the identity at rest with a passphrase-derived key. For v1, identity is stored alongside channel keys in localStorage. **This is a gap; see §12.**

---

## 4. Per-call key exchange (PQ-hybrid KEX)

### 4.1 Inputs

Both parties know:
- `callerIdentity` (long-term public triple)
- `calleeIdentity` (long-term public triple)
- The text channel through which signaling will happen

Each party freshly generates (per call):
- `callerX25519Eph` (32-byte scalar) + `callerX25519EphPub` (32-byte public)
- `callerMLKEMEph` (32-byte seed) + `callerMLKEMEphPub` (1184-byte public)
- `calleeX25519Eph` (32-byte scalar) + `calleeX25519EphPub` (32-byte public)
- `calleeMLKEMEph` (32-byte seed) + `calleeMLKEMEphPub` (1184-byte public)

### 4.2 Flow

**Step 1 (Caller):** Generate ephemeral X25519 + ML-KEM-768 keys. Construct the offer:

```
CallOffer = {
  v: 1,
  callId: random(16 bytes),                 // 128 bits of entropy
  callerIdentity: { ed25519, x25519, mlkem },
  callerEphemeral: { x25519, mlkem },
  signature: Ed25519.sign(
    callerIdentity.ed25519.privateKey,
    SHA-256(
      "bv-voice-v1-offer" ||
      callId ||
      callerIdentity.x25519.public ||
      callerIdentity.mlkem.public ||
      callerEphemeral.x25519.public ||
      callerEphemeral.mlkem.public ||
      sdpOffer
    )
  ),
  sdpOffer: <compressed SDP, see §6>
}
```

Send the offer to the callee as a regular channel message (encrypted with the existing channel key, indistinguishable from a text message at the server level).

**Step 2 (Callee):** On receipt:
1. Verify the signature against `callerIdentity.ed25519.public` over the exact byte sequence.
2. If signature is invalid, drop the offer. Log locally; do not retry automatically.
3. Generate ephemeral X25519 + ML-KEM-768 keys.
4. **ML-KEM encapsulation:** The callee does **not** have the caller's ML-KEM private key. The caller generated a fresh ML-KEM keypair and sent the public key. The callee encapsulates a 32-byte shared secret against the caller's ML-KEM public key, producing a 1088-byte ciphertext. This is part of ML-KEM: the caller can decapsulate later; the ciphertext is bound to the caller's public key.
5. Construct the answer:

```
CallAnswer = {
  v: 1,
  callId: <same callId as offer>,
  calleeIdentity: { ed25519, x25519, mlkem },
  calleeEphemeral: { x25519, mlkem },
  mlkemCiphertext: <1088 bytes, encapsulated to caller's ML-KEM pub>,
  signature: Ed25519.sign(... same construction as offer, over sdpAnswer),
  sdpAnswer: <compressed SDP>
}
```

Send the answer back as a regular channel message.

**Step 3 (Both parties compute the shared secret):**

Each side computes the same transcript and the same shared secret:

```
transcriptBytes = concat(
  "bv-voice-v1-transcript",
  callId,
  callerIdentity.x25519.public,
  callerIdentity.mlkem.public,
  calleeIdentity.x25519.public,
  calleeIdentity.mlkem.public,
  callerEphemeral.x25519.public,
  callerEphemeral.mlkem.public,
  calleeEphemeral.x25519.public,
  mlkemCiphertext
)

transcriptHash = SHA-256(transcriptBytes)

// X25519 contribution: each side uses the OTHER side's ephemeral public with
// its OWN ephemeral private.
x25519Shared = X25519.scalarMult(
  self.x25519.ephemeral.private,
  peer.x25519.ephemeral.public
)

// ML-KEM contribution:
//   Caller side: decapsulate the ciphertext using caller's ML-KEM private key.
//   Callee side: decapsulate using callee's own ML-KEM private key.
//   (Both sides end up with the same 32-byte shared secret.)
mlkemShared = self.mlkem.ephemeral.private.decapsulate(mlkemCiphertext)

// Concatenate and pass through HKDF-SHA-256.
ikm = x25519Shared || mlkemShared   // 32 + 32 = 64 bytes
kexSecret = HKDF-SHA-256(
  ikm,
  salt: SHA-256("bv-voice-v1-kex-salt"),
  info: "bv-voice-v1-kex-master" || transcriptHash
)
```

Both parties must compute **identical** `kexSecret`. If they differ, the call is MITM'd and must be aborted. See §7 for detection.

### 4.3 Why this is safe

- **Classical security:** Either the X25519 DH or the ML-KEM encapsulation being broken breaks the protocol. ML-KEM-768 is believed secure against classical computers; X25519 is the well-analyzed classical primitive.
- **Post-quantum security:** As long as ML-KEM-768 holds, the protocol is post-quantum secure, because `kexSecret` is HKDF-derived from `mlkemShared` which is information-theoretically bound to the ML-KEM shared secret.
- **Forward secrecy (per call):** Ephemeral private keys are destroyed immediately after `kexSecret` is computed (zeroized). Compromise of the long-term identity keys after the call ends does not reveal `kexSecret` for past calls.
- **Forward secrecy (across calls):** Not provided. See §12.
- **Active MITM defense:** The transcript binds all public keys (long-term AND ephemeral) into the HKDF info. A MITM who substitutes a different ML-KEM public key for either party cannot produce a matching `mlkemCiphertext` that decapsulates to the same `mlkemShared` for both sides. The transcript hash is part of the HKDF info, so even if both sides compute the same wrong `kexSecret` (e.g., both ran against a MITM's public key), the safety number derived from the transcript will differ, and users will see the mismatch.

---

## 5. Key schedule

From `kexSecret` (32 bytes) and `transcriptHash` (32 bytes), derive the SRTP and ratchet keys:

```
kexChainingKey = HKDF-SHA-256(
  ikm: kexSecret,
  salt: transcriptHash,
  info: "bv-voice-v1-chaining"
)
// 32 bytes

rootKey = HKDF-SHA-256(
  ikm: kexChainingKey,
  salt: zero-filled(32),
  info: "bv-voice-v1-root"
)
// 32 bytes

srtpMasterKey = HKDF-SHA-256(
  ikm: rootKey,
  salt: zero-filled(32),
  info: "bv-voice-v1-srtp-key-aes-cm-128"
)
// 16 bytes for AES-CM-128

srtpMasterSalt = HKDF-SHA-256(
  ikm: rootKey,
  salt: zero-filled(32),
  info: "bv-voice-v1-srtp-salt"
)
// 14 bytes (truncate)

srtpGcmKey = HKDF-SHA-256(
  ikm: rootKey,
  salt: zero-filled(32),
  info: "bv-voice-v1-srtp-key-aes-gcm-256"
)
// 32 bytes for AES-256-GCM (used only if negotiated)

srtpGcmSalt = HKDF-SHA-256(
  ikm: rootKey,
  salt: zero-filled(32),
  info: "bv-voice-v1-srtp-salt-aes-gcm"
)
// 12 bytes (truncate)

ratchetRoot = HKDF-SHA-256(
  ikm: rootKey,
  salt: zero-filled(32),
  info: "bv-voice-v1-ratchet-root"
)
// 32 bytes (reserved for in-call ratchet; not used in v1)

safetyNumberSeed = HKDF-SHA-256(
  ikm: rootKey,
  salt: transcriptHash,
  info: "bv-voice-v1-safety-number"
)
// 32 bytes
```

**Why distinct info labels:** Each derived key must be in a separate key space. A future vulnerability in one usage (e.g., SRTP implementation bug) must not leak the channel key or any other derived key. This matches the existing BlackVault channel's pattern (which uses `info: "aes-256-gcm"` and `salt: "blackvault-channel-v1"` for the channel AEAD key).

---

## 6. SDP handling

WebRTC's Session Description Protocol (SDP) carries codec negotiation, ICE candidates, fingerprint, and DTLS setup. The offer and answer are large (typically 1-3 KB after compression).

### 6.1 Compression

SDP is well-known to be repetitive. We compress with **gzip** before signing and before sending. The compression level is standard zlib (level 6).

```
sdpOfferCompressed = gzip(SDP offer string)
sdpAnswerCompressed = gzip(SDP answer string)
```

Stored in the message as base64 of the compressed bytes. (WebCrypto doesn't expose a sync gzip; the implementation will use a small gzip library or `CompressionStream` from the browser's Streams API, which is async-friendly.)

### 6.2 Mandatory SDP attributes

The SDP **must** include these attributes; the receiver rejects the call if any are missing:

- `a=fingerprint:<hash>:<value>` — DTLS-SRTP certificate fingerprint. Hash is always SHA-256.
- `a=rtpmap:<pt> opus/48000/2` — Opus codec, 48 kHz, stereo (browser will negotiate down to mono automatically).
- `a=fmtp:<pt> stereo=0; maxaveragebitrate=32000; usedtx=0; useinbandfec=1; cbr=1` — CBR 32 kbps, DTX off, inband FEC on, **CBR mode mandatory**.
- `a=ice-options:trickle` — trickle ICE (we don't wait for gathering to complete before sending the offer).

The **caller rejects the offer** if `usedtx=0` or `cbr=1` is missing — the threat model requires CBR, and silence suppression is forbidden (see §1.2 and §12).

### 6.3 SDP signature

The signature is computed over the **compressed** SDP, not the plaintext. This binds the signature to the same bytes that travel over the wire, so a MITM cannot swap a different SDP body without invalidating the signature.

```
signed = SHA-256(
  "bv-voice-v1-offer" ||  // or "-answer"
  callId ||
  identity.x25519.public ||
  identity.mlkem.public ||
  ephemeral.x25519.public ||
  ephemeral.mlkem.public ||  // (or mlkemCiphertext, on the answer side)
  sdpCompressed
)
```

The signature itself is the Ed25519 signature over `signed`.

---

## 7. SRTP key derivation and nonce handling

### 7.1 Key derivation per RFC 3711

Given `srtpMasterKey` and `srtpMasterSalt`, the per-session keys are derived as:

```
srtpEncryptionKey = srtpMasterKey        // 16 bytes for AES-CM-128
srtpEncryptionSalt = srtpMasterSalt       // 14 bytes

srtpAuthKey = HMAC-SHA1(srtpMasterKey, 0x00 || "SRTP-AES-CM-128-ICM" || 0x00 || srtpMasterSalt)
// truncate to 20 bytes for HMAC-SHA1-80
```

For AES-256-GCM (RFC 7714), the master key/salt are 32 and 12 bytes respectively; no separate auth key is needed (GCM provides authentication).

### 7.2 Nonce construction

The SRTP IV for each packet is constructed as:

```
IV = (srtpMasterSalt XOR (SSRC || ROC || seq_num)) truncated/padded to 16 bytes
```

Where:
- `SSRC` (4 bytes): the synchronization source identifier from the RTP header
- `ROC` (4 bytes): the 32-bit rollover counter, maintained in software; incremented whenever `seq_num` wraps from 0xFFFF to 0
- `seq_num` (2 bytes): the 16-bit sequence number from the RTP header

This construction (RFC 3711 §4.1.1) is collision-free as long as the ROC is correctly maintained. Loss and reordering do not cause reuse because the SSRC and ROC are stable for a session, and `seq_num` cycles within the ROC.

### 7.3 ROC maintenance

The receiver maintains a 16-bit `s_l` (the highest received sequence number) and a 32-bit `ROC`. On every received packet:
- If `seq_num >= s_l - 2^15`: update `s_l = seq_num`; if `seq_num` wrapped (was near 0xFFFF and now is low), increment `ROC`.
- If `seq_num < s_l - 2^15`: a late packet from a previous ROC window; don't update.

The exact algorithm is RFC 3711 §4.1, with the standard `window_size = 100` for reordering tolerance.

### 7.4 Loss and reorder tolerance

The fuzz harness (see §11) drops 10%, reorders 20%, and duplicates 5% of packets across 1000 trials. The crypto layer must:
- Decrypt successfully for any packet that arrives within the reordering window
- Reject (not crash, not silently accept) any packet that fails the auth tag
- Never reuse a nonce, even under adversarial packet manipulation

---

## 8. Safety number (fingerprint verification)

The safety number is what users compare out-of-band to detect a MITM. It is derived from both parties' long-term public keys AND the per-call KEX transcript, so a MITM who can compromise the per-call KEX but not both long-term keys still produces a different number.

```
safetyNumberSeed = HKDF-SHA-256(
  ikm: rootKey,
  salt: transcriptHash,
  info: "bv-voice-v1-safety-number"
)
// 32 bytes

safetyNumber = SHA-256(
  "bv-voice-v1-safety-final" ||
  callerIdentity.x25519.public ||
  callerIdentity.mlkem.public ||
  calleeIdentity.x25519.public ||
  calleeIdentity.mlkem.public ||
  safetyNumberSeed
)
// 32 bytes -> 256 bits
```

### 8.1 Display format

60 bits of the digest are encoded as 12 emoji, drawn from a 64-emoji alphabet (e.g., the Signal "safety number" emoji set). The display is **12 emojis**, formatted as **6 pairs** for readability: e.g., `🌊🐢🏔️🦊🎪🌙  ⛺🎲🎺🐉🌸🪐`.

The pairing is fixed: bits 0-59 (12 emojis * 5 bits each... actually 60 bits / 5 = 12 emojis from a 32-emoji alphabet; see implementation). **Reviewed separately** for exact emoji alphabet and pair ordering.

### 8.2 UX rules

- The safety number is **mandatory** in the call flow. After a call connects, the UI presents a modal showing both sides' safety number.
- The modal **cannot be dismissed by clicking through**. The only way to close it is to type "yes, verified" or click "Mark verified" after visual or verbal comparison with the peer.
- A "Skip for now" link is present but **always** results in a permanent "Identity not verified" banner on the call screen. The banner is dismissible per-session but re-appears on every new call until verified.
- When the peer's identity key changes (rotated or first-time contact), the call triggers a fresh safety number. The banner re-appears with a hard warning: **"This person's identity has changed. Verify out of band before continuing."**
- A persistent verified-safety-number state is stored locally per peer (long-term public key as the key). Once verified for a peer, subsequent calls with the same peer show the safety number silently; a key change breaks the cache and forces re-verification.

---

## 9. Transport

### 9.1 Media transport

All media is relayed. No direct P2P. The relay is a TURN server with the following non-negotiable configuration:

- **No logs.** The TURN process is started with `--no-log`, stdout/stderr discarded, no syslog, no journald.
- **No retention.** TURN deletes all allocations on session end. No persistent storage of state.
- **No upstream authentication cache.** TURN credentials are short-lived (TTL ≤ 1 hour), generated by the BlackVault Hono server using the coturn `use-auth-secret` mechanism.
- **Disposable.** The TURN server is deployed in a non-operator jurisdiction, with a clear data-handling policy and a documented seizure protocol. (Operator jurisdiction is a deployment decision, not a code decision.)

**ICE config in the SDP offer/answer:**
- `iceServers`: only the relay URL. No STUN-only servers.
- `iceTransportPolicy`: `relay` — forces all media through the relay. Direct P2P is forbidden by the SDP itself.

### 9.2 Transport interface (swappable for v2)

```typescript
interface VoiceTransport {
  readonly kind: "direct-turn" | "tor-onion" | "pluggable-future";
  connect(role: "caller" | "callee", callId: string): Promise<MediaSession>;
  close(): Promise<void>;
}

interface MediaSession {
  // The local microphone stream. Encrypted in-transit; never leaves
  // the device plaintext at any layer the application can see.
  localStream: MediaStream;

  // The remote stream. Decryption happens inside the SRTP layer; the
  // application sees only the resulting audio.
  remoteStream: MediaStream;

  onStateChange: (state: "connecting" | "connected" | "disconnected" | "failed") => void;
  onIdentityMismatch: () => void;  // safety number mismatch
  close(): Promise<void>;
}
```

In v1, only `direct-turn` is implemented. The interface exists so v2 (Tor onion for media) can swap in without touching call logic.

### 9.3 Signaling transport

Signaling (offer, answer, hangup, rekey) travels over the existing BlackVault text channel. This is encrypted by the existing channel key, but **the server can see**:
- Which channel the message was sent in
- Which agent sent the message
- When the message was sent
- The approximate message size

This is the **v1 metadata leak** acknowledged in §1 and documented in §12.

---

## 10. Failure modes

### 10.1 KEX mismatch (safety number does not match)

**Detection:** Each side independently computes the safety number from the transcript. If a MITM has substituted any public key, the two sides compute different `kexSecret` and therefore different safety numbers.

**Behavior:**
- Both sides immediately drop the call. No audio exchange.
- Both sides display: **"Identity verification failed. This call may be intercepted. Do not proceed."**
- The error is logged locally; the BlackVault server is not notified (no useful server-side action).
- The user must re-initiate the call, and the new call will produce a new (correct) safety number unless the MITM is still in the path.

### 10.2 Relay failure

**Detection:** ICE connection state becomes `failed` within the standard WebRTC timeout (configurable; default 30s).

**Behavior:**
- The call is torn down locally.
- A reconnection attempt is made with exponential backoff: 2s, 4s, 8s, 16s, 32s, max 5 attempts.
- If reconnection fails, the call ends with a "Relay unavailable" error.
- No automatic redial; the user must re-initiate.

### 10.3 Mid-call key rotation (NOT in v1)

The `CallRekey` message type is reserved but unused. v1 has no in-call ratchet. If the threat-model assumption of "harvest-now-decrypt-later" is taken seriously, an in-call ratchet is a defense-in-depth measure (so a session-key compromise mid-call does not retroactively reveal the entire call). v1 leaves this as a roadmap item because the v1 ephemeral keys are already short-lived (single call).

### 10.4 Hangup races

If both sides hang up at the same time, the second `CallHangup` is a no-op. If a `CallHangup` arrives before the `CallAnswer`, the offer is cancelled and the caller's UI returns to the channel.

### 10.5 Loss of text channel connectivity during a call

The call does not depend on the text channel for media (the relay handles that). Signaling messages queued during the channel outage (e.g., a late `CallHangup` from the peer) are dropped on the next reconnect. The user is informed that the call ended without a clean hangup; this is a normal edge case, not a security failure.

---

## 11. Test vector coverage

The reference implementation ships with:

1. **KEX KAT** — known inputs for ephemeral X25519 + ML-KEM-768 keys, known transcript hash, known `kexSecret` and key schedule outputs. Allows any reviewer to verify the key derivation matches this spec.

2. **SRTP KAT (AES-CM-128)** — known `srtpMasterKey`, `srtpMasterSalt`, plaintext, sequence number, SSRC, expected ciphertext + auth tag, and expected ROC behavior on wraparound.

3. **SRTP KAT (AES-256-GCM)** — same, for the optional cipher suite.

4. **Loss/reorder fuzz harness** — 1000 trials, each with 10% drop, 20% reorder within a 100-packet window, 5% duplication, against a known SRTP session. Asserts:
   - All packets that arrive within the reordering window decrypt to the expected plaintext
   - Packets that fail the auth tag are rejected (no crash, no silent accept)
   - No nonce is ever used twice (assert by instrumenting the nonce derivation)

5. **Safety number KAT** — known transcript, known long-term public keys, expected 256-bit digest. Allows reviewers to verify the fingerprint matches across implementations.

6. **Transcript binding test** — two parties with the same inputs compute the same `kexSecret`; a third party with a different `mlkemCiphertext` or different ephemeral public key does not.

---

## 12. Known limitations vs. the threat model

This section is **honest**, not marketing. These are the gaps.

### 12.1 Endpoint compromise (out of scope by spec, listed for completeness)

If either endpoint is compromised (keylogger, screen capture, malware that reads the WebCrypto key material from memory), no protocol feature protects the call. The user should treat any device that has been used for a BlackVault call with the same suspicion as the call itself.

### 12.2 No forward secrecy across calls (v1 only)

v1 uses fresh ephemeral keys per call, so each call is forward-secret. **However**, compromise of the long-term identity keys during a call exposes that call. v2 (post-quantum identity keys with sub-key rotation, or a "double ratchet" per contact) would close this.

### 12.3 mlock gap (audio buffers in OS page cache)

JavaScript does not expose `mlock` natively. Decrypted audio buffers may be swapped to disk by the OS under memory pressure. A determined adversary with physical access to a running device could recover these buffers.

**Mitigation roadmap (not in v1):** deploy with COOP/COEP headers, move crypto into a WebAssembly worker with `mlock` of the Wasm linear memory, zero all Wasm pages after use.

**v1 mitigation:** zero JavaScript typed arrays immediately after use. This catches the common case but not OS-level swap.

### 12.4 Signaling metadata leak (acknowledged v1 limitation)

The BlackVault server sees:
- A message of type `voice.call.offer` (or `.answer`, `.hangup`) sent in a given channel at a given time from agent X to agent Y
- The compressed SDP body size (typically 1-3 KB after gzip)
- The fact that X initiated a call to Y at time T

**It does NOT see:** the SDP contents, the keys, the call audio, the safety number, or any of the message body beyond size and type.

A sealed-sender-style delivery layer (decoupling message sender identity from the relay path) is **phase 2** and protects both text and voice. This is on the roadmap.

### 12.5 Single relay sees call timing and packet sizes

The TURN relay can observe: call start, call end, packet sizes, packet rate, total bytes. It cannot see content. The metadata still allows a traffic analyst to infer "agents X and Y are talking" from the timing pattern.

**Mitigation roadmap:** Tor onion routing for media, requiring multiple relays to collude. Not in v1.

### 12.6 No defense against malicious relay modifying packet timing

The TURN relay can delay or drop packets. WebRTC's NACK and PLI mechanisms detect packet loss and request retransmits, but a determined relay can selectively drop to degrade audio quality without preventing the call. This is a denial-of-service against call quality, not a confidentiality break.

### 12.7 Browser-level audio fingerprinting

WebRTC's audio processing (AGC, echo cancellation, noise suppression) is OS- and browser-dependent. A passive observer of the SRTP stream (which we have shown the relay cannot be) could potentially fingerprint the browser. Since the relay cannot decrypt, this is theoretical, not a v1 concern.

### 12.8 Identity key storage at rest

v1 stores identity keys in browser localStorage, alongside channel keys. Anyone with local access to the device can extract them. The roadmap item is passphrase-derived encryption of localStorage (Argon2id + AES-GCM).

### 12.9 No formal audit

This protocol is specified by Mavis, an LLM agent, without formal cryptographic review. The components used (Ed25519, X25519, ML-KEM-768, HKDF-SHA-256, SRTP) are themselves well-vetted, but the **combiner construction** (X25519 || ML-KEM → HKDF → key schedule) and the **transcript binding** (which public keys go into the SHA-256) have not been formally analyzed.

**Before this protocol is used for anything beyond personal experimentation, it requires review by a credentialed cryptographer.** This is not a rubber-stamp. The construction draws on standard patterns (X3DH, Noise), but the specific choices in §4.2 have not been formally verified.

---

## 13. Operator hardening (what the BlackVault server should NOT log)

This is a separate document (`OPERATOR-HARDENING.md`) but the key points are:

- **No HTTP access logs** beyond what Render's edge gives you (and that should be disabled in the Render dashboard if possible).
- **No SSE connection metadata** beyond what the existing session lookup needs.
- **No per-message metadata** beyond what's in the DB (channelId, agentId, createdAt) — and that is already minimal.
- **No ICE candidate paths, SDP bodies, or anything from the call signaling.** That data is in the channel messages, encrypted, never seen by the server.
- **No WebRTC peer-connection statistics.**
- **`Cache-Control: no-store`** on all `/api/*` responses.
- **No persistent log file**; stdout is the only thing that escapes, and that should be at `error` level only.
- **Log forwarder configured to drop anything below `error`.**

See `OPERATOR-HARDENING.md` for the full list with concrete configuration snippets.

---

## 14. Open questions for the implementer

These are explicitly out of scope for the protocol but the implementer needs to decide them:

1. **Emoji alphabet for the safety number display.** Spec says "12 emoji pairs." The exact 32- or 64-emoji alphabet is a UI decision. Recommendation: 60 bits, 12 emojis from a 32-emoji alphabet (5 bits each, but only 32 used), formatted as 6 pairs. **Sign-off needed before implementation.**

2. **Rekey cadence for in-call ratchet (v2).** Not in v1, but the `CallRekey` message type is reserved. v2 should specify the cadence (per N packets? per M seconds? on every packet?).

3. **Compression library.** `pako` (gzip) is the obvious choice. Stream-based compression in the browser via `CompressionStream` is also available; the implementation will choose based on bundle size and async ergonomics.

4. **Identity key serialization.** JSON? CBOR? Custom? The wire format for the identity bundle needs to be specified before code is written.

These are recorded here so the implementation phase knows what it needs to lock down.
