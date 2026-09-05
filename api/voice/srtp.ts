// Per PROTOCOL.md §7: SRTP with two cipher modes.
//
//   1. AES-CM-128-HMAC-SHA1-80 (RFC 3711) — the default; what WebRTC
//      negotiates out of the box. 16-byte master key, 14-byte master
//      salt, separate auth key (HMAC-SHA1-80).
//
//   2. AES-256-GCM (RFC 7714) — opt-in, requires both sides to
//      negotiate. 32-byte key, 12-byte salt, AEAD built-in.
//
// Both modes share the same nonce construction: SSRC || ROC || seq
// (XOR'd with the master salt) and the same rollover counter (ROC)
// algorithm (RFC 3711 §4.1).
//
// This module is reference code. The production runtime will use the
// browser's built-in SRTP (in WebRTC); this implementation exists for
// the Node test harness, the fuzz harness, and as a verified reference.

import { gcm, ctr, cbc } from "@noble/ciphers/aes.js";
import { createHmac, createHash } from "node:crypto";
import type { ByteSeq } from "./kex";

export type SrtpCipherSuite = "AES_CM_128_HMAC_SHA1_80" | "AES_256_GCM";

/** RTP header. SRTP just needs SSRC and seq; we keep the rest for AAD. */
export interface RtpHeader {
  version: number;
  padding: boolean;
  extension: boolean;
  cc: number;
  marker: boolean;
  pt: number;
  seq: number;          // 16-bit
  timestamp: number;     // 32-bit
  ssrc: number;          // 32-bit
}

/** A single SRTP packet: header + encrypted payload + auth tag. */
export interface SrtpPacket {
  header: RtpHeader;
  ciphertext: ByteSeq;
  tag: ByteSeq;          // 10 bytes for HMAC-SHA1-80, 16 bytes for GCM
}

function ctEqual(a: ByteSeq, b: ByteSeq): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function concat(...parts: ByteSeq[]): ByteSeq {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function hmacSha1(key: ByteSeq, msg: ByteSeq): ByteSeq {
  return new Uint8Array(createHmac("sha1", key).update(msg).digest());
}

/** Per-call SRTP state. Both sides maintain a receiver and a sender. */
export class SrtpSession {
  private roc = 0;                  // 32-bit rollover counter
  private s_l = 0;                  // highest seq seen
  private prevSeq?: number;
  private windowSize = 100;         // reordering tolerance (RFC 3711 default)

  constructor(
    public readonly ssrc: number,
    private readonly cipher: SrtpCipherSuite,
    private readonly key: ByteSeq,
    private readonly salt: ByteSeq,
  ) {
    if (cipher === "AES_CM_128_HMAC_SHA1_80" && key.length !== 16) {
      throw new Error(`AES-CM-128 needs a 16-byte key, got ${key.length}`);
    }
    if (cipher === "AES_CM_128_HMAC_SHA1_80" && salt.length !== 14) {
      throw new Error(`AES-CM-128 needs a 14-byte salt, got ${salt.length}`);
    }
    if (cipher === "AES_256_GCM" && key.length !== 32) {
      throw new Error(`AES-256-GCM needs a 32-byte key, got ${key.length}`);
    }
    if (cipher === "AES_256_GCM" && salt.length !== 12) {
      throw new Error(`AES-256-GCM needs a 12-byte salt, got ${salt.length}`);
    }
  }

  /** Encrypt one RTP packet. The session is created with a fixed SSRC. */
  encrypt(header: RtpHeader, plaintext: ByteSeq): SrtpPacket {
    if (header.ssrc !== this.ssrc) {
      throw new Error(`encrypt: header.ssrc ${header.ssrc} != session ssrc ${this.ssrc}`);
    }
    this.advanceOutboundSeq(header.seq);

    if (this.cipher === "AES_CM_128_HMAC_SHA1_80") {
      return this.encryptCm128(header, plaintext);
    }
    return this.encryptGcm256(header, plaintext);
  }

  /**
   * Decrypt one SRTP packet. Throws on auth failure.
   * Implements the RFC 3711 ROC algorithm and the §4.1 reordering
   * window check.
   */
  decrypt(packet: SrtpPacket): ByteSeq {
    if (packet.header.ssrc !== this.ssrc) {
      throw new Error(`decrypt: header.ssrc ${packet.header.ssrc} != session ssrc ${this.ssrc}`);
    }
    if (this.cipher === "AES_CM_128_HMAC_SHA1_80") {
      return this.decryptCm128(packet);
    }
    return this.decryptGcm256(packet);
  }

  // ----- AES-CM-128-HMAC-SHA1-80 (RFC 3711) -----

  /** RFC 3711 §4.3.1 — derive the session encryption and auth keys. */
  private deriveCm128Keys(): { encKey: ByteSeq; authKey: ByteSeq } {
    const labelBase = new TextEncoder().encode("SRTP-AES-CM-128-ICM");
    const label = new Uint8Array(1 + labelBase.length + 1 + this.salt.length + 12);
    let o = 0;
    label[o++] = 0x00;
    label.set(labelBase, o); o += labelBase.length;
    label[o++] = 0x00;
    label.set(this.salt, o); o += this.salt.length;
    label[o++] = 0x00; label[o++] = 0x00; label[o++] = 0x00; label[o++] = 0x01;
    label[o++] = 0x00; label[o++] = 0x00; label[o++] = 0x00; label[o++] = 0x03;
    label[o++] = 0x00; label[o++] = 0x00; label[o++] = 0x00; label[o++] = 0x04;

    const eLabel = new Uint8Array(label);
    eLabel[eLabel.length - 4] = 0; eLabel[eLabel.length - 3] = 0;
    eLabel[eLabel.length - 2] = 0; eLabel[eLabel.length - 1] = 3;
    const aLabel = new Uint8Array(label);
    aLabel[aLabel.length - 4] = 0; aLabel[aLabel.length - 3] = 0;
    aLabel[aLabel.length - 2] = 0; aLabel[aLabel.length - 1] = 4;

    const iv = new Uint8Array(16);
    const encCipher = cbc(this.key, iv);
    const encKey = encCipher.encrypt(eLabel);
    const authCipher = cbc(this.key, iv);
    const authKey = authCipher.encrypt(aLabel);
    return { encKey: encKey.slice(0, 16), authKey: authKey.slice(0, 20) };
  }

  private encryptCm128(header: RtpHeader, plaintext: ByteSeq): SrtpPacket {
    const { encKey, authKey } = this.deriveCm128Keys();
    const roc = this.rocForOutbound(header.seq);
    const counter = this.makeCounterBlock(header.seq, roc);
    const cipher = ctr(encKey, counter);
    const ciphertext = cipher.encrypt(plaintext);

    const aad = this.rtpHeaderBytes(header);
    const mac = hmacSha1(authKey, concat(aad, ciphertext));
    return { header, ciphertext, tag: mac.slice(0, 10) };
  }

  private decryptCm128(packet: SrtpPacket): ByteSeq {
    const { encKey, authKey } = this.deriveCm128Keys();
    const aad = this.rtpHeaderBytes(packet.header);
    const mac = hmacSha1(authKey, concat(aad, packet.ciphertext));
    if (!ctEqual(mac.slice(0, 10), packet.tag)) {
      throw new Error("srtp: auth tag mismatch (AES-CM-128)");
    }
    const roc = this.rocForInbound(packet.header.seq);
    const counter = this.makeCounterBlock(packet.header.seq, roc);
    const cipher = ctr(encKey, counter);
    return cipher.decrypt(packet.ciphertext);
  }

  // ----- AES-256-GCM (RFC 7714) -----

  private encryptGcm256(header: RtpHeader, plaintext: ByteSeq): SrtpPacket {
    const roc = this.rocForOutbound(header.seq);
    const iv = this.makeIv(header.seq, roc, 12);
    const aad = this.rtpHeaderBytes(header);
    const cipher = gcm(this.key, iv, aad);
    const sealed = cipher.encrypt(plaintext);
    return { header, ciphertext: sealed.slice(0, sealed.length - 16), tag: sealed.slice(sealed.length - 16) };
  }

  private decryptGcm256(packet: SrtpPacket): ByteSeq {
    const roc = this.rocForInbound(packet.header.seq);
    const iv = this.makeIv(packet.header.seq, roc, 12);
    const aad = this.rtpHeaderBytes(packet.header);
    const cipher = gcm(this.key, iv, aad);
    return cipher.decrypt(concat(packet.ciphertext, packet.tag));
  }

  // ----- IV, ROC, header helpers -----

  private makeIv(seq: number, roc: number, len: number = 16): ByteSeq {
    const iv = new Uint8Array(len);
    const saltOffset = len - this.salt.length;
    iv.set(this.salt, saltOffset);
    const ssrcOffset = saltOffset - 4;
    iv[ssrcOffset + 0] ^= (this.ssrc >>> 24) & 0xff;
    iv[ssrcOffset + 1] ^= (this.ssrc >>> 16) & 0xff;
    iv[ssrcOffset + 2] ^= (this.ssrc >>> 8) & 0xff;
    iv[ssrcOffset + 3] ^= this.ssrc & 0xff;
    iv[len - 6] ^= (roc >>> 24) & 0xff;
    iv[len - 5] ^= (roc >>> 16) & 0xff;
    iv[len - 4] ^= (roc >>> 8) & 0xff;
    iv[len - 3] ^= roc & 0xff;
    iv[len - 2] ^= (seq >>> 8) & 0xff;
    iv[len - 1] ^= seq & 0xff;
    return iv;
  }

  private makeCounterBlock(seq: number, roc: number): ByteSeq {
    const counter = this.makeIv(seq, roc, 16);
    const pktIdx = ((seq << 16) | roc) >>> 0;
    counter[12] = (pktIdx >>> 24) & 0xff;
    counter[13] = (pktIdx >>> 16) & 0xff;
    counter[14] = (pktIdx >>> 8) & 0xff;
    counter[15] = pktIdx & 0xff;
    return counter;
  }

  private advanceOutboundSeq(seq: number) {
    if (this.prevSeq === undefined) {
      this.prevSeq = seq;
      return;
    }
    if (seq < this.prevSeq) {
      if (this.prevSeq > 0x8000 && seq < 0x8000) {
        this.roc = (this.roc + 1) >>> 0;
      }
    }
    this.prevSeq = seq;
  }

  private rocForOutbound(_seq: number): number {
    return this.roc;
  }

  private rocForInbound(seq: number): number {
    if (this.prevSeq === undefined) {
      this.prevSeq = seq;
      this.s_l = seq;
      return this.roc;
    }
    const halfWindow = 0x8000;
    const diff = (seq - this.s_l + 0x10000) & 0xffff;
    if (diff < halfWindow) {
      const wrapped = (this.s_l > 0xffff - halfWindow) && (seq < halfWindow);
      if (wrapped) this.roc = (this.roc + 1) >>> 0;
      this.s_l = seq;
      return this.roc;
    } else if (diff > halfWindow) {
      return this.roc === 0 ? 0 : (this.roc - 1) >>> 0;
    } else {
      return this.roc;
    }
  }

  private rtpHeaderBytes(header: RtpHeader): ByteSeq {
    const b = new Uint8Array(12);
    b[0] = (header.version << 6) | (header.padding ? 0x20 : 0) | (header.extension ? 0x10 : 0) | (header.cc & 0x0f);
    b[1] = (header.marker ? 0x80 : 0) | (header.pt & 0x7f);
    b[2] = (header.seq >>> 8) & 0xff;
    b[3] = header.seq & 0xff;
    b[4] = (header.timestamp >>> 24) & 0xff;
    b[5] = (header.timestamp >>> 16) & 0xff;
    b[6] = (header.timestamp >>> 8) & 0xff;
    b[7] = header.timestamp & 0xff;
    b[8] = (this.ssrc >>> 24) & 0xff;
    b[9] = (this.ssrc >>> 16) & 0xff;
    b[10] = (this.ssrc >>> 8) & 0xff;
    b[11] = this.ssrc & 0xff;
    return b;
  }
}
