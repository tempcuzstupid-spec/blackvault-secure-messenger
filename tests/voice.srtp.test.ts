// SRTP round-trip and ROC behavior tests.

import { describe, it, expect } from "vitest";
import { SrtpSession, type RtpHeader } from "../api/voice/srtp";
import { randomBytes } from "../api/voice/kex";

function header(ssrc: number, seq: number, ts: number = 0): RtpHeader {
  return {
    version: 2,
    padding: false,
    extension: false,
    cc: 0,
    marker: false,
    pt: 96, // dynamic payload type for Opus
    seq,
    timestamp: ts,
    ssrc,
  };
}

describe("srtp: AES-CM-128 round-trip", () => {
  it("encrypts and decrypts a packet back to its plaintext", () => {
    const ssrc = 0x12345678;
    const key = randomBytes(16);
    const salt = randomBytes(14);
    const sender = new SrtpSession(ssrc, "AES_CM_128_HMAC_SHA1_80", key, salt);
    const receiver = new SrtpSession(ssrc, "AES_CM_128_HMAC_SHA1_80", key, salt);
    const plaintext = new TextEncoder().encode("Hello SRTP, this is a 100-byte payload that we want to round-trip through SRTP. The payload is longer than one AES block so we exercise the CTR mode across two blocks and ensure no corner case is hit on the block boundary or near the 16-byte counter wraparound point..");
    const packet = sender.encrypt(header(ssrc, 0x0001, 0xCAFEBABE), plaintext);
    const decrypted = receiver.decrypt(packet);
    expect(decrypted).toEqual(plaintext);
  });

  it("rejects a packet with a corrupted ciphertext", () => {
    const ssrc = 0x12345678;
    const key = randomBytes(16);
    const salt = randomBytes(14);
    const sender = new SrtpSession(ssrc, "AES_CM_128_HMAC_SHA1_80", key, salt);
    const receiver = new SrtpSession(ssrc, "AES_CM_128_HMAC_SHA1_80", key, salt);
    const plaintext = new TextEncoder().encode("payload");
    const packet = sender.encrypt(header(ssrc, 0x0001), plaintext);
    // Flip one bit of the ciphertext
    packet.ciphertext[0] ^= 0x01;
    expect(() => receiver.decrypt(packet)).toThrow(/auth tag mismatch/);
  });

  it("rejects a packet with the wrong SSRC", () => {
    const key = randomBytes(16);
    const salt = randomBytes(14);
    const sender = new SrtpSession(0x11111111, "AES_CM_128_HMAC_SHA1_80", key, salt);
    const receiver = new SrtpSession(0x22222222, "AES_CM_128_HMAC_SHA1_80", key, salt);
    const packet = sender.encrypt(header(0x11111111, 0x0001), new TextEncoder().encode("p"));
    expect(() => receiver.decrypt(packet)).toThrow(/ssrc/);
  });
});

describe("srtp: ROC behavior", () => {
  it("accepts a reordering within the window", () => {
    const ssrc = 0x12345678;
    const key = randomBytes(16);
    const salt = randomBytes(14);
    const sender = new SrtpSession(ssrc, "AES_CM_128_HMAC_SHA1_80", key, salt);
    const receiver = new SrtpSession(ssrc, "AES_CM_128_HMAC_SHA1_80", key, salt);
    const plaintext = (i: number) => new TextEncoder().encode(`msg ${i}`);

    const pkts = [
      sender.encrypt(header(ssrc, 0x0001, 1), plaintext(1)),
      sender.encrypt(header(ssrc, 0x0002, 2), plaintext(2)),
      sender.encrypt(header(ssrc, 0x0003, 3), plaintext(3)),
    ];
    // Reorder: deliver 2, 1, 3
    expect(receiver.decrypt(pkts[1])).toEqual(plaintext(2));
    expect(receiver.decrypt(pkts[0])).toEqual(plaintext(1));
    expect(receiver.decrypt(pkts[2])).toEqual(plaintext(3));
  });

  it("increments ROC on seq wraparound and decrypts the next packet correctly", () => {
    const ssrc = 0x12345678;
    const key = randomBytes(16);
    const salt = randomBytes(14);
    const sender = new SrtpSession(ssrc, "AES_CM_128_HMAC_SHA1_80", key, salt);
    const receiver = new SrtpSession(ssrc, "AES_CM_128_HMAC_SHA1_80", key, salt);
    const plaintext = (i: number) => new TextEncoder().encode(`msg ${i}`);

    // Send 0xFFFE, 0xFFFF, then wrap to 0x0000, then 0x0001
    const pkts = [
      sender.encrypt(header(ssrc, 0xFFFE, 1), plaintext(0xFFFE)),
      sender.encrypt(header(ssrc, 0xFFFF, 2), plaintext(0xFFFF)),
      sender.encrypt(header(ssrc, 0x0000, 3), plaintext(0x0000)),
      sender.encrypt(header(ssrc, 0x0001, 4), plaintext(0x0001)),
    ];
    // Deliver in order; each must decrypt correctly
    for (let i = 0; i < pkts.length; i++) {
      expect(receiver.decrypt(pkts[i])).toEqual(plaintext([0xFFFE, 0xFFFF, 0x0000, 0x0001][i]));
    }
  });
});

describe("srtp: AES-256-GCM round-trip", () => {
  it("encrypts and decrypts a packet back to its plaintext", () => {
    const ssrc = 0xCAFEBABE;
    const key = randomBytes(32);
    const salt = randomBytes(12);
    const sender = new SrtpSession(ssrc, "AES_256_GCM", key, salt);
    const receiver = new SrtpSession(ssrc, "AES_256_GCM", key, salt);
    const plaintext = new TextEncoder().encode("GCM-mode SRTP payload, also 100 bytes or so to exercise the GCM path across multiple blocks and the tag generation/verification....");
    const packet = sender.encrypt(header(ssrc, 0x0001), plaintext);
    const decrypted = receiver.decrypt(packet);
    expect(decrypted).toEqual(plaintext);
  });

  it("rejects a packet with a corrupted tag", () => {
    const ssrc = 0xCAFEBABE;
    const key = randomBytes(32);
    const salt = randomBytes(12);
    const sender = new SrtpSession(ssrc, "AES_256_GCM", key, salt);
    const receiver = new SrtpSession(ssrc, "AES_256_GCM", key, salt);
    const packet = sender.encrypt(header(ssrc, 0x0001), new TextEncoder().encode("p"));
    packet.tag[0] ^= 0x01;
    expect(() => receiver.decrypt(packet)).toThrow();
  });
});
