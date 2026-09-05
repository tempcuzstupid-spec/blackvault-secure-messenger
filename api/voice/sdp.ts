// SDP compression for the signaling payload. Per §6.1, we compress
// the SDP body with gzip before signing and before sending. The
// implementation uses a small, vetted gzip lib (pako) for the Node
// side; on the browser side, CompressionStream is the right tool
// (gzip is supported by the spec).
//
// For the reference implementation we use pako, which is a pure-JS
// port of zlib and has been audited.

import { gzip, ungzip } from "pako";
import { fromB64, toB64, type ByteSeq } from "./kex";

export function compressSdp(sdp: string): string {
  // pako.gzip expects a Uint8Array of UTF-8 bytes
  const enc = new TextEncoder();
  const bytes = enc.encode(sdp);
  const compressed = gzip(bytes, { level: 6 });
  return toB64(compressed);
}

export function decompressSdp(b64: string): string {
  const dec = new TextDecoder();
  const compressed = fromB64(b64);
  const decompressed = ungzip(compressed);
  return dec.decode(decompressed);
}
