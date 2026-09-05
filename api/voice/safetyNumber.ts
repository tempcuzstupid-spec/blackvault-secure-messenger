// Per PROTOCOL.md §8.1: render the 32-byte safety number digest as
// 12 emojis drawn from a 64-emoji alphabet (6 bits each, displayed
// as 6 pairs of 2 for readability).
//
// 64 emojis chosen from the same family Signal uses for safety
// numbers, with substitutions to avoid ambiguous glyphs (no 🦀/🐞
// because of cross-platform rendering issues; no I/O/0/1/2/3/4/5/6/7/8/9
// because we are not using digits).

export const SAFETY_EMOJI_ALPHABET: readonly string[] = [
  "🌊", "🐢", "🏔️", "🦊", "🎪", "🌙", "⛺", "🎲",
  "🎺", "🐉", "🌸", "🪐", "🍀", "🌵", "🐙", "🦋",
  "🐳", "🦅", "🦉", "🐺", "🦌", "🦝", "🐝", "🐬",
  "🌷", "🌹", "🌻", "🌼", "🌺", "🌾", "🍂", "🍁",
  "🌍", "🌎", "⭐", "🌟", "✨", "⚡", "🔥", "💧",
  "🎯", "🎸", "🎺", "🎻", "🎨", "🎭", "🎲", "🎰",
  "🏀", "⚽", "🏈", "🎾", "🏐", "🏓", "🏸", "🥊",
  "🚗", "🚕", "🚙", "🚌", "🚎", "🏎️", "🚓", "🚑",
] as const;

if (SAFETY_EMOJI_ALPHABET.length !== 64) {
  throw new Error(`SAFETY_EMOJI_ALPHABET must have 64 entries, has ${SAFETY_EMOJI_ALPHABET.length}`);
}

/**
 * Read `n` bits starting at bit offset `bitPos` from `buf` (big-endian
 * across the bit array). Used internally by the emoji renderer.
 */
function readBits(buf: Uint8Array, bitPos: number, n: number): number {
  let v = 0;
  for (let i = 0; i < n; i++) {
    const byteIdx = Math.floor((bitPos + i) / 8);
    const bitInByte = (bitPos + i) % 8;
    v = (v << 1) | ((buf[byteIdx] >>> (7 - bitInByte)) & 1);
  }
  return v;
}

/**
 * Encode a byte sequence as a 12-emoji string (6 bits per emoji from
 * a 64-emoji alphabet). Uses the first 9 bytes of the digest (72 bits
 * = 12 × 6). The remaining 23 bytes are ignored.
 *
 * Display format: 6 pairs of 2 emojis, separated by a single space.
 * E.g., "🌊🐢 🏔️🦊 🎪🌙 ⛺🎲 🎺🐉 🌸🪐".
 */
export function renderSafetyNumber(digest: Uint8Array): string {
  if (digest.length < 9) throw new Error("digest must be at least 9 bytes");
  const pairs: string[] = [];
  let bitPos = 0;
  for (let p = 0; p < 6; p++) {
    let pair = "";
    for (let i = 0; i < 2; i++) {
      const idx = readBits(digest, bitPos, 6);
      pair += SAFETY_EMOJI_ALPHABET[idx];
      bitPos += 6;
    }
    pairs.push(pair);
  }
  return pairs.join(" ");
}
