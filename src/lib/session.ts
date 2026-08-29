// Session token storage + channel label/invite-code memory.
// Invite codes are kept in localStorage so channel keys can be re-derived
// after reload; they never leave the device except as SHA-256 hashes.

const TOKEN_KEY = "bv.session";
const TAG_KEY = "bv.agentTag";
const CHAN_KEY = "bv.channels";

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? "";
}
export function setSession(token: string, tag: string) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(TAG_KEY, tag);
}
export function getAgentTag(): string {
  return localStorage.getItem(TAG_KEY) ?? "";
}
export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(TAG_KEY);
}

export type LocalChannel = { id: number; label: string; inviteCode: string };

export function getLocalChannels(): LocalChannel[] {
  try {
    return JSON.parse(localStorage.getItem(CHAN_KEY) ?? "[]");
  } catch {
    return [];
  }
}

export function rememberChannel(ch: LocalChannel) {
  const list = getLocalChannels().filter((c) => c.id !== ch.id);
  list.push(ch);
  localStorage.setItem(CHAN_KEY, JSON.stringify(list));
}
