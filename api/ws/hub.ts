// Server-side WebSocket hub. One singleton per Node process. Clients connect
// at /ws?token=<sessionToken>. On open, the server validates the token,
// looks up the agent's channel memberships, and subscribes the connection
// to those channels. The client can also send `{"type":"subscribe","channelId":N}`
// to subscribe to a channel it just joined.
//
// The hub never sees plaintext message content. It only forwards opaque
// event payloads that the broadcasting side already serialized (typically
// the public-shape message object, which is ciphertext + nonce + sender
// tag — all of which the server already had to know about to store).

import { eq } from "drizzle-orm";
import { getDb } from "../queries/connection";
import { sessions, memberships } from "@db/schema";

type Conn = { ws: import("ws").WebSocket; agentId: number };

class WsHub {
  private conns = new Map<import("ws").WebSocket, { agentId: number; channels: Set<number> }>();
  // channelId -> set of conns subscribed to it (derived from conns map)

  addConn(ws: import("ws").WebSocket, agentId: number, initialChannels: number[]) {
    this.conns.set(ws, { agentId, channels: new Set(initialChannels) });
  }

  removeConn(ws: import("ws").WebSocket) {
    this.conns.delete(ws);
  }

  subscribe(ws: import("ws").WebSocket, channelId: number) {
    const c = this.conns.get(ws);
    if (c) c.channels.add(channelId);
  }

  unsubscribe(ws: import("ws").WebSocket, channelId: number) {
    const c = this.conns.get(ws);
    if (c) c.channels.delete(channelId);
  }

  /**
   * Broadcast an event to every connection subscribed to `channelId`,
   * except the optional `except` connection (used so a sender doesn't
   * get a redundant echo when they already have the local optimistic
   * update).
   */
  broadcast(channelId: number, event: unknown, except?: import("ws").WebSocket) {
    const payload = JSON.stringify(event);
    for (const [ws, state] of this.conns) {
      if (ws === except) continue;
      if (!state.channels.has(channelId)) continue;
      if (ws.readyState !== 1) continue; // OPEN
      try { ws.send(payload); } catch { /* swallow — onClose will clean up */ }
    }
  }

  /** Broadcast to a specific agent across all their open connections. */
  broadcastToAgent(agentId: number, event: unknown) {
    const payload = JSON.stringify(event);
    for (const [ws, state] of this.conns) {
      if (state.agentId !== agentId) continue;
      if (ws.readyState !== 1) continue;
      try { ws.send(payload); } catch {}
    }
  }

  presenceSnapshot(channelId: number): number[] {
    const set = new Set<number>();
    for (const [, state] of this.conns) {
      if (state.channels.has(channelId)) set.add(state.agentId);
    }
    return [...set];
  }

  memberCount(channelId: number): number {
    let n = 0;
    for (const [, state] of this.conns) {
      if (state.channels.has(channelId)) n++;
    }
    return n;
  }
}

export const wsHub = new WsHub();

/**
 * Validate a session token and return the agentId, or null if invalid.
 * Mirrors the auth used by tRPC authedQuery so the WS path is consistent.
 */
export async function agentFromToken(token: string): Promise<number | null> {
  if (!token) return null;
  const db = getDb();
  const [row] = await db
    .select({ id: sessions.id, agentId: sessions.agentId, expiresAt: sessions.expiresAt })
    .from(sessions)
    .where(eq(sessions.token, token))
    .limit(1);
  if (!row) return null;
  if (row.expiresAt.getTime() < Date.now()) return null;
  return row.agentId;
}

export async function channelIdsForAgent(agentId: number): Promise<number[]> {
  const db = getDb();
  const rows = await db
    .select({ channelId: memberships.channelId })
    .from(memberships)
    .where(eq(memberships.agentId, agentId));
  return rows.map((r) => r.channelId);
}
