// Server-side fan-out hub. One singleton per Node process. Each
// authenticated connection (currently SSE) registers itself here, gets
// subscribed to its agent's existing channel memberships, and receives
// any events broadcast to those channels.
//
// The hub never sees plaintext message content. It only forwards
// opaque event payloads — typically the public-shape message object,
// which is ciphertext + nonce + sender tag — that the broadcasting
// side already serialized (the server always has this info anyway
// because it has to store it).

import type { Response } from "express";
import { eq } from "drizzle-orm";
import { getDb } from "../queries/connection";
import { sessions, memberships } from "@db/schema";

type Conn = {
  agentId: number;
  channels: Set<number>;
  send: (event: unknown) => void;
  close: () => void;
  /** Set to true when the connection is gone; hub will GC it. */
  alive: boolean;
};

class SseHub {
  private conns = new Set<Conn>();

  add(conn: Conn) {
    this.conns.add(conn);
  }

  remove(conn: Conn) {
    this.conns.delete(conn);
  }

  subscribe(conn: Conn, channelId: number) {
    conn.channels.add(channelId);
  }

  unsubscribe(conn: Conn, channelId: number) {
    conn.channels.delete(channelId);
  }

  broadcast(channelId: number, event: unknown) {
    const payload = JSON.stringify(event);
    for (const conn of this.conns) {
      if (!conn.alive) continue;
      if (!conn.channels.has(channelId)) continue;
      try { conn.send(payload); } catch { conn.alive = false; }
    }
  }

  broadcastToAgent(agentId: number, event: unknown) {
    const payload = JSON.stringify(event);
    for (const conn of this.conns) {
      if (conn.agentId !== agentId || !conn.alive) continue;
      try { conn.send(payload); } catch { conn.alive = false; }
    }
  }

  presenceSnapshot(channelId: number): number[] {
    const set = new Set<number>();
    for (const conn of this.conns) {
      if (conn.channels.has(channelId) && conn.alive) set.add(conn.agentId);
    }
    return [...set];
  }
}

export const sseHub = new SseHub();

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
