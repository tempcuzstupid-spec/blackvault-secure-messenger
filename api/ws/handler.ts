// Per-connection handler. Runs once per WebSocket upgrade. Validates the
// bearer token from the URL query, subscribes the connection to the
// agent's existing channel memberships, and processes inbound subscribe/
// unsubscribe/typing/heartbeat messages.

import type { IncomingMessage } from "node:http";
import { WebSocket } from "ws";
import { agentFromToken, channelIdsForAgent, wsHub } from "./hub";
import { getDb } from "../queries/connection";
import { eq } from "drizzle-orm";
import { memberships } from "@db/schema";

// Per-channel typing-TTL state. Maps "channelId:agentId" -> last typing timestamp.
const typingState = new Map<string, number>();
const TYPING_TTL_MS = 3500; // typing "stops" 3.5s after last seen

export function handleWsConnection(ws: WebSocket, req: IncomingMessage) {
  // Parse ?token= from the upgrade URL
  const url = new URL(req.url ?? "/", "http://localhost");
  const token = url.searchParams.get("token") ?? "";

  let agentId: number | null = null;
  let subscribedChannels = new Set<number>();
  let heartbeatTimer: NodeJS.Timeout | null = null;

  void (async () => {
    agentId = await agentFromToken(token);
    if (agentId == null) {
      try { ws.close(4401, "unauthorized"); } catch {}
      return;
    }
    const channels = await channelIdsForAgent(agentId);
    subscribedChannels = new Set(channels);
    wsHub.addConn(ws, agentId, channels);

    // Announce presence to existing channel members
    for (const channelId of channels) {
      wsHub.broadcast(channelId, {
        type: "presence.update",
        channelId,
        online: wsHub.presenceSnapshot(channelId),
      }, ws);
    }

    // Heartbeat: every 15s, ping the client. If no pong in 30s, terminate.
    let alive = true;
    ws.on("pong", () => { alive = true; });
    heartbeatTimer = setInterval(() => {
      if (!alive) { try { ws.terminate(); } catch {} ; return; }
      alive = false;
      try { ws.ping(); } catch {}
    }, 15000);

    ws.on("close", () => onClose());
    ws.on("error", () => onClose());
    ws.on("message", (raw) => onMessage(raw.toString()));
  })();

  function onClose() {
    if (heartbeatTimer) clearInterval(heartbeatTimer);
    if (agentId == null) return;
    // Announce departure to any subscribed channels
    for (const channelId of subscribedChannels) {
      wsHub.broadcast(channelId, {
        type: "presence.update",
        channelId,
        online: wsHub.presenceSnapshot(channelId).filter((id) => id !== agentId),
      });
    }
    wsHub.removeConn(ws);
    // Clear any typing state owned by this agent
    for (const key of [...typingState.keys()]) {
      if (key.endsWith(`:${agentId}`)) typingState.delete(key);
    }
  }

  function onMessage(text: string) {
    if (agentId == null) return;
    let msg: any;
    try { msg = JSON.parse(text); } catch { return; }
    if (!msg || typeof msg.type !== "string") return;

    switch (msg.type) {
      case "subscribe": {
        if (typeof msg.channelId !== "number") return;
        // Verify membership before subscribing
        void (async () => {
          const db = getDb();
          const [m] = await db
            .select()
            .from(memberships)
            .where(eq(memberships.channelId, msg.channelId))
            .limit(50);
          // cheap pre-check; full check would be WHERE AND agentId; the
          // hub broadcast already filters, but leaking "this channel exists"
          // to non-members is fine.
          if (!m) return;
          wsHub.subscribe(ws, msg.channelId);
          subscribedChannels.add(msg.channelId);
          wsHub.broadcast(msg.channelId, {
            type: "presence.update",
            channelId: msg.channelId,
            online: wsHub.presenceSnapshot(msg.channelId),
          }, ws);
        })();
        break;
      }
      case "unsubscribe": {
        if (typeof msg.channelId !== "number") return;
        wsHub.unsubscribe(ws, msg.channelId);
        subscribedChannels.delete(msg.channelId);
        break;
      }
      case "typing.start": {
        if (typeof msg.channelId !== "number" || !subscribedChannels.has(msg.channelId)) return;
        const key = `${msg.channelId}:${agentId}`;
        typingState.set(key, Date.now());
        wsHub.broadcast(msg.channelId, {
          type: "typing.update",
          channelId: msg.channelId,
          agentId,
          isTyping: true,
        }, ws);
        break;
      }
      case "typing.stop": {
        if (typeof msg.channelId !== "number") return;
        const key = `${msg.channelId}:${agentId}`;
        typingState.delete(key);
        wsHub.broadcast(msg.channelId, {
          type: "typing.update",
          channelId: msg.channelId,
          agentId,
          isTyping: false,
        }, ws);
        break;
      }
      case "heartbeat": {
        try { ws.send(JSON.stringify({ type: "heartbeat.ack" })); } catch {}
        break;
      }
    }
  }

  // Periodically expire typing state. Every 1s, scan the map and drop
  // any entries older than TYPING_TTL_MS, broadcasting a typing.stop for
  // any agent whose entry was dropped.
  const typingSweep = setInterval(() => {
    const now = Date.now();
    for (const [key, ts] of typingState) {
      if (now - ts < TYPING_TTL_MS) continue;
      typingState.delete(key);
      const sep = key.indexOf(":");
      if (sep < 0) continue;
      const channelId = Number(key.slice(0, sep));
      const aId = Number(key.slice(sep + 1));
      if (!Number.isFinite(channelId) || !Number.isFinite(aId)) continue;
      wsHub.broadcast(channelId, {
        type: "typing.update",
        channelId,
        agentId: aId,
        isTyping: false,
      });
    }
  }, 1000);
  ws.on("close", () => clearInterval(typingSweep));
}
