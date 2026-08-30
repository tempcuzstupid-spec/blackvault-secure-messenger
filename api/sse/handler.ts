// Per-connection handler. Validates the bearer token from the URL
// query, opens an SSE stream, subscribes the connection to the agent's
// channel memberships, and processes inbound subscribe/unsubscribe/
// typing/heartbeat messages via the companion POST endpoints (typing
// is fire-and-forget; subscribe/unsubscribe change the SSE filter).

import type { Hono } from "hono";
import { sseHub, agentFromToken, channelIdsForAgent } from "./hub";

export function sseHandler(app: Hono) {
  app.get("/sse", async (c) => {
    const token = c.req.query("token") ?? "";
    const agentId = await agentFromToken(token);
    if (agentId == null) {
      return c.text("unauthorized", 401);
    }
    const channels = await channelIdsForAgent(agentId);

    // Hono's streaming response
    const stream = new ReadableStream({
      start(controller) {
        const enc = new TextEncoder();
        const write = (event: unknown) => {
          try {
            controller.enqueue(enc.encode(`data: ${JSON.stringify(event)}\n\n`));
          } catch {
            conn.alive = false;
          }
        };

        const conn = {
          agentId,
          channels: new Set<number>(channels),
          send: write,
          close: () => {
            try { controller.close(); } catch {}
          },
          alive: true,
        };
        sseHub.add(conn);

        // Initial presence broadcast to all subscribed channels
        for (const channelId of channels) {
          sseHub.broadcast(channelId, {
            type: "presence.update",
            channelId,
            online: sseHub.presenceSnapshot(channelId),
          });
        }

        // 15s keepalive comment (not a real event) to keep proxies from
        // idling the connection out. SSE clients ignore "comment:" lines.
        const keepalive = setInterval(() => {
          if (!conn.alive) return;
          try { controller.enqueue(enc.encode(`: keepalive ${Date.now()}\n\n`)); }
          catch { conn.alive = false; }
        }, 15000);

        // Announce departure on stream close
        const cleanup = () => {
          if (!conn.alive) return;
          conn.alive = false;
          clearInterval(keepalive);
          for (const channelId of conn.channels) {
            sseHub.broadcast(channelId, {
              type: "presence.update",
              channelId,
              online: sseHub.presenceSnapshot(channelId).filter((id) => id !== conn.agentId),
            });
          }
          sseHub.remove(conn);
        };
        c.req.raw.signal.addEventListener("abort", cleanup);
        c.req.raw.signal.addEventListener("close", cleanup);

        // Send a hello so the client knows the stream is open
        write({ type: "ready", agentId, channels: [...conn.channels] });
      },
      cancel() {
        // Stream cancelled by client; cleanup runs via the abort/close
        // handlers registered in `start`.
      },
    });

    return new Response(stream, {
      headers: {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-cache, no-transform",
        "connection": "keep-alive",
        "x-accel-buffering": "no", // disable buffering on nginx-style proxies
      },
    });
  });
}

export function sseChannelControls(app: Hono) {
  // POST /api/sse/subscribe { channelId } - subscribe this connection.
  // Note: the connection identity is identified by a token cookie or
  // a one-shot correlation id. For simplicity we just look up the
  // agent from the bearer token and subscribe every open connection
  // for that agent. EventSource is the only consumer; it auto-reconnects
  // so a brief duplicate-subscribe window is harmless.
  app.post("/api/sse/subscribe", async (c) => {
    const token = c.req.header("authorization")?.slice(7) ?? "";
    const agentId = await agentFromToken(token);
    if (agentId == null) return c.json({ error: "unauthorized" }, 401);
    const body = await c.req.json().catch(() => null) as { channelId?: number } | null;
    if (!body || typeof body.channelId !== "number") {
      return c.json({ error: "channelId required" }, 400);
    }
    for (const conn of (sseHub as any).conns) {
      if (conn.agentId === agentId) {
        sseHub.subscribe(conn, body.channelId);
        sseHub.broadcast(body.channelId, {
          type: "presence.update",
          channelId: body.channelId,
          online: sseHub.presenceSnapshot(body.channelId),
        });
      }
    }
    return c.json({ ok: true });
  });

  app.post("/api/sse/unsubscribe", async (c) => {
    const token = c.req.header("authorization")?.slice(7) ?? "";
    const agentId = await agentFromToken(token);
    if (agentId == null) return c.json({ error: "unauthorized" }, 401);
    const body = await c.req.json().catch(() => null) as { channelId?: number } | null;
    if (!body || typeof body.channelId !== "number") {
      return c.json({ error: "channelId required" }, 400);
    }
    for (const conn of (sseHub as any).conns) {
      if (conn.agentId === agentId) sseHub.unsubscribe(conn, body.channelId);
    }
    return c.json({ ok: true });
  });

  // POST /api/sse/typing { channelId, isTyping } - broadcast typing.
  app.post("/api/sse/typing", async (c) => {
    const token = c.req.header("authorization")?.slice(7) ?? "";
    const agentId = await agentFromToken(token);
    if (agentId == null) return c.json({ error: "unauthorized" }, 401);
    const body = await c.req.json().catch(() => null) as { channelId?: number; isTyping?: boolean } | null;
    if (!body || typeof body.channelId !== "number" || typeof body.isTyping !== "boolean") {
      return c.json({ error: "channelId + isTyping required" }, 400);
    }
    sseHub.broadcast(body.channelId, {
      type: "typing.update",
      channelId: body.channelId,
      agentId,
      isTyping: body.isTyping,
    });
    return c.json({ ok: true });
  });
}
