// Client-side WebSocket hook. One singleton connection per page. Reconnects
// on close. Routes inbound events to a simple in-memory bus that the rest
// of the app can subscribe to via `useWsEvent`.

import { useEffect, useRef, useState } from "react";
import { getToken } from "./session";

type WsEvent =
  | { type: "message.created"; channelId: number; message: any }
  | { type: "message.updated"; channelId: number; message: any }
  | { type: "message.deleted"; channelId: number; messageId: number }
  | { type: "reaction.added"; channelId: number; messageId: number; agentId: number; emoji: string }
  | { type: "reaction.removed"; channelId: number; messageId: number; agentId: number; emoji: string }
  | { type: "typing.update"; channelId: number; agentId: number; isTyping: boolean }
  | { type: "presence.update"; channelId: number; online: number[] }
  | { type: "channel.member_joined"; channelId: number; agentId: number; online: number[] }
  | { type: "heartbeat.ack" };

type Listener = (e: WsEvent) => void;
const listeners = new Set<Listener>();

let socket: WebSocket | null = null;
let reconnectTimer: number | null = null;
let intentionallyClosed = false;

function urlForToken(token: string): string {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${location.host}/ws?token=${encodeURIComponent(token)}`;
}

export function openWs(): WebSocket | null {
  const token = getToken();
  if (!token) return null;
  if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
    return socket;
  }
  intentionallyClosed = false;
  const ws = new WebSocket(urlForToken(token));
  socket = ws;

  ws.addEventListener("open", () => {
    // Heartbeat: every 25s, send a no-op so the server's TCP keepalive
    // has a peer; without it some load balancers idle-out the connection.
    const hb = window.setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        try { ws.send(JSON.stringify({ type: "heartbeat" })); } catch {}
      } else {
        window.clearInterval(hb);
      }
    }, 25000);
    ws.addEventListener("close", () => window.clearInterval(hb));
  });

  ws.addEventListener("message", (e) => {
    let parsed: WsEvent;
    try { parsed = JSON.parse(e.data); } catch { return; }
    for (const l of listeners) l(parsed);
  });

  ws.addEventListener("close", () => {
    socket = null;
    if (intentionallyClosed) return;
    if (reconnectTimer != null) return;
    reconnectTimer = window.setTimeout(() => {
      reconnectTimer = null;
      // Only reconnect if we still have a token
      if (getToken()) openWs();
    }, 1500);
  });

  ws.addEventListener("error", () => {
    // The close handler will fire next; reconnect is handled there.
  });

  return ws;
}

export function closeWs() {
  intentionallyClosed = true;
  if (socket) {
    try { socket.close(); } catch {}
    socket = null;
  }
  if (reconnectTimer != null) {
    window.clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
}

export function sendWs(obj: unknown) {
  if (socket && socket.readyState === WebSocket.OPEN) {
    try { socket.send(JSON.stringify(obj)); } catch {}
  }
}

export function subscribeWs(fn: Listener): () => void {
  listeners.add(fn);
  return () => { listeners.delete(fn); };
}

/** React hook: subscribe to a specific event type from the WS bus. */
export function useWsEvent<T extends WsEvent["type"]>(
  type: T,
  handler: (e: Extract<WsEvent, { type: T }>) => void,
) {
  const ref = useRef(handler);
  ref.current = handler;
  useEffect(() => {
    const off = subscribeWs((e) => {
      if (e.type === type) ref.current(e as Extract<WsEvent, { type: T }>);
    });
    return off;
  }, [type]);
}

/** React hook: open the WS once on mount, close on unmount. */
export function useWsConnection() {
  const [state, setState] = useState<"idle" | "open" | "closed">(getToken() ? "idle" : "closed");
  useEffect(() => {
    const ws = openWs();
    if (!ws) return;
    const onOpen = () => setState("open");
    const onClose = () => setState("closed");
    ws.addEventListener("open", onOpen);
    ws.addEventListener("close", onClose);
    return () => {
      ws.removeEventListener("open", onOpen);
      ws.removeEventListener("close", onClose);
    };
  }, []);
  return state;
}
