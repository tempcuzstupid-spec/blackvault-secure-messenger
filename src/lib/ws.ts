// Client-side realtime transport. Uses Server-Sent Events (EventSource),
// which is one-way server->client over a long-lived HTTP response. No
// WebSocket upgrade dance, works through every proxy. EventSource
// auto-reconnects with exponential backoff on close.
//
// Outbound events (typing.start, subscribe to a new channel) are sent
// as POST requests to companion REST endpoints. SSE is the receive
// side only; the request side is normal HTTP.

import { useEffect, useRef, useState } from "react";
import { getToken } from "./session";

type SseEvent =
  | { type: "ready"; agentId: number; channels: number[] }
  | { type: "message.created"; channelId: number; message: any }
  | { type: "message.updated"; channelId: number; message: any }
  | { type: "message.deleted"; channelId: number; messageId: number }
  | { type: "reaction.added"; channelId: number; messageId: number; agentId: number; emoji: string }
  | { type: "reaction.removed"; channelId: number; messageId: number; agentId: number; emoji: string }
  | { type: "typing.update"; channelId: number; agentId: number; isTyping: boolean }
  | { type: "presence.update"; channelId: number; online: number[] }
  | { type: "channel.member_joined"; channelId: number; agentId: number; online: number[] };

type Listener = (e: SseEvent) => void;
const listeners = new Set<Listener>();

let es: EventSource | null = null;
let intentionallyClosed = false;

function urlForToken(token: string): string {
  return `/sse?token=${encodeURIComponent(token)}`;
}

export function openWs(): EventSource | null {
  const token = getToken();
  if (!token) return null;
  if (es) return es; // singleton
  intentionallyClosed = false;
  es = new EventSource(urlForToken(token));

  es.addEventListener("message", (e) => {
    let parsed: SseEvent;
    try { parsed = JSON.parse((e as MessageEvent).data); } catch { return; }
    for (const l of listeners) l(parsed);
  });

  es.addEventListener("error", () => {
    // EventSource auto-reconnects; just mark state for the UI.
    // If close was intentional, don't react.
    if (intentionallyClosed) return;
  });

  return es;
}

export function closeWs() {
  intentionallyClosed = true;
  if (es) {
    try { es.close(); } catch {}
    es = null;
  }
}

export function sendWs(obj: { type: string; channelId?: number; isTyping?: boolean }) {
  const token = getToken();
  if (!token) return;
  const url = obj.type === "subscribe" ? "/api/sse/subscribe"
    : obj.type === "unsubscribe" ? "/api/sse/unsubscribe"
    : obj.type === "typing.start" || obj.type === "typing.stop" ? "/api/sse/typing"
    : null;
  if (!url) return;
  const body: any = { channelId: obj.channelId };
  if (obj.type === "typing.start" || obj.type === "typing.stop") {
    body.isTyping = obj.type === "typing.start";
  }
  fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "Authorization": `Bearer ${token}` },
    body: JSON.stringify(body),
    keepalive: true,
  }).catch(() => {});
}

export function subscribeWs(fn: Listener): () => void {
  listeners.add(fn);
  return () => { listeners.delete(fn); };
}

export function useWsEvent<T extends SseEvent["type"]>(
  type: T,
  handler: (e: Extract<SseEvent, { type: T }>) => void,
) {
  const ref = useRef(handler);
  ref.current = handler;
  useEffect(() => {
    const off = subscribeWs((e) => {
      if (e.type === type) ref.current(e as Extract<SseEvent, { type: T }>);
    });
    return off;
  }, [type]);
}

export function useWsConnection() {
  const [state, setState] = useState<"idle" | "open" | "closed">(getToken() ? "idle" : "closed");
  useEffect(() => {
    const s = openWs();
    if (!s) return;
    const onOpen = () => setState("open");
    const onError = () => {
      // EventSource doesn't fire 'close' on disconnect attempts; treat
      // error as "not currently open" but it'll come back via reconnect.
      if (s.readyState === EventSource.CLOSED) setState("closed");
    };
    s.addEventListener("open", onOpen);
    s.addEventListener("error", onError);
    return () => {
      s.removeEventListener("open", onOpen);
      s.removeEventListener("error", onError);
    };
  }, []);
  return state;
}
