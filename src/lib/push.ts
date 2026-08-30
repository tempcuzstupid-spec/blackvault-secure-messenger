// Web Push subscription manager. Called from the React app on mount
// (after login). Asks the browser for permission, subscribes via the
// service worker, and posts the resulting endpoint + keys to the
// server. The server uses those to send pushes later.

import { getToken } from "./session";
import { trpc } from "@/providers/trpc";

const REGISTRATION_TIMEOUT_MS = 10000;

function urlBase64ToUint8Array(base64String: string): Uint8Array {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

async function getVapidKey(): Promise<string | null> {
  try {
    const r = await fetch("/api/push/vapid-key");
    if (!r.ok) return null;
    const data = await r.json();
    return data.publicKey ?? null;
  } catch {
    return null;
  }
}

export async function ensurePushSubscribed(): Promise<boolean> {
  if (typeof window === "undefined") return false;
  if (!("serviceWorker" in navigator) || !("PushManager" in window)) return false;
  if (!getToken()) return false;

  // Permission gate
  if (Notification.permission === "denied") return false;
  if (Notification.permission === "default") {
    const p = await Notification.requestPermission();
    if (p !== "granted") return false;
  }

  // Register service worker
  let reg: ServiceWorkerRegistration;
  try {
    reg = await Promise.race([
      navigator.serviceWorker.register("/sw.js"),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("sw timeout")), REGISTRATION_TIMEOUT_MS)),
    ]);
  } catch (e) {
    console.warn("push: service worker registration failed", e);
    return false;
  }

  // Don't re-subscribe if already subscribed
  let sub = await reg.pushManager.getSubscription();
  if (sub) {
    // Sync the existing subscription to the server in case the server
    // lost it (DB reset, etc.)
    const endpoint = sub.endpoint;
    const p256dh = sub.getKey("p256dh");
    const auth = sub.getKey("auth");
    if (!p256dh || !auth) return false;
    await syncSubscriptionToServer({
      endpoint,
      p256dh: btoa(String.fromCharCode(...new Uint8Array(p256dh))),
      auth: btoa(String.fromCharCode(...new Uint8Array(auth))),
    });
    return true;
  }

  const vapid = await getVapidKey();
  if (!vapid) {
    console.warn("push: no VAPID key from server");
    return false;
  }

  sub = await reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(vapid),
  });

  const p256dh = sub.getKey("p256dh");
  const auth = sub.getKey("auth");
  if (!p256dh || !auth) return false;
  await syncSubscriptionToServer({
    endpoint: sub.endpoint,
    p256dh: btoa(String.fromCharCode(...new Uint8Array(p256dh))),
    auth: btoa(String.fromCharCode(...new Uint8Array(auth))),
  });
  return true;
}

async function syncSubscriptionToServer(sub: { endpoint: string; p256dh: string; auth: string }) {
  const token = getToken();
  if (!token) return;
  try {
    const r = await fetch("/api/trpc/secure.subscribePush?batch=1", {
      method: "POST",
      headers: { "content-type": "application/json", "Authorization": `Bearer ${token}` },
      body: JSON.stringify({
        "0": { json: { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth }, userAgent: navigator.userAgent } },
      }),
    });
    if (!r.ok) console.warn("push: subscribePush failed", r.status);
  } catch (e) {
    console.warn("push: sync to server failed", e);
  }
}

export async function unsubscribePush(): Promise<void> {
  if (typeof window === "undefined") return;
  if (!("serviceWorker" in navigator)) return;
  const reg = await navigator.serviceWorker.getRegistration("/sw.js").catch(() => null);
  if (!reg) return;
  const sub = await reg.pushManager.getSubscription();
  if (!sub) return;
  const token = getToken();
  if (token) {
    try {
      await fetch("/api/trpc/secure.unsubscribePush?batch=1", {
        method: "POST",
        headers: { "content-type": "application/json", "Authorization": `Bearer ${token}` },
        body: JSON.stringify({ "0": { json: { endpoint: sub.endpoint } } }),
      });
    } catch {}
  }
  await sub.unsubscribe();
}
