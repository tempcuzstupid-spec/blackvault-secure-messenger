// BlackVault service worker. Three responsibilities:
//  1. Web Push: receive push events and show a generic notification
//  2. App shell caching: serve the cached HTML / JS / CSS on cold start
//     so the PWA launches offline (after first visit)
//  3. Notification clicks: focus or open the app at a deep link

const CACHE = "bv-shell-v1";
const SHELL = ["/", "/manifest.json", "/icon-192.png", "/icon-512.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  // Only handle same-origin GETs; let everything else (API, SSE, push, etc.) through.
  if (event.request.method !== "GET") return;
  if (url.origin !== self.location.origin) return;
  // Don't intercept SSE or API; let Hono handle it.
  if (url.pathname.startsWith("/sse") || url.pathname.startsWith("/api/") || url.pathname.startsWith("/assets/")) return;
  // Network-first for HTML so deploys land quickly; cache as fallback.
  if (event.request.mode === "navigate" || event.request.destination === "document") {
    event.respondWith(
      fetch(event.request).then((resp) => {
        const copy = resp.clone();
        caches.open(CACHE).then((c) => c.put(event.request, copy)).catch(() => {});
        return resp;
      }).catch(() => caches.match(event.request).then((r) => r || caches.match("/")))
    );
    return;
  }
  // Cache-first for static assets already in the cache.
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request).then((resp) => {
      const copy = resp.clone();
      if (resp.ok) caches.open(CACHE).then((c) => c.put(event.request, copy)).catch(() => {});
      return resp;
    }))
  );
});

self.addEventListener("push", (event) => {
  if (!event.data) return;
  let payload;
  try { payload = event.data.json(); } catch { return; }
  const title = payload.title || "BlackVault";
  const options = {
    body: payload.body || "New encrypted message",
    tag: payload.tag || "bv-default",
    icon: payload.icon || "/icon-192.png",
    badge: payload.badge || "/icon-192.png",
    data: { url: payload.url || "/" },
    requireInteraction: false,
    silent: false,
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = event.notification.data?.url || "/";
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if ("focus" in client) {
          client.focus();
          if ("navigate" in client) client.navigate(url);
          return;
        }
      }
      if (self.clients.openWindow) return self.clients.openWindow(url);
    })
  );
});

self.addEventListener("message", (event) => {
  if (event.data?.type === "SKIP_WAITING") self.skipWaiting();
});
