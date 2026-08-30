// BlackVault service worker. Handles Web Push: receives a push event
// from the server, shows a generic notification (the server payload
// is content-hidden by design), and opens the app on click.
//
// Also handles client-side push subscription: the page calls
// `pushManager.subscribe({userVisibleOnly: true, applicationServerKey: <VAPID>})`
// and posts the resulting subscription to the server.

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

// Allow the page to skip waiting so a new SW activates immediately.
self.addEventListener("message", (event) => {
  if (event.data?.type === "SKIP_WAITING") self.skipWaiting();
});
